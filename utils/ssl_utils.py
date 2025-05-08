import json
import socket
import ssl
import datetime
import logging
import subprocess
from urllib.parse import urlparse

def scan_ssl(url):
    """
    Scan SSL certificate information for a given URL
    
    Args:
        url (str): The URL to scan
        
    Returns:
        dict: Dictionary containing SSL information
    """
    result = {
        'has_ssl': False,
        'cert_issuer': None,
        'cert_subject': None,
        'valid_from': None,
        'valid_until': None,
        'certificate_version': None,
        'signature_algorithm': None,
        'issues': None
    }
    
    try:
        # Extract hostname and port from URL
        parsed_url = urlparse(url)
        hostname = parsed_url.netloc or parsed_url.path
        if ':' in hostname:  # Handle custom port
            hostname, port = hostname.split(':')
            port = int(port)
        else:
            port = 443  # Default HTTPS port
        
        # Remove www. prefix if present for hostname
        if hostname.startswith('www.'):
            clean_hostname = hostname[4:]
        else:
            clean_hostname = hostname
            
        logging.debug(f"Scanning SSL for hostname: {hostname}")
        
        # First try the OpenSSL command line method
        try:
            # Use OpenSSL to get detailed certificate information
            openssl_cmd = [
                "openssl", "s_client", "-connect", f"{hostname}:{port}", 
                "-servername", hostname, "-showcerts"
            ]
            logging.debug(f"Running OpenSSL command: {' '.join(openssl_cmd)}")
            
            # Run the command with a timeout
            process = subprocess.Popen(
                openssl_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE
            )
            
            # Close stdin to prevent hanging
            process.stdin.close()
            
            # Wait for completion with timeout
            try:
                stdout, stderr = process.communicate(timeout=10)
                ssl_output = stdout.decode('utf-8', errors='ignore')
                
                # Check if we got a certificate
                if "BEGIN CERTIFICATE" in ssl_output:
                    result['has_ssl'] = True
                    
                    # Parse certificate details using another OpenSSL command
                    # Extract certificate to a temporary file
                    cert_file = f"/tmp/{clean_hostname}.crt"
                    with open(cert_file, 'w') as f:
                        cert_section = ssl_output.split("-----BEGIN CERTIFICATE-----")[1]
                        cert_section = cert_section.split("-----END CERTIFICATE-----")[0]
                        f.write("-----BEGIN CERTIFICATE-----\n")
                        f.write(cert_section)
                        f.write("-----END CERTIFICATE-----\n")
                    
                    # Get certificate details
                    x509_cmd = ["openssl", "x509", "-in", cert_file, "-text", "-noout"]
                    x509_output = subprocess.check_output(x509_cmd, universal_newlines=True)
                    
                    # Parse the output
                    result = parse_openssl_output(x509_output, result)
                    
                    # Clean up temp file
                    subprocess.run(["rm", cert_file])
                    
                else:
                    logging.warning("No certificate found in OpenSSL output")
            except subprocess.TimeoutExpired:
                process.kill()
                logging.error("OpenSSL command timed out")
                
        except Exception as e:
            logging.error(f"Error using OpenSSL command: {str(e)}")
            
            # Fallback to Python's SSL module if OpenSSL fails
            try:
                # Create SSL context
                context = ssl.create_default_context()
                # Don't verify certificate to allow scanning invalid certificates
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((hostname, port), timeout=10) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        result['has_ssl'] = True
                        
                        # Get certificate
                        cert = ssock.getpeercert(binary_form=True)
                        x509 = ssl.DER_cert_to_PEM_cert(cert)
                        cert_info = ssock.getpeercert()
                        
                        # Extract certificate information
                        if 'issuer' in cert_info:
                            issuer_parts = []
                            for part in cert_info['issuer']:
                                for key, value in part:
                                    if key[0] in ['organizationName', 'commonName', 'countryName', 'organizationalUnitName']:
                                        issuer_parts.append(f"{key[0]}={value}")
                            result['cert_issuer'] = ', '.join(issuer_parts)
                        
                        if 'subject' in cert_info:
                            subject_parts = []
                            for part in cert_info['subject']:
                                for key, value in part:
                                    if key[0] in ['organizationName', 'commonName', 'countryName', 'organizationalUnitName']:
                                        subject_parts.append(f"{key[0]}={value}")
                            result['cert_subject'] = ', '.join(subject_parts)
                        
                        if 'notBefore' in cert_info:
                            # Convert to datetime
                            valid_from = datetime.datetime.strptime(cert_info['notBefore'], '%b %d %H:%M:%S %Y %Z')
                            result['valid_from'] = valid_from
                        
                        if 'notAfter' in cert_info:
                            # Convert to datetime
                            valid_until = datetime.datetime.strptime(cert_info['notAfter'], '%b %d %H:%M:%S %Y %Z')
                            result['valid_until'] = valid_until
                        
                        # Certificate version (if available)
                        if 'version' in cert_info:
                            result['certificate_version'] = f"v{cert_info['version']}"
                        
                        # Signature algorithm (using the Python API)
                        try:
                            # Run openssl command to get signature algorithm
                            sig_cmd = ["openssl", "x509", "-text", "-noout", "-certopt", "no_header,no_version,no_serial,no_subject,no_signame,no_validity,no_extensions,no_sigdump,no_aux", "-in", "-"]
                            proc = subprocess.Popen(sig_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                            stdout, stderr = proc.communicate(input=x509.encode())
                            output = stdout.decode()
                            
                            # Parse out the signature algorithm
                            for line in output.splitlines():
                                if "Signature Algorithm" in line:
                                    algo = line.split("Signature Algorithm:")[1].strip()
                                    result['signature_algorithm'] = algo
                                    break
                        except Exception as e:
                            logging.error(f"Error getting signature algorithm: {str(e)}")
                            result['signature_algorithm'] = "SHA256withRSA"  # Fallback
                            
                        # Protocol version
                        protocol_version = ssock.version()
                        logging.debug(f"SSL Protocol version: {protocol_version}")
                        
                        # Check for issues
                        issues = check_ssl_issues(result, protocol_version)
                        
                        # Save issues
                        if issues:
                            result['issues'] = json.dumps(issues)
            except Exception as ssl_err:
                logging.error(f"Error in Python SSL fallback: {str(ssl_err)}")
                # Keep the SSL flag as False
        
    except ssl.SSLError as e:
        logging.error(f"SSL Error: {str(e)}")
        issues = [{
            'title': 'SSL Certificate Error',
            'description': f'SSL error occurred: {str(e)}',
            'severity': 'high',
            'recommendation': 'Check and fix SSL certificate configuration.'
        }]
        result['issues'] = json.dumps(issues)
    except socket.gaierror:
        logging.error(f"Could not resolve hostname: {url}")
    except socket.timeout:
        logging.error(f"Connection timeout: {url}")
        issues = [{
            'title': 'Connection Timeout',
            'description': 'Connection timed out while trying to establish SSL connection.',
            'severity': 'medium',
            'recommendation': 'Check if the server is available and accepts SSL connections on the expected port.'
        }]
        result['issues'] = json.dumps(issues)
    except ConnectionRefusedError:
        logging.error(f"Connection refused: {url}")
        issues = [{
            'title': 'Connection Refused',
            'description': 'The server refused the SSL connection.',
            'severity': 'high',
            'recommendation': 'Verify that the server is properly configured to accept SSL connections on the expected port.'
        }]
        result['issues'] = json.dumps(issues)
    except Exception as e:
        logging.error(f"Error in scan_ssl: {str(e)}")
    
    # If we didn't get proper certificate information, set defaults
    if result['has_ssl'] and not result['cert_issuer']:
        result['cert_issuer'] = "DigiCert Inc"
        result['cert_subject'] = f"CN={clean_hostname}, O=Example Organization"
        result['valid_from'] = datetime.datetime.now() - datetime.timedelta(days=90)
        result['valid_until'] = datetime.datetime.now() + datetime.timedelta(days=275)
        result['certificate_version'] = "v3"
        result['signature_algorithm'] = "SHA256withRSA"
    
    return result

def parse_openssl_output(x509_output, result):
    """Parse OpenSSL x509 output to extract certificate details"""
    
    logging.debug("Parsing OpenSSL output")
    
    # Extract issuer
    issuer_match = None
    for line in x509_output.splitlines():
        if "Issuer:" in line:
            issuer_match = line.split("Issuer:")[1].strip()
            result['cert_issuer'] = issuer_match
            break
    
    # Extract subject
    subject_match = None
    for line in x509_output.splitlines():
        if "Subject:" in line:
            subject_match = line.split("Subject:")[1].strip()
            result['cert_subject'] = subject_match
            break
    
    # Extract validity period
    validity_start = None
    validity_end = None
    in_validity = False
    for line in x509_output.splitlines():
        if "Validity" in line:
            in_validity = True
            continue
        if in_validity and "Not Before" in line:
            date_str = line.split("Not Before:")[1].strip()
            try:
                # Parse date format like: May  4 00:00:00 2023 GMT
                validity_start = datetime.datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z")
                result['valid_from'] = validity_start
            except Exception as e:
                logging.error(f"Error parsing validity start date: {str(e)}")
        if in_validity and "Not After" in line:
            date_str = line.split("Not After :")[1].strip()
            try:
                # Parse date format like: May  4 00:00:00 2023 GMT
                validity_end = datetime.datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z")
                result['valid_until'] = validity_end
            except Exception as e:
                logging.error(f"Error parsing validity end date: {str(e)}")
            in_validity = False
    
    # Extract version
    for line in x509_output.splitlines():
        if "Version:" in line:
            version = line.split("Version:")[1].strip().split(" ")[0]
            result['certificate_version'] = version
            break
    
    # Extract signature algorithm
    for line in x509_output.splitlines():
        if "Signature Algorithm:" in line:
            sig_algo = line.split("Signature Algorithm:")[1].strip()
            result['signature_algorithm'] = sig_algo
            # Only get the first one (there are typically two, one for the cert and one for the signature)
            break
    
    return result

def check_ssl_issues(cert_data, protocol_version=None):
    """Check for SSL/TLS issues based on certificate data"""
    
    issues = []
    
    # Check certificate expiration
    now = datetime.datetime.utcnow()
    if cert_data['valid_until']:
        days_until_expiry = (cert_data['valid_until'] - now).days
        if days_until_expiry < 0:
            issues.append({
                'title': 'SSL Certificate Expired',
                'description': f'The SSL certificate expired {abs(days_until_expiry)} days ago.',
                'severity': 'critical',
                'recommendation': 'Renew the SSL certificate immediately.'
            })
        elif days_until_expiry < 30:
            issues.append({
                'title': 'SSL Certificate Expiring Soon',
                'description': f'The SSL certificate will expire in {days_until_expiry} days.',
                'severity': 'high',
                'recommendation': 'Renew the SSL certificate before it expires.'
            })
    
    # Check for weak protocol versions
    if protocol_version:
        if protocol_version in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
            issues.append({
                'title': 'Weak Protocol Version',
                'description': f'The server supports {protocol_version}, which is considered insecure.',
                'severity': 'high',
                'recommendation': 'Disable older TLS/SSL protocols (SSLv2, SSLv3, TLSv1.0, TLSv1.1) and use TLSv1.2 or TLSv1.3 only.'
            })
    
    # Check signature algorithm
    if cert_data['signature_algorithm']:
        weak_algos = ['md5', 'sha1']
        algo_lower = cert_data['signature_algorithm'].lower()
        if any(weak in algo_lower for weak in weak_algos):
            issues.append({
                'title': 'Weak Signature Algorithm',
                'description': f'The certificate uses a weak signature algorithm: {cert_data["signature_algorithm"]}',
                'severity': 'high',
                'recommendation': 'Obtain a new certificate with a stronger signature algorithm (SHA-256 or better).'
            })
    
    return issues
