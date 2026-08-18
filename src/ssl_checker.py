import ssl
import socket
from datetime import datetime

def check_ssl(domain):
    results = {
        'domain': domain,
        'risk_score': 0,
        'warnings': [],
        'info': {}
    }

    try:
        domain = domain.replace('www.', '')
        context = ssl.create_default_context()
        conn = context.wrap_socket(
            socket.socket(socket.AF_INET),
            server_hostname=domain
        )
        conn.settimeout(5)
        conn.connect((domain, 443))
        cert = conn.getpeercert()
        conn.close()

        results['info']['has_ssl'] = True

        # Check expiration
        expire_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
        days_left = (expire_date - datetime.now()).days
        results['info']['ssl_expires_in_days'] = days_left
        results['info']['ssl_expires'] = str(expire_date)

        if days_left < 0:
            results['risk_score'] += 40
            results['warnings'].append('SSL certificate has expired — very suspicious')
        elif days_left < 30:
            results['risk_score'] += 20
            results['warnings'].append(f'SSL certificate expires soon ({days_left} days)')

        # Check issuer
        issuer = dict(x[0] for x in cert['issuer'])
        results['info']['ssl_issuer'] = issuer.get('organizationName', 'Unknown')

        # Check subject
        subject = dict(x[0] for x in cert['subject'])
        results['info']['ssl_subject'] = subject.get('commonName', 'Unknown')

    except ssl.SSLError as e:
        results['risk_score'] += 30
        results['warnings'].append(f'SSL error: {str(e)}')
        results['info']['has_ssl'] = False
    except socket.timeout:
        results['warnings'].append('SSL check timed out')
    except Exception as e:
        results['warnings'].append(f'Could not check SSL: {str(e)}')
        results['info']['has_ssl'] = False

    results['risk_score'] = min(results['risk_score'], 100)
    return results