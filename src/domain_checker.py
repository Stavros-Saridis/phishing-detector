import whois
from datetime import datetime, timezone

def check_domain(domain):
    results = {
        'domain': domain,
        'risk_score': 0,
        'warnings': [],
        'info': {}
    }

    try:
        w = whois.whois(domain)

        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date:
            if creation_date.tzinfo is not None:
                age_days = (datetime.now(timezone.utc) - creation_date).days
            else:
                age_days = (datetime.now() - creation_date).days

            results['info']['domain_age_days'] = age_days
            results['info']['created'] = str(creation_date)

            if age_days < 30:
                results['risk_score'] += 40
                results['warnings'].append(f'Very new domain ({age_days} days old) — high risk')
            elif age_days < 180:
                results['risk_score'] += 20
                results['warnings'].append(f'Relatively new domain ({age_days} days old) — moderate risk')
            else:
                results['info']['domain_age_status'] = 'established'

        if w.registrar:
            results['info']['registrar'] = w.registrar

        if w.country:
            results['info']['country'] = w.country

        expiration_date = w.expiration_date
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]

        if expiration_date:
            if expiration_date.tzinfo is not None:
                days_until_expiry = (expiration_date - datetime.now(timezone.utc)).days
            else:
                days_until_expiry = (expiration_date - datetime.now()).days

            results['info']['expires_in_days'] = days_until_expiry
            if days_until_expiry < 30:
                results['risk_score'] += 15
                results['warnings'].append(f'Domain expires soon ({days_until_expiry} days) — suspicious')

    except Exception as e:
        results['warnings'].append(f'Could not retrieve WHOIS data: {str(e)}')
        results['risk_score'] += 10

    results['risk_score'] = min(results['risk_score'], 100)
    return results