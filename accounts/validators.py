"""
Zero Trust email validators.
1. Syntax check (Django built-in EmailValidator)
2. MX record check — domain must have a real mail server
3. Disposable email domain blocklist
"""
import re
import dns.resolver
from django.core.exceptions import ValidationError
from django.core.validators import validate_email as django_validate_email


# ── Disposable / throwaway domain blocklist ───────────────────────────────────
DISPOSABLE_DOMAINS = {
    'mailinator.com', 'guerrillamail.com', 'guerrillamail.net',
    'guerrillamail.org', 'guerrillamail.de', 'guerrillamail.info',
    'guerrillamail.biz', 'sharklasers.com', 'guerrillamailblock.com',
    'grr.la', 'spam4.me', 'yopmail.com', 'yopmail.fr', 'cool.fr.nf',
    'jetable.fr.nf', 'nospam.ze.tc', 'nomail.xl.cx', 'mega.zik.dj',
    'speed.1s.fr', 'courriel.fr.nf', 'moncourrier.fr.nf',
    'monemail.fr.nf', 'monmail.fr.nf', 'spamgourmet.com',
    'trashmail.me', 'trashmail.at', 'trashmail.com', 'trashmail.io',
    'trashmail.net', 'trashmail.org', 'dispostable.com',
    'mailnull.com', 'maildrop.cc', 'throwam.com', 'throwam.net',
    'throwaway.email', 'tempmail.com', 'tempmail.net', 'temp-mail.org',
    'fakeinbox.com', 'discard.email', 'sharklasers.com', 'zetmail.com',
    'mailnesia.com', 'mailnull.com', 'spamgourmet.net', 'spamgourmet.org',
    'spamgourmet.com', 'mailexpire.com', 'spamfree24.org',
    'spamfree24.de', 'spamfree24.eu', 'spamfree24.info', 'spamfree24.net',
    'spamfree.eu', 'byom.de', '0-mail.com', '0815.ru', '0815.su',
    '10minutemail.com', '10minutemail.net', '10minutemail.org',
    '20minutemail.com', 'emailondeck.com', 'getairmail.com',
    'getnada.com', 'mohmal.com', 'spamgrap.de', 'wegwerfmail.de',
    'wegwerfmail.net', 'wegwerfmail.org', 'filzmail.com',
    'discard.cf', 'spamdecoy.net',
}


def _extract_domain(email: str) -> str:
    return email.rsplit('@', 1)[-1].lower().strip()


def validate_email_syntax(email: str):
    """Check Django's standard email syntax rules."""
    try:
        django_validate_email(email)
    except ValidationError:
        raise ValidationError('Enter a valid email address (e.g. name@domain.com).')


def validate_email_not_disposable(email: str):
    """Reject known throwaway / disposable email domains."""
    domain = _extract_domain(email)
    if domain in DISPOSABLE_DOMAINS:
        raise ValidationError(
            'Disposable or throwaway email addresses are not allowed. '
            'Please use your real email address.'
        )


def validate_email_domain_mx(email: str):
    """
    Check that the email domain has a valid MX record.
    This confirms the domain can actually receive email.
    Falls back gracefully if DNS is unavailable.
    """
    domain = _extract_domain(email)
    try:
        dns.resolver.resolve(domain, 'MX')
    except dns.resolver.NXDOMAIN:
        raise ValidationError(
            f'The domain "{domain}" does not exist. '
            'Please enter a real email address.'
        )
    except dns.resolver.NoAnswer:
        raise ValidationError(
            f'The domain "{domain}" cannot receive email (no mail server found). '
            'Please use a valid email address.'
        )
    except dns.resolver.Timeout:
        # DNS timeout — don't block the user, let it pass
        pass
    except Exception:
        # Any other DNS error — fail open (don't block)
        pass


def validate_real_email(email: str):
    """
    Composite validator — runs all checks in order.
    Call this from form clean_email methods.
    """
    email = email.strip().lower()
    validate_email_syntax(email)
    validate_email_not_disposable(email)
    validate_email_domain_mx(email)
    return email
