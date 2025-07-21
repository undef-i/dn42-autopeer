import requests
import string
import resend
import random
import os
import subprocess
import logging
from config import Config

resend.api_key = Config.RESEND_API_KEY

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)



def get_dn42_info(path, attributes):
    info = {}
    registry_path = './registry'
    full_path = os.path.join(registry_path, 'data', path)
    
    logger.info(f"Looking for DN42 info at: {full_path}")
    
    try:
        if not os.path.exists(full_path):
            if os.path.exists(registry_path):
                logger.info("Updating DN42 registry")
                subprocess.run(['git', '-C', registry_path, 'pull'], check=True)
            else:
                logger.info("Cloning DN42 registry")
                git_url = Config.DN42_REGISTRY_URL
                if Config.GIT_USERNAME and Config.GIT_TOKEN:
                    git_url = git_url.replace('https://', f'https://{Config.GIT_USERNAME}:{Config.GIT_TOKEN}@')
                subprocess.run(['git', 'clone', git_url, registry_path], check=True)
        
        if not os.path.exists(full_path):
            logger.warning(f"File not found: {full_path}")
            return info

        with open(full_path, 'r', encoding='utf-8') as file:
            for line in file:
                line = line.strip()
                if ':' in line:
                    key, value = line.split(':', 1)
                    key = key.strip()
                    value = value.strip()
                    
                    if key in attributes:
                        info[key] = value

    except subprocess.CalledProcessError as e:
        logger.error(f"Git operation failed: {e}")
        return {}
    except Exception as e:
        logger.error(f"Error reading DN42 info: {e}")
        return {}

    return info

def get_auth_info(ASN):
    if not ASN or not ASN.isdigit():
        logger.warning(f"Invalid ASN format: {ASN}")
        return {}
    
    logger.info(f"Getting auth info for AS{ASN}")
    info = get_dn42_info(f"aut-num/AS{ASN}", ("admin-c", "mnt-by"))
    
    if not info:
        logger.warning(f"No aut-num info found for AS{ASN}")
        return {}
    
    admin_c = info.get('admin-c')
    mnt_by = info.get('mnt-by')
    
    if admin_c:
        email_info = get_dn42_info(f"person/{admin_c}", ("e-mail",))
        info.update(email_info)
    
    if mnt_by:
        auth_info = get_dn42_info(f"mntner/{mnt_by}", ("auth",))
        info.update(auth_info)
    
    logger.info(f"Retrieved auth info for AS{ASN}: {list(info.keys())}")
    return info


def generate_verification_code(length=8):
    characters = string.ascii_uppercase + string.digits
    verification_code = ''.join(random.choice(characters) for _ in range(length))
    return verification_code

def send_verification_code(email, verification_code):
    if not Config.RESEND_API_KEY:
        logger.error("RESEND_API_KEY not configured")
        raise ValueError("Email service not configured")
    
    params = {
        "from": Config.EMAIL_FROM,
        "to": [email],
        "subject": "[DN42 AutoPeer] Email Verification Code",
        "html": f'''
        <h2>DN42 AutoPeer Verification</h2>
        <p>Your verification code is: <strong>{verification_code}</strong></p>
        <p>This code will expire in 5 minutes.</p>
        <p>If you did not request this verification, please ignore this email.</p>
        ''',
    }
    
    try:
        result = resend.Emails.send(params)
        logger.info(f"Verification email sent to {email}")
        return result
    except Exception as e:
        logger.error(f"Failed to send verification email to {email}: {e}")
        raise
