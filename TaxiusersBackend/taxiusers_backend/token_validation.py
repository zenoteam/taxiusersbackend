import os
import jwt
import redis
from parse import parse
from datetime import datetime, timedelta

import logging

logger = logging.getLogger(__name__)

REDIS_HOST = os.environ.get('REDIS_HOST', 'localhost')
REDIS_PORT = os.environ.get('REDIS_PORT', 6379)
REDIS_DB = os.environ.get('REDIS_DB', 0)

# redis connection for storing the blacklisted tokens
blacklistStore = redis.StrictRedis(host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB, decode_responses=True)


def blacklist_token(payload):
    """
    store token jti value in redis
    """
    expTime = payload['exp'] - int(datetime.utcnow().timestamp())
    blacklistStore.set('blacklist:{}'.format(payload['jti']), payload['jti'], expTime)
    return is_token_blacklisted(payload)


def is_token_blacklisted(payload):
    """
    check if jti value is stored redis i.e. token has been blacklisted
    """
    jti = payload['jti']
    if blacklistStore.get('blacklist:'+jti):
        return True
    else:
        return False


def encode_token(payload, private_key):
    return jwt.encode(payload, private_key, algorithm='RS256')


def decode_token(token, public_key):
    return jwt.decode(token, public_key, algoritms='RS256')


def generate_token_header(username, private_key):
    """
    Generate a token header base on the username. Sign using the private key.
    """
    payload = {
        'username': username,
        'iat': datetime.utcnow(),
        'exp': datetime.utcnow() + timedelta(days=2),
        'jti': '{0}{1}'.format(username, int(datetime.utcnow().timestamp()))
    }
    token = encode_token(payload, private_key)
    token = token.decode('utf8')
    return f'Bearer {token}'


def validate_token_header(header, public_key):
    """
    Validate that a token header is correct

    If correct, it returns the payload, if not, it
    returns None
    """
    if not header:
        logger.info('No header')
        return None

    # Retrieve the Bearer token
    parse_result = parse('Bearer {}', header)
    if not parse_result:
        logger.info(f'Wrong format for header "{header}"')
        return None
    token = parse_result[0]
    try:
        decoded_token = decode_token(token.encode('utf8'), public_key)
    except jwt.exceptions.DecodeError:
        logger.warning(f'Error decoding header "{header}". '
                       'This may be key mismatch or wrong key')
        return None
    except jwt.exceptions.ExpiredSignatureError:
        logger.error(f'Authentication header has expired')
        return None

    # Check expiry is in the token
    if 'exp' not in decoded_token:
        logger.warning('Token does not have expiry (exp)')
        return None

    # Check username is in the token
    if 'username' not in decoded_token:
        logger.warning('Token does not have username')
        return None

    # Check if token has been blacklisted
    if is_token_blacklisted(decoded_token):
        logger.error(f'Token has been blacklisted')
        return None

    logger.info('Header successfully validated')
    return decoded_token
