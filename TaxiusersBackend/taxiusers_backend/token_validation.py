import os
import jwt
import redis
from parse import parse
from datetime import datetime, timedelta

import logging

logger = logging.getLogger(__name__)

REDIS_URI = os.environ.get('REDIS_URI', 'redis://localhost:6379/0')
print(REDIS_URI)
# redis connection for storing the blacklisted tokens
blacklistStore = redis.StrictRedis.from_url(REDIS_URI, decode_responses=True)


def blacklist_token(payload):
    """
    store token jti value in redis
    """
    expTime = payload['exp'] - int(datetime.utcnow().timestamp())
    blacklistStore.set('blacklist:{}'.format(payload['jti']), payload['jti'],
                       expTime)
    return is_token_blacklisted(payload)


def is_token_blacklisted(payload):
    """
    check if jti value is stored redis i.e. token has been blacklisted
    """
    jti = payload['jti']
    if blacklistStore.get('blacklist:' + jti):
        return True
    else:
        return False


def encode_token(payload, private_key):
    return jwt.encode(payload, private_key, algorithm='RS256')


def decode_token(token, public_key):
    return jwt.decode(token, public_key, algoritms='RS256')


def generate_token_header(payload1, private_key):
    """
    Generate a token header base on the email. Sign using the private key.
    """
    payload = {
        'id': payload1['id'],
        "auth_id": payload1["auth_id"],
        'iat': datetime.utcnow(),
        'exp': datetime.utcnow() + timedelta(days=2),
        'jti': '{0}-{1}'.format(payload1['id'],
                                int(datetime.utcnow().timestamp()))
    }

    # indicate that user is a (super) admin
    if 'admin' in payload1:
        if payload1['admin'] is not None:
            payload['admin'] = payload1['admin']

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

    # Check email is in the token
    if 'id' not in decoded_token:
        logger.warning('Token does not have user id')
        return None

    # Check if token has been blacklisted
    if is_token_blacklisted(decoded_token):
        logger.error(f'Token has been blacklisted')
        return None

    logger.info('Header successfully validated')
    return decoded_token
