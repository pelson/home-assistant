"""Authentication for HTTP component."""
import asyncio
import base64
from functools import wraps
import hmac
import logging
from types import MethodType

from aiohttp import hdrs
from aiohttp import web

from homeassistant.const import HTTP_HEADER_HA_AUTH
from .util import get_real_ip
from .const import KEY_TRUSTED_NETWORKS, KEY_AUTHENTICATED

DATA_API_PASSWORD = 'api_password'

_LOGGER = logging.getLogger(__name__)

#: A list of all the valid scopes that may be used.
SCOPES = ['view_local']


def assert_authz(request, scope=None):
    """
    Given the request, raise an HTTPUnathorized error if the user does not
    the authorization for the given scope.

    Note: scope not yet used.

    """
    if KEY_AUTHENTICATED not in request:
        _LOGGER.error("Please ensure the authorization middleware is active.")
        raise web.HTTPInternalServerError

    authenticated = request.get(KEY_AUTHENTICATED, False)

    if not authenticated:
        raise web.HTTPUnauthorized()


def require_authorization(scope):
    """
    Create a decorator that may be used to assert authorization for a handler.

    Note: Another source of authorization in home-assistant is
    :func:`http.request_handler_factory`.

    """
    if scope not in SCOPES:
        raise ValueError('Invalid authorization scope "{}".'.format(scope))
    def authorize_handler_decorator(handler):
        @wraps(handler)
        @asyncio.coroutine
        def new_handler(request):
            assert_authz(request, scope)
            return (yield from handler(request))
        return new_handler
    return authorize_handler_decorator


def authorized_resource(resource, required_scope):
    """Modify the resource to ensure authorization against the requested permissions."""
    orig_resolve = resource.resolve
    @asyncio.coroutine
    def new_resolve(self, request):
        resolved = yield from orig_resolve(request)
        url_mapping, allowed = resolved
        if url_mapping and required_scope:
            # Wrap the mapping's _handler to check authorization.
            url_mapping.route._handler = require_authorization(required_scope)(
                    url_mapping.route._handler)
        return url_mapping, allowed
    resource.resolve = MethodType(new_resolve, resource)
    return resource


@web.middleware
@asyncio.coroutine
def auth_middleware(request, handler):
    """Authenticate as middleware."""
    # If no password set, just always set authenticated=True
    if request.app['hass'].http.api_password is None:
        request[KEY_AUTHENTICATED] = True
        return (yield from handler(request))

    # Check authentication
    authenticated = False

    if (HTTP_HEADER_HA_AUTH in request.headers and
            validate_password(
                request, request.headers[HTTP_HEADER_HA_AUTH])):
        # A valid auth header has been set
        authenticated = True

    elif (DATA_API_PASSWORD in request.query and
          validate_password(request, request.query[DATA_API_PASSWORD])):
        authenticated = True

    elif (hdrs.AUTHORIZATION in request.headers and
          validate_authorization_header(request)):
        authenticated = True

    elif is_trusted_ip(request):
        authenticated = True

    request[KEY_AUTHENTICATED] = authenticated
    return (yield from handler(request))


def is_trusted_ip(request):
    """Test if request is from a trusted ip."""
    ip_addr = get_real_ip(request)

    return ip_addr and any(
        ip_addr in trusted_network for trusted_network
        in request.app[KEY_TRUSTED_NETWORKS])


def validate_password(request, api_password):
    """Test if password is valid."""
    return hmac.compare_digest(
        api_password, request.app['hass'].http.api_password)


def validate_authorization_header(request):
    """Test an authorization header if valid password."""
    if hdrs.AUTHORIZATION not in request.headers:
        return False

    auth_type, auth = request.headers.get(hdrs.AUTHORIZATION).split(' ', 1)

    if auth_type != 'Basic':
        return False

    decoded = base64.b64decode(auth).decode('utf-8')
    username, password = decoded.split(':', 1)

    if username != 'homeassistant':
        return False

    return validate_password(request, password)
