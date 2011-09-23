"""
Facebook OAuth support.

This contribution adds support for Facebook OAuth service. The settings
FACEBOOK_APP_ID and FACEBOOK_API_SECRET must be defined with the values
given by Facebook application registration process.

Extended permissions are supported by defining FACEBOOK_EXTENDED_PERMISSIONS
setting, it must be a list of values to request.

By default account id and token expiration time are stored in extra_data
field, check OAuthBackend class for details on how to extend it.
"""
import cgi
import logging
from urllib import urlencode
from urllib2 import urlopen, URLError

from django.conf import settings
from django.contrib.auth.models import get_hexdigest
from django.utils import simplejson
from django.contrib.auth import authenticate

from social_auth.backends import BaseOAuth, OAuthBackend, USERNAME


# Facebook configuration
FACEBOOK_SERVER = 'graph.facebook.com'
FACEBOOK_AUTHORIZATION_URL = 'https://%s/oauth/authorize' % FACEBOOK_SERVER
FACEBOOK_ACCESS_TOKEN_URL = 'https://%s/oauth/access_token' % FACEBOOK_SERVER
FACEBOOK_CHECK_AUTH = 'https://%s/me' % FACEBOOK_SERVER
EXPIRES_NAME = getattr(settings, 'SOCIAL_AUTH_EXPIRATION', 'expires')


class FacebookBackend(OAuthBackend):
    """Facebook OAuth authentication backend"""
    name = 'facebook'
    # Default extra data to store
    EXTRA_DATA = [('id', 'id'), ('expires', EXPIRES_NAME)]

    def get_user_details(self, response):
        """Return user details from Facebook account"""
        return {USERNAME: response.get('username') or response['name'],
                'email': response.get('email', ''),
                'fullname': response['name'],
                'first_name': response.get('first_name', ''),
                'last_name': response.get('last_name', '')}


class FacebookAuth(BaseOAuth):
    """Facebook OAuth mechanism"""
    AUTH_BACKEND = FacebookBackend

    def get_fb_csrf_token(self):
        session_key = self.request.session.session_key
        return get_hexdigest('md5', session_key, settings.FACEBOOK_API_SECRET)[:6]

    def auth_url(self):
        """Returns redirect url"""

        fb_CSRF_state = self.get_fb_csrf_token()

        #TODO for debugging
        meta = {}
        for key in ('HTTP_COOKIE', 'HTTP_USER_AGENT', 'REQUEST_URI', 'REMOTE_ADDR'):
            if key in self.request.META:
                meta[key] = self.request.META[key]
        logging.getLogger('social_auth').info(
            'fb_state_set %s %s %s' % (fb_CSRF_state, self.request.session.session_key, meta))
        #end debugging

        args = {'client_id': settings.FACEBOOK_APP_ID,
                'redirect_uri': self.redirect_uri,
                'state': fb_CSRF_state,
                }
        if hasattr(settings, 'FACEBOOK_EXTENDED_PERMISSIONS'):
            args['scope'] = ','.join(settings.FACEBOOK_EXTENDED_PERMISSIONS)
        return FACEBOOK_AUTHORIZATION_URL + '?' + urlencode(args)

    def auth_complete(self, *args, **kwargs):
        """Returns user, might be logged in"""
        if 'code' in self.data:
            local_state = self.get_fb_csrf_token()
            facebook_state = self.data['state']
            if facebook_state != local_state:
                #TODO remove logging before merging to Trunk
                meta = {}
                for key in ('HTTP_COOKIE', 'HTTP_USER_AGENT', 'REQUEST_URI', 'REMOTE_ADDR'):
                    if key in self.request.META:
                        meta[key] = self.request.META[key]
                logging.getLogger('social_auth').warning(
                    'invalid_or_missing_state %s %s %s %s' % (
                        local_state, facebook_state, self.request.session.session_key, meta)
                )
                #error = "invalid or missing state"
                #raise ValueError('Authentication error: %s' % error)

            url = FACEBOOK_ACCESS_TOKEN_URL + '?' + \
                  urlencode({'client_id': settings.FACEBOOK_APP_ID,
                                'redirect_uri': self.redirect_uri,
                                'client_secret': settings.FACEBOOK_API_SECRET,
                                'code': self.data['code']})
            try:
                response = cgi.parse_qs(urlopen(url, timeout=30).read())
            except URLError, e:
                logging.getLogger('social_auth').error('facebook_url_error %s' % e.message)
                raise ValueError(e.message)
                
            access_token = response['access_token'][0]
            data = self.user_data(access_token)
            data['access_token'] = access_token
            # expires will not be part of response if offline access
            # premission was requested
            if 'expires' in response:
                data['expires'] = response['expires'][0]
            kwargs.update({'response': data, FacebookBackend.name: True})
            return authenticate(*args, **kwargs)
        else:
            error = self.data.get('error') or 'unknown error'
            raise ValueError('Authentication error: %s' % error)

    def user_data(self, access_token):
        """Loads user data from service"""
        params = {'access_token': access_token, }
        url = FACEBOOK_CHECK_AUTH + '?' + urlencode(params)
        try:
            data = simplejson.load(urlopen(url, timeout=30))
        except (URLError, ValueError), e:
            raise ValueError('Authentication error: %s' % e.message)
        if not isinstance(data, dict):
            raise ValueError('Authentication error: bad_response_type')
        if 'error' in data:
            error = self.data.get('error') or 'unknown error'
            raise ValueError('Authentication error: %s' % error)
        return data

    @classmethod
    def enabled(cls):
        """Return backend enabled status by checking basic settings"""
        return all(hasattr(settings, name) for name in
                        ('FACEBOOK_APP_ID',
                         'FACEBOOK_API_SECRET'))


# Backend definition
BACKENDS = {
    'facebook': FacebookAuth,
}
