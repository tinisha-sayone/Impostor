import inspect

from tenant_schemas.utils import schema_context

import django.contrib.auth as auth
from django.contrib.auth.models import Group
from django.http import HttpRequest
from django.contrib.auth import get_user_model
from django.conf import settings

from impostor.models import ImpostorLog

from apps.retailers.models import Retailer
from etailpet.utils.helpers import get_profile_from_user
from etailpet.utils.constants import USER_RETAILER, USER_CUSTOMER

try:
    IMPOSTOR_GROUP = Group.objects.get(name=settings.IMPOSTOR_GROUP)
except:
    IMPOSTOR_GROUP = None

User = get_user_model()


def find_request():
    '''
    Inspect running environment for request object. There should be one,
    but don't rely on it.
    '''
    frame = inspect.currentframe()
    request = None
    f = frame

    while not request and f:
        if 'request' in f.f_locals and isinstance(f.f_locals['request'], HttpRequest):
            request = f.f_locals['request']
        f = f.f_back

    del frame
    return request


class AuthBackend:
    supports_anonymous_user = False
    supports_object_permissions = False
    supports_inactive_user = False

    def authenticate(self, request, username=None, password=None):
        auth_user = None
        try:
            # Admin logging as user?
            admin, uuser = [uname.strip() for uname in username.split(" as ")]
            # Check if admin exists and authenticates
            try:
                admin_obj = User.objects.get(email=admin)
                auth_user = User.objects.get(email=uuser)
            except User.DoesNotExist:
                admin_obj = User.objects.get(username=admin)
                auth_user = User.objects.get(username=uuser)

            except User.MultipleObjectsReturned:
                logger.warning(
                    'Multiple users with identical email address and password'
                    'were found. Marking all but one as not active.')
            if (((get_profile_from_user(admin_obj) == USER_RETAILER) and (get_profile_from_user(auth_user) == USER_CUSTOMER))
                    or (IMPOSTOR_GROUP and IMPOSTOR_GROUP in admin_obj.groups.all()) and admin_obj.check_password(password)):

                if auth_user:
                    # Try to find request object and maybe be lucky enough to find
                    # IP address there
                    request = find_request()
                    ip_addr = ''
                    if request:
                        ip_addr = request.META.get(
                            'HTTP_X_FORWARDED_FOR', request.META.get(
                                'HTTP_X_REAL_IP', request.META.get(
                                    'REMOTE_ADDR', '')))
                        # if there are several ip addresses separated by comma
                        # like HTTP_X_FORWARDED_FOR returns,
                        # take only the first one, which is the client's address
                        if ',' in ip_addr:
                            ip_addr = ip_addr.split(',', 1)[0].strip()
                    log_entry = ImpostorLog.objects.create(impostor=admin_obj, imposted_as=auth_user, impostor_ip=ip_addr)

                    if log_entry.token and request:
                        request.session['impostor_token'] = log_entry.token

        except:  # Nope. Do nothing and let other backends handle it.
            pass
        return auth_user

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None
