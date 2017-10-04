from django.conf.urls import include, url
from django.conf.urls.i18n import i18n_patterns
import django.contrib.auth.views
import authentication.views
import esi.urls
from django.utils.translation import ugettext_lazy as _

urlpatterns = [
    # Locale
    url(r'^i18n/', include('django.conf.urls.i18n')),
    
    # Index
    url(_(r'^$'), authentication.views.index_view, name='auth_index'),
]

# User viewed/translated URLS
urlpatterns += i18n_patterns(
    # Authentication
    url(_(r'^login_user/'), authentication.views.login_user, name='auth_login_user'),
    url(_(r'^register_user/'), authentication.views.register_user_view, name='auth_register_user'),
    
    url(_(r'^user/password/$'), django.contrib.auth.views.password_change, name='password_change'),
    url(_(r'^user/password/done/$'), django.contrib.auth.views.password_change_done,
        name='password_change_done'),
    url(_(r'^user/password/reset/$'), django.contrib.auth.views.password_reset,
        name='password_reset'),
    url(_(r'^user/password/password/reset/done/$'), django.contrib.auth.views.password_reset_done,
        name='password_reset_done'),
    url(_(r'^user/password/reset/complete/$'), django.contrib.auth.views.password_reset_complete,
        name='password_reset_complete'),
    url(_(r'^user/password/reset/confirm/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>.+)/$'),
        django.contrib.auth.views.password_reset_confirm, name='password_reset_confirm'),
        
    # SSO
    url(r'^sso/', include(esi.urls, namespace='esi')),
    url(r'^sso/login$', authentication.views.sso_login, name='auth_sso_login'),
)
