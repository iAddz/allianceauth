from django.conf import settings
from django_hosts import patterns, host

host_patterns = patterns('',
    host(r'entosis.link', 'alliance_auth.publicurls', name='home'),
    host(r'auth.entosis.link', settings.ROOT_URLCONF, name='auth'), 
)
