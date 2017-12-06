from __future__ import unicode_literals
from django.contrib.auth import login
from django.contrib.auth import logout
from django.contrib.auth import authenticate
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.views.decorators.clickjacking import xframe_options_exempt
from django.utils.translation import ugettext_lazy as _
from django.urls import resolve
from eveonline.managers import EveManager
from eveonline.models import EveCharacter
from authentication.models import AuthServicesInfo
from authentication.forms import LoginForm, RegistrationForm
from django.contrib.auth.models import User
from django.contrib import messages
from esi.decorators import token_required
import logging
from django_hosts.resolvers import reverse
from django_hosts import host

import eveonline.tasks as EveTasks
from services.modules.teamspeak3.tasks import Teamspeak3Tasks
from services.modules.discord.tasks import DiscordTasks

logger = logging.getLogger(__name__)

def legacy_check(meta):
    return True if "login_user" in meta['HTTP_REFERER'] or "register_user" in meta['HTTP_REFERER'] else False

def login_user(request):
    logger.debug("login_user called by user %s" % request.user)
    if request.method == 'POST':
        url = '/login_user/' if legacy_check(request.META) else '/#login'
        form = LoginForm(request.POST)
        logger.debug("Request of type POST, received form, valid: %s" % form.is_valid())
        if form.is_valid():
            user = authenticate(username=form.cleaned_data['username'], password=form.cleaned_data['password'])
            logger.debug("Authentication attempt with supplied credentials. Received user %s" % user)
            if user is not None:
                if user.is_active:
                    logger.info("Successful login attempt from user %s" % user)
                    login(request, user)
                    next = request.POST.get('next', request.GET.get('next', ''))
                    if not next or next == '/':
                        return redirect(reverse('auth_dashboard', host='auth'))
                    return redirect(next, host='auth')
                else:
                    logger.info("Login attempt failed for user %s: user marked inactive." % user)
                    messages.warning(request, _('Your account has been disabled.'))
            else:
                logger.info("Failed login attempt: provided username %s" % form.cleaned_data['username'])
                messages.error(request, _('Username/password invalid.'))
            return redirect(url, context={'form': form})
    else:
        logger.debug("Providing new login form.")
        form = LoginForm()

    return render(request, 'public/login.html', context={'form': form})


def logout_user(request):
    logger.debug("logout_user called by user %s" % request.user)
    temp_user = request.user
    logout(request)
    logger.info("Successful logout for user %s" % temp_user)
    return redirect(reverse("auth_index", host='home'))


def register_user_view(request):
    logger.debug("register_user_view called by user %s" % request.user)
    if request.method == 'POST':
        url = '/register_user/' if legacy_check(request.META) else '/#register'
        form = RegistrationForm(request.POST)
        logger.debug("Request type POST contains form valid: %s" % form.is_valid())
        if form.is_valid():

            if not User.objects.filter(username=form.cleaned_data['username']).exists():
                user = User.objects.create_user(form.cleaned_data['username'],
                                                form.cleaned_data['email'], form.cleaned_data['password'])

                user.save()
                logger.info("Created new user %s" % user)
                login(request, user)
                messages.warning(request, _('Add an API key to set up your account.'))
                return redirect(reverse('auth_dashboard', host='auth'))

            else:
                logger.error("Unable to register new user: username %s already exists." % form.cleaned_data['username'])
                messages.error(request, _('Username Already Registered'))
                return redirect(url, context={'form': form})
        else:
            logger.debug("Registration form invalid. Returning for user %s to make corrections." % request.user)

    else:
        logger.debug("Returning blank registration form.")
        form = RegistrationForm()

    return render(request, 'public/register.html', context={'form': form})


def index_view(request):
    logger.debug("index_view called by user %s" % request.user)
    if request.method == 'POST':
        url = '/login_user/' if legacy_check(request.META) else '/#login'
        form = LoginForm(request.POST)
        logger.debug("Request of type POST, received form, valid: %s" % form.is_valid())
        if form.is_valid():
            user = authenticate(username=form.cleaned_data['username'], password=form.cleaned_data['password'])
            logger.debug("Authentication attempt with supplied credentials. Received user %s" % user)
            if user is not None:
                if user.is_active:
                    logger.info("Successful login attempt from user %s" % user)
                    login(request, user)
                    next = request.POST.get('next', request.GET.get('next', ''))
                    if not next or next == '/':
                        return redirect(reverse('auth_dashboard', host='auth'))
                    return redirect((reverse('auth_index', host='auth') + next), host='auth')
                else:
                    logger.info("Login attempt failed for user %s: user marked inactive." % user)
                    messages.warning(request, _('Your account has been disabled.'))
            else:
                logger.info("Failed login attempt: provided username %s" % form.cleaned_data['username'])
                messages.error(request, _('Username/password invalid.'))
            return redirect(url, context={'form': form})
    form = LoginForm()
    form2 = RegistrationForm()
    return render(request, 'public/index.html', context={'form': form, 'form2': form2})


def index_redir(request):
    logger.error(request)
    url = reverse('auth_index', host='home')
    path = request.GET.get('next', '')
    redirurl = (url + "?next=" + path + "#login")
    return redirect(redirurl)


@login_required
def help_view(request, id=None):
    logger.debug("help_view called by user %s" % request.user)
    if id=='1':
        EveTasks.refresh_all_apis.delay()
    elif id=='2':
        EveTasks.run_corp_update.delay()
    elif id=='3':
        Teamspeak3Tasks.update_all_groups.delay()
    elif id=='4':
        Teamspeak3Tasks.run_ts3_group_update.delay()
    elif id=='5':
        DiscordTasks.update_all_groups.delay()
    elif id=='6':
        DiscordTasks.update_all_nicknames.delay()
    return render(request, 'registered/help.html')
    
@xframe_options_exempt
def nav_view(request):
    logger.debug("nav_view called by user %s" % request.user)
    return render(request, 'public/nav.html')

@token_required(new=True)
def sso_login(request, token):
    try:
        char = EveCharacter.objects.get(character_id=token.character_id)
        if char.user:
            if char.user.is_active:
                login(request, char.user)
                token.user = char.user
                token.save()
                return redirect(reverse('auth_dashboard', host='auth'))
            else:
                messages.error(request, _('Your account has been disabled.'))
        else:
            messages.warning(request,
                             _('Authenticated character has no owning account. Please log in with username and password.'))
    except EveCharacter.DoesNotExist:
        messages.error(request, _('No account exists with the authenticated character. Please create an account first.'))
    return redirect(login_user)
