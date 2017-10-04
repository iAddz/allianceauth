# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from django.contrib import messages
from django.contrib.auth.decorators import login_required, permission_required, user_passes_test
from django.shortcuts import render, redirect
from django.db import IntegrityError
from eveonline.models import EveCorporationInfo, EveCharacter
from eveonline.managers import EveManager
from finance.models import FinanceToken, JournalEntry, TaxChange
from finance.manager import FinanceManager
from esi.decorators import token_required

import datetime


import logging

logger = logging.getLogger(__name__)

def access_finances_test(user):
    return user.has_perm('finance.view_corp_finances') or user.has_perm(
        'finance.view_alliance_finances')


def first_day_of_next_month(year, month):
    if month == 12:
        return datetime.datetime(year + 1, 1, 1)
    else:
        return datetime.datetime(year, month + 1, 1)


def first_day_of_previous_month(year, month):
    if month == 1:
        return datetime.datetime(year - 1, 12, 1)
    else:
        return datetime.datetime(year, month - 1, 1)


def chars_per_user():
    SQL_CHAR_COUNT = r"select count(*) from " \
                     r"(SELECT t1.user_id, t1.character_name " \
                     r"FROM eveonline_evecharacter t1 " \
                     r"inner join authentication_authservicesinfo t2 on t1.user_id = t2.user_id " \
                     r"WHERE t2.state='Member' AND t1.alliance_name='inPanic' " \
                     r"GROUP BY t1.user_id " \
                     r"HAVING COUNT(t1.character_id) =%s) T"
    try:
        count = []
        cursor = connections['default'].cursor()
        for x in range(1, 50):
            cursor.execute(SQL_CHAR_COUNT, [x])
            count.append(cursor.fetchone())
        return count
    except:
        logger.exception("Error retrieving invalid chars_per_user")

@login_required
@user_passes_test(access_finances_test)
def finance_view(request, corp_id=None, year=None, month=None):
    if year is None:
        year = datetime.date.today().year
    if month is None:
        month = datetime.date.today().month
    year = int(year)
    month = int(month)

    charsPerUser = chars_per_user()

    # get requested model
    if corp_id:
        selectedcorp = EveCorporationInfo.objects.get(corporation_id=corp_id)
        start_of_month = datetime.datetime(year, month, 1)
        start_of_next_month = first_day_of_next_month(year, month)
        start_of_previous_month = first_day_of_previous_month(year, month)
        entries = JournalEntry.objects.filter(corporation__corporation_id=corp_id).filter(date__gte=start_of_month).filter(
            date__lt=start_of_next_month).order_by('-date')
        bounties = JournalEntry.objects.filter(corporation__corporation_id=corp_id).filter(date__gte=start_of_month).filter(
            date__lt=start_of_next_month).filter(ref_type='bounty_prizes')
        tax = int(TaxChange.objects.filter(corp__corporation_id=corp_id)[0].tax)
        totalBounty = 0
        bruceTax = 0
        for bounty in bounties:
            totalBounty += int(bounty.amount)
        if totalBounty != 0:
            bruceTax = ((totalBounty*100)/tax)*0.03
        
    mainchar = EveManager.get_main_character(request.user)
    if request.user.has_perm('finance.view_corp_finances'):
        corps = EveCorporationInfo.objects.filter(corporation_id=mainchar.corporation_id)
    if request.user.has_perm('finance.view_alliance_finances'):
        tokens = FinanceToken.objects.all()
        corps = EveCorporationInfo.objects.filter(id__in=tokens.values('corp'))

    context = {
        'corps':corps,
    }
    if corp_id:
        context.update({
            'month': start_of_month.strftime("%B"),'year': year,'entries': entries,'monthnr': month,'corp_id': corp_id,
            'scorp': selectedcorp,'previous_month': start_of_previous_month,'totalBounty': totalBounty,
            'bruceTax': bruceTax,})
        if datetime.datetime.now() > start_of_next_month:
            context.update({'next_month': start_of_next_month,})
    else:
        context = {'corps': corps, 'year': year, 'monthnr': month, 'stats': charsPerUser}


    return render(request, 'finance/corpfinances.html', context=context)


@login_required
@user_passes_test(access_finances_test)
@permission_required('corputils.add_corpstats')
@token_required(scopes='esi-wallet.read_corporation_wallets.v1')
def finance_add(request, token):
    try:
        corp_id = EveCharacter.objects.get(character_id=token.character_id).corporation_id
        corp = EveCorporationInfo.objects.get(corporation_id=corp_id)
        ft = FinanceToken.objects.create(token=token, corp=corp)
        if FinanceToken.objects.filter(pk=ft.pk).exists():
            FinanceManager.update(ft)
            FinanceManager.tax(corp)
            return redirect('view_finances', corp_id=corp.corporation_id)
    except EveCorporationInfo.DoesNotExist:
        messages.error(request, _('Unrecognized corporation. Please ensure it is a member of the alliance or a blue.'))
    except IntegrityError:
        messages.error(request, _('Selected corp already has a finance module.'))

    return redirect('view_finances')
