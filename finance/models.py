# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from django.utils.encoding import python_2_unicode_compatible
from django.db import models
from eveonline.models import EveCorporationInfo
from esi.models import Token
from evelink import corp


@python_2_unicode_compatible
class JournalEntry(models.Model):
    corporation = models.ForeignKey(EveCorporationInfo, on_delete=models.CASCADE)
    amount = models.DecimalField(max_digits=14, decimal_places=2, null=True)
    balance = models.DecimalField(max_digits=14, decimal_places=2, null=True)
    date = models.DateTimeField()
    _extra = models.TextField(default='{}', null=True)
    first_party_id = models.IntegerField(null=True)
    first_party_type = models.CharField(null=True, max_length=15)
    reason = models.CharField(null=True, max_length=40)
    ref_id = models.BigIntegerField(unique=True)
    ref_type = models.CharField(max_length=100)
    second_party_id = models.IntegerField(null=True)
    second_party_type = models.CharField(max_length=15, null=True)
    tax = models.DecimalField(max_digits=14, decimal_places=2, null=True)
    tax_reciever_id = models.IntegerField(null=True)

    def __str__(self):
        output = "Journal Entry ID %s for corp %s" % (self.ref_id, self.corporation.corporation_ticker)
        return output.encode('utf-8')
    
    class Meta:
        permissions = (
            ("view_alliance_finances", "Can see finances for the entire alliance"),
            ("view_corp_finances", "Can see finances for their own corp"),
        )

@python_2_unicode_compatible
class FinanceToken(models.Model):
    token = models.ForeignKey(Token, on_delete=models.CASCADE)
    corp = models.OneToOneField(EveCorporationInfo)
    
    def __str__(self):
        output = "Finance Entry for corp %s" % self.corp.corporation_ticker
        return output.encode('utf-8')

@python_2_unicode_compatible
class TaxChange(models.Model):
    corp = models.ForeignKey(EveCorporationInfo, on_delete=models.CASCADE)
    tax = models.IntegerField()
    date = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        output = "Corp %s changed tax rate to %s" % (self.corp.corporation_ticker, self.tax)
        return output.encode('utf-8')
