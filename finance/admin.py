# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from django.contrib import admin
from finance.models import JournalEntry
from finance.models import FinanceToken
from finance.models import TaxChange

admin.site.register(JournalEntry)
admin.site.register(FinanceToken)
admin.site.register(TaxChange)
