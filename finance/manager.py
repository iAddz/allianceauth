from datetime import datetime
from esi.models import Token
from esi.errors import TokenError
from finance.models import JournalEntry, FinanceToken, TaxChange
from notifications import notify
from bravado.exception import HTTPForbidden
from django.db.utils import IntegrityError
from esi.clients import esi_client_factory

import logging

logger = logging.getLogger(__name__)

class FinanceManager:
    
    def __init__(self):
        pass
    
    @staticmethod
    def has_token(corp_id):
        return FinanceToken.objects.filter(corp=corp_id).exists()

    @staticmethod
    def update(ftoken):
        try:
            corp = ftoken.corp
            token = ftoken.token
            lastid = 0
            c = token.get_esi_client(version='v1')
            while True:
                logger.DEBUG("Entering corp wallet journal update loop for %s" % corp)
                if lastid == 0:
                    entries = c.Wallet.get_corporations_corporation_id_wallets_division_journal(corporation_id=corp.corporation_id, division=1).result()
                else:
                    entries = c.Wallet.get_corporations_corporation_id_wallets_division_journal(corporation_id=corp.corporation_id, division=1, from_id=lastid).result()
                if len(entries) == 0:
                    logger.DEBUG("Ran out of records, leaving loop")
                    return
                for entry in entries:
                        try:
                            JournalEntry.objects.create(
                                corporation = corp,
                                amount = entry['amount'],
                                balance = entry['balance'],
                                date = entry['date'],
                                _extra = entry['extra_info'],
                                first_party_id = entry['first_party_id'],
                                first_party_type = entry['first_party_type'],
                                reason = entry['reason'],
                                ref_id = entry['ref_id'],
                                ref_type = entry['ref_type'],
                                second_party_id = entry['second_party_id'],
                                second_party_type = entry['second_party_type'],
                                tax = entry['tax'],
                                tax_reciever_id = entry['tax_reciever_id']
                            )
                            lastid = int(entry['ref_id'])
                        except IntegrityError:
                            logger.DEBUG("Duplicate records detected, leaving loop")
                            return
        except TokenError as e:
            logger.warning("%s failed to update: %s " % (token, e))
            if token.user:
                notify(token.user, "%s failed to update with your ESI token." % token,
                       message="Your token has expired or is no longer valid. Please add a new one to create a new CorpStats.",
                       level="error")
            token.delete()
        except HTTPForbidden as e:
            logger.warning("%s failed to update: %s" % (token, e))
            if token.user:
                notify(token.user, "%s failed to update with your ESI token." % token,
                       message="%s: %s" % (e.status_code, e.message), level="error")
            token.delete()
        except AssertionError:
            logger.warning("%s token character no longer in corp." % token)
            if token.user:
                notify(token.user, "%s cannot update with your ESI token." % token,
                       message="%s cannot update with your ESI token as you have left corp." % token, level="error")
            token.delete()


    @staticmethod
    def tax(corp):
        c = esi_client_factory(version='v3')
        tax = int((c.Corporation.get_corporations_corporation_id(corporation_id=corp.corporation_id).result()['tax_rate'])*100)
        try:
            lasttax = TaxChange.objects.filter(corp=corp).order_by('-id')[0]
            if tax != lasttax.tax:
                TaxChange.objects.create(corp=corp, tax=tax)
        except (TaxChange.DoesNotExist, IndexError):
            TaxChange.objects.create(corp=corp, tax=tax)

