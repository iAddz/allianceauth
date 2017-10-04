from alliance_auth.celeryapp import app
from finance.manager import FinanceManager
from eveonline.models import EveCorporationInfo
from finance.models import FinanceToken

import logging

logger = logging.getLogger(__name__)

class FinanceTasks:
    
    def __init__(self):
        pass

    @staticmethod
    @app.task(bind=True, name='finance.update_journal')
    def update_journal(task_self, pk):
        corp = EveCorporationInfo.objects.get(pk=pk)
        logger.debug("Updating wallet journal for corp %s" % corp)
        if FinanceManager.has_token(corp.pk):
            token = FinanceToken.objects.get(corp=corp)
            FinanceManager.update(token)
        else:
            logger.debug("Corp %s does not have a finance token" % corp)


    @staticmethod
    @app.task(name="finance.update_all_journals")
    def update_all_journals():
        logger.debug("Updating all wallet journals")
        tokens = FinanceToken.objects.all()
        corps = EveCorporationInfo.objects.filter(id__in=tokens.values('corp'))
        for corp in corps:
            FinanceTasks.update_journal.delay(corp.pk)


    @staticmethod
    @app.task(name="finance.update_tax")
    def update_tax():
        logger.debug("Updating all corp tax")
        tokens = FinanceToken.objects.all()
        corps = EveCorporationInfo.objects.filter(id__in=tokens.values('corp'))
        for corp in corps:
            FinanceManager.tax(corp)
