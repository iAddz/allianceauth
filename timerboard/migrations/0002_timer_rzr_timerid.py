# -*- coding: utf-8 -*-
# Generated by Django 1.11.1 on 2017-06-04 19:43
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('timerboard', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='timer',
            name='rzr_timerid',
            field=models.IntegerField(default=0),
        ),
    ]