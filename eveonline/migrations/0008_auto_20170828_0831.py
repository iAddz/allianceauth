# -*- coding: utf-8 -*-
# Generated by Django 1.11.3 on 2017-08-28 08:31
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('eveonline', '0007_unique_id_name'),
    ]

    operations = [
        migrations.AddField(
            model_name='eveapikeypair',
            name='api_acc',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='eveapikeypair',
            name='api_mask',
            field=models.CharField(default=0, max_length=254),
            preserve_default=False,
        ),
    ]