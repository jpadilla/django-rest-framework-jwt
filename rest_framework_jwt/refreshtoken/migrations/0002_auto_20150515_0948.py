# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('refreshtoken', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='refreshtoken',
            name='app',
            field=models.CharField(max_length=255),
        ),
        migrations.AlterUniqueTogether(
            name='refreshtoken',
            unique_together=set([('user', 'app')]),
        ),
    ]
