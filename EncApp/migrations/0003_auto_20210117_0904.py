# Generated by Django 3.1.5 on 2021-01-17 03:34

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('EncApp', '0002_customval'),
    ]

    operations = [
        migrations.AlterField(
            model_name='customval',
            name='ValName',
            field=models.CharField(max_length=30),
        ),
    ]