from django.db import models

# Create your models here.

class tempfiles(models.Model):
    idn = models.IntegerField()
    fname = models.CharField(max_length=20)

class CustomVal(models.Model):
    ValName = models.CharField(max_length=30)
    val = models.IntegerField()