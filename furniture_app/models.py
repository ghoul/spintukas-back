from django.db import models
from django.contrib.auth.models import User

class Type(models.Model):
    title = models.CharField(max_length=20)

class State(models.Model):
    title = models.CharField(max_length=20)

class Furniture(models.Model):
    title = models.CharField(max_length=20)
    code = models.CharField(max_length=10)

class Defect(models.Model):
    date = models.DateField()
    description = models.CharField(max_length=200)
    level = models.IntegerField()
    user_reported = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='reported_defects'
    )
    user_assigned = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='assigned_defects',
        null=True )
    type = models.ForeignKey(Type,on_delete=models.CASCADE)
    furniture = models.ForeignKey(Furniture,on_delete=models.CASCADE)
    state = models.ForeignKey(State, on_delete=models.CASCADE)
