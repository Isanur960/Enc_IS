from django.contrib import admin
from django.urls import path , include
from EncApp import views

urlpatterns = [
    path('', views.index , name="home" ),
    path('privacy_policy', views.privacy , name="privacy_policy" ),
    path('encryption', views.encryption , name="encryption" ),
    path('decryption', views.decryption , name="decryption" ),
]
