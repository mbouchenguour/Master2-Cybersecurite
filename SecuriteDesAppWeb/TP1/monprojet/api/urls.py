from django.urls import path
from .views import lire_fichier_api

urlpatterns = [
    path("lire_fichier/", lire_fichier_api, name="lire_fichier_api"),
]
