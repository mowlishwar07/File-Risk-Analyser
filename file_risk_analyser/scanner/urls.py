from django.urls import path
from . import views

urlpatterns = [
    path('', views.index),
    path('scan/', views.scan_file),
    path('history/', views.history),
]