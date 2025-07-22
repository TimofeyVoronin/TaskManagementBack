"""
URL configuration for core project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
#from taskmanagement.views import index
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView, SpectacularRedocView
from rest_framework_simplejwt.views import (
    TokenRefreshView,
    TokenVerifyView,
)


urlpatterns = [
    path('admin/', admin.site.urls),
    # 1) Генерация OpenAPI‑схемы по /schema/ (имя — "schema")
    path('schema/', SpectacularAPIView.as_view(), name='schema'),

    # 2) Swagger UI по /docs/, берёт схему с reverse('schema')
    path('docs/', SpectacularSwaggerView.as_view(url_name='schema'), name='swagger'),

    # опционально — ReDoc UI
    path('redoc/', SpectacularRedocView.as_view(url_name='schema'), name='redoc'),
    
    #path('tasks/', include('taskmanagement.urls')),
    path('profile/', include('registration.urls')),
    path('docs/', SpectacularSwaggerView.as_view(url_name='schema'), name='swagger')
]
