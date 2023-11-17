from django.contrib import admin
from django.urls import path, include
from furniture_app import views
from django.urls import re_path

urlpatterns = [
    path('admin/', admin.site.urls),

    path('login/',views.login_user, name='login_user'),
    path('signup/',views.signup_user, name='signup_user'),

    path('types/', views.get_types, name='get_types'),
    path('furniture/', views.get_furniture, name='get_furniture'),
    
    path('defect/', views.post_defect, name='post_defect'),
    path('defects/', views.get_defects, name='get_defects'),

    path('defect/<int:pk>/', views.handle_defect, name='handle_defect'),
    path('states/', views.get_states, name='get_states'),

]