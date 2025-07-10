from django.urls import path
from . import views

urlpatterns = [
    path('', views.login_view, name='login'),
    path('admin/', views.admin_dashboard, name='admin_dashboard'),
    path('upload/', views.upload_excel, name='upload_excel'),
    path('publish/<int:file_id>/', views.publish_excel, name='publish_excel'),
    path('doctor/', views.doctor_dashboard, name='doctor_dashboard'),
    path('delete/<int:file_id>/', views.delete_excel, name='delete_excel'),
    path('audit-logs/', views.audit_logs, name='audit_logs'),
    path('patient/<str:patient_id>/', views.patient_detail, name='patient_detail'),
    path('clear_audit_logs/', views.clear_audit_logs, name='clear_audit_logs'),
    path('manage-users/', views.manage_users, name='manage_users'),
    path('add-user/', views.add_user, name='add_user'),
    path('delete-user/<int:user_id>/', views.delete_user, name='delete_user'),
]
