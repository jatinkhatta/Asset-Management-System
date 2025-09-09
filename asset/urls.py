"""
URL configuration for asset project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.1/topics/http/urls/
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
from django.urls import path
from django.conf import settings
from django.conf.urls.static import static
from app import views
from django.conf import settings
from django.conf.urls.static import static
from django.urls import re_path
from django.views.static import serve
urlpatterns = [
    path('admin/', admin.site.urls),
    path('documentation/', views.documentation_view, name='documentation'),
    path('', views.login, name='login'),
    path('register/', views.register, name='register'),
    path('logout/', views.user_logout, name='logout'),
    path('login/', views.login, name='login'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('api/chart-data/', views.chart_data_api, name='chart_data_api'),
    path('Asset Inventory/', views.Asset_Inventory, name='Asset Inventory'),
    path('api/generate-asset-number/', views.GenerateAssetNumberView.as_view(), name='generate_asset_number'),
    path('add-asset/', views.add_asset_selection, name='Add Asset'),
    path('add-hardware-asset/', views.add_hardware_asset, name='add_hardware_asset'),
    path('add-software-asset/', views.add_software_asset, name='add_software_asset'),
    path('add-vendor/', views.add_vendor, name='add_vendor'),
    path('get-vendors/', views.get_vendors, name='get_vendors'),
    path('create_category/', views.create_category, name='create_category'),
    path('Alerts/', views.Alerts, name='Alerts'),
    path('MaintenancePage/', views.MaintenancePage, name='MaintenancePage'),
    path('asset-request-tracking/', views.asset_request_tracking, name='asset_request_tracking'),  # Main request tracking page
    path('api/user-details/<int:user_id>/', views.get_user_details, name='get_user_details'),
    path('users/', views.user_management, name='user_management'),
    path('users/delete/<int:user_id>/', views.delete_user, name='delete_user'),
    
    path('update-request-status/<int:request_id>/', views.update_request_status, name='update_request_status'),  # Handles status updates
    path('api/request-history/<int:request_id>/', views.request_history, name='request-history'),
    path('Reports/', views.Reports, name='Reports'),
    path('asset_stats_view/', views.asset_stats_view, name='asset_stats_view'),
    path('custom_report_builder/', views.custom_report_builder, name='custom_report_builder'),
    path('get_asset_data/', views.get_asset_data, name='get_asset_data'),
    path('get_filtered_assets/', views.get_filtered_assets, name='get_filtered_assets'),
    path('download-asset-data-pdf/', views.download_asset_data_pdf, name='download_asset_data_pdf'),
    path('download_idle_report/', views.download_idle_report, name='download_idle_report'),
    path('download-cost-analysis/',views.download_cost_analysis_pdf, name='download_cost_analysis_pdf'),
    path('download-combined-reports/',views.download_combined_reports, name='download_combined_reports'),
    path('get_cost_data/', views.get_cost_data, name='get_cost_data'),
    path('export-assets/', views.export_assets, name='export_assets'),
    path('delete_Asset/<int:AssetID>', views.delete_Asset, name='delete_Asset'),
    path('update-asset/<str:asset_id>/', views.update_asset, name='update_asset'),
    path('assets/get_email_template/', views.get_email_template, name='get_email_template'),
    path('assets/send_email_notification/', views.send_email_notification, name='send_email_notification'),
    path('update-request-status/<int:RequestId>/', views.update_request_status, name='update_request_status'),
    path('download/<path:document_path>/', views.download_document, name='download_document'),
    path('upload-excel/', views.upload_excel, name='upload_excel'),

    path('user_dashboard/', views.user_dashboard, name='user_dashboard'),
    path('user_log_download_csv/', views.user_log_download_csv, name='user_log_download_csv'),
    path('user_log_download_pdf/', views.user_log_download_pdf, name='user_log_download_pdf'),
    path('User_Asset_Inventory/', views.User_Asset_Inventory, name='User_Asset_Inventory'),  # User
    path('submit_request/', views.submit_request, name='submit_request'),
    path('user/asset-requests/', views.user_asset_requests, name='user_asset_requests'),
     path('user-update-request-status/<int:request_id>/', views.user_update_request_status, name='user_update_request_status'),
     path('request/acknowledge/<int:request_id>/', views.acknowledge_asset_request, name='acknowledge_asset_request'),
    path('user/cancel-request/<int:request_id>/', views.cancel_asset_request, name='cancel_asset_request'),
    path('user/surrender-request/<int:request_id>/', views.surrender_asset_request, name='surrender_asset_request'),
  
]

# Serve media files in production
if not settings.DEBUG:
    urlpatterns += [
        re_path(r'^media/(?P<path>.*)$', serve, {'document_root': settings.MEDIA_ROOT}),
    ]
else:
    # Serve media files during development
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)