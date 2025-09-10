from django import forms
from django.shortcuts import render, redirect, get_object_or_404
from django.conf import settings
from django.contrib import messages
from django.contrib.auth.hashers import make_password, check_password
from django.contrib.auth import authenticate, logout
from django.db.models import Sum, Count, F, ExpressionWrapper, fields
from django.db.models.functions import TruncMonth
from django.http import JsonResponse, HttpResponse
from django.urls import reverse
from django.views.decorators.http import require_http_methods, require_POST
from django.core.mail import send_mail, EmailMessage
from django.contrib.auth.decorators import login_required
from collections import defaultdict
from datetime import datetime, date, timedelta
from io import BytesIO
import os
import json
import csv
import matplotlib.pyplot as plt
from PIL import Image as PILImage
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib.utils import ImageReader
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image as ReportLabImage
from reportlab.lib.units import inch
from celery import shared_task
from .models import *
from .forms import *
from django.contrib import messages
from django.shortcuts import render, redirect
from django.contrib.auth.hashers import make_password
from .forms import registerForm  # Assuming you have a registerForm defined

from django.contrib import messages
from django.shortcuts import render, redirect
from django.contrib.auth.hashers import make_password
from .forms import registerForm
from .models import User  # Import the User model

from django.shortcuts import render

def documentation_view(request):
    return render(request, 'user_documentation.html')
def register(request):
    if request.method == 'POST':
        form = registerForm(request.POST)
        email = request.POST.get('email', '').lower()  # Convert email to lowercase

        # Check if the email already exists in the database
        if User.objects.filter(email=email).exists():
            messages.error(request, 'A user with this email already exists.')
            return render(request, 'register.html', {'form': form})

        # If the email doesn't exist, proceed with form validation
        if form.is_valid():
            # Save the user with a hashed password
            user = form.save(commit=False)
            user.email = email  # Ensure email saved is also in lowercase
            user.password_hash = make_password(form.cleaned_data['password'])
            user.save()

            # Add a success message and redirect to the login page
            messages.success(request, 'Signup successful! Please login.')
            return redirect('login')  # Redirect to the login page
        else:
            # Add an error message if the form is invalid
            messages.error(request, 'Please check the details and try again.')
    else:
        form = registerForm()

    # Render the registration page with the form and any messages
    return render(request, 'register.html', {'form': form})




from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth.hashers import check_password
from .models import User
import json
from django.contrib import messages
def login(request):
    if request.method == 'POST':
        email = request.POST.get('email', '').lower()  # Convert email to lowercase
        password = request.POST.get('password')

        try:
            # Fetch the user from the database using lowercase email
            user = User.objects.get(email=email)

            # Verify the password
            if check_password(password, user.password_hash):
                # Set session variables
                request.session['user_id'] = user.UserId
                request.session['role'] = user.role.upper()

                # Restore viewed_alert_ids from cookies (if they exist)
                viewed_alert_ids_json = request.COOKIES.get('viewed_alert_ids', '[]')
                try:
                    viewed_alert_ids = json.loads(viewed_alert_ids_json)
                except json.JSONDecodeError:
                    viewed_alert_ids = []

                request.session['viewed_alert_ids'] = viewed_alert_ids

                # Redirect based on role
                if user.role.upper() == 'ADMIN':
                    return redirect('dashboard')
                else:
                    return redirect('user_dashboard')
            else:
                messages.error(request, 'Invalid email or password.')
        except User.DoesNotExist:
            messages.error(request, 'User not found.')

    return render(request, 'login.html')


import json
from django.shortcuts import redirect
from django.contrib.auth import logout

def user_logout(request):
    # Save viewed_alert_ids to a cookie before clearing the session
    viewed_alert_ids = request.session.get('viewed_alert_ids', [])
    
    # Serialize the viewed_alert_ids list to JSON
    viewed_alert_ids_json = json.dumps(viewed_alert_ids)
    
    # Perform logout
    logout(request)
    
    # Set the viewed_alert_ids in a cookie to persist across sessions
    response = redirect('login')  # Redirect to login page
    response.set_cookie('viewed_alert_ids', viewed_alert_ids_json, max_age=60*60*24*30)  # Expires in 30 days
    
    return response

from django.http import JsonResponse
from django.utils.timezone import now
from datetime import timedelta
from collections import defaultdict
from django.db.models import Count
from app.models import Asset, AssetRequest, Category
import json
from django.contrib.auth.decorators import login_required

def chart_data_api(request):
    """API endpoint to provide chart data for the dashboard"""
    
    # Asset Distribution Data - Category-wise distribution
    asset_distribution = Asset.objects.values('Category').annotate(
        quantity=Count('Category')
    ).order_by('-quantity')
    
    # Monthly Asset Usage Data
    six_months_ago = now() - timedelta(days=180)
   
    # Initialize data structures
    monthly_data = defaultdict(lambda: defaultdict(int))
    category_data = defaultdict(lambda: defaultdict(int))
    all_months = set()
 
    # Get approved asset requests within last 6 months
    asset_requests = AssetRequest.objects.filter(
        StartDate__gte=six_months_ago,
        Status='Completed'
    ).select_related('AssetID').order_by('StartDate')
 
    # Process each approved request
    for asset_req in asset_requests:
        month = asset_req.StartDate.strftime("%b %Y")
        category = asset_req.AssetID.Category
       
        # Only count if the request is approved
        all_months.add(month)
        monthly_data['all'][month] += 1
        category_data[category][month] += 1
 
    # Sort months chronologically
    sorted_months = sorted(list(all_months),
                         key=lambda x: datetime.strptime(x, "%b %Y"))
 
    # Get all distinct category names from the Category model
    distinct_categories = Category.objects.values_list('Name', flat=True).distinct()
 
    # Prepare the final chart data structure
    usage_chart_data = {
        "months": sorted_months,
        "usage_counts": [monthly_data['all'][month] for month in sorted_months],
        "categories": {
            category_name: {
                "months": sorted_months,
                "usage_counts": [
                    category_data.get(category_name, {}).get(month, 0)  # Default to 0 if missing
                    for month in sorted_months
                ]
            }
            for category_name in distinct_categories
        }
    }
    
    # NEW: Get asset provider distribution data
    provider_distribution = Asset.objects.values('AssetProvider').annotate(
        count=Count('AssetID')
    ).order_by('AssetProvider')
   
    # NEW: Calculate the percentages for each provider
    total_count = sum(item['count'] for item in provider_distribution)
    for item in provider_distribution:
        item['percentage'] = round((item['count'] / total_count) * 100, 1) if total_count > 0 else 0
   
    # NEW: Get asset counts by provider and type
    provider_type_distribution = {}
    providers = [choice[0] for choice in Asset.ASSET_PROVIDER_CHOICES]
   
    for provider in providers:
        provider_type_distribution[provider] = {
            'Hardware': Asset.objects.filter(AssetProvider=provider, AssetType='Hardware').count(),
            'Software': Asset.objects.filter(AssetProvider=provider, AssetType='Software').count(),
            'Total': Asset.objects.filter(AssetProvider=provider).count()
        }
    
    # Prepare the response data
    chart_data = {
        'asset_distribution': {
            'category_labels': [item['Category'] for item in asset_distribution],
            'category_values': [item['quantity'] for item in asset_distribution],
        },
        'monthly_usage': usage_chart_data,
        'provider_distribution': list(provider_distribution),
        'provider_type_distribution': provider_type_distribution
    }
    
    return JsonResponse(chart_data)

def dashboard(request):
    user_id = request.session.get('user_id')
    if not user_id:
        return redirect('login')  # Redirect if not logged in
 
    # Fetch user details
    user = User.objects.get(UserId=user_id)
    
    # Basic statistics
    total_assets = Asset.objects.count()
 
    # Count bonded and non-bonded assets
    bonded_assets = Asset.objects.filter(AssetBondType='Bonded').count()
    # This would update all variations to 'Non Bonded'
    Asset.objects.filter(
        Q(AssetBondType__iexact='non-bonded') |
        Q(AssetBondType__iexact='nonbonded') |
        Q(AssetBondType__iexact='non bonded')
    ).update(AssetBondType='Non Bonded')
    non_bonded_assets = Asset.objects.filter(AssetBondType='Non Bonded').count()
 
    # Count hardware and software assets
    hardware_assets = Asset.objects.filter(AssetType='Hardware').count()
    software_assets = Asset.objects.filter(AssetType='Software').count()
   
    # Get only approved asset requests
    approved_requests = AssetRequest.objects.filter(Status='Completed')
   
    # Count distinct assets that are currently in approved requests
    in_use_assets = AssetRequest.objects.filter(
        Status='Completed',
        AssetID__AssetAvailability='In Use'
    ).values('AssetID').distinct().count()
    
    # Get IDs of assets that are currently in approved requests
    used_asset_ids = approved_requests.values_list('AssetID', flat=True).distinct()
   
    # Count assets that are not in use (i.e., not in approved requests or not marked as "In Use")
    not_in_use_assets = Asset.objects.exclude(
        AssetID__in=used_asset_ids, AssetAvailability='In Use'
    ).count()
   
    # Count assets under maintenance
    under_maintenance_assets = Asset.objects.filter(AssetStatus='Under Maintenance').count()
 
    # Get all distinct category names from the Category model
    distinct_categories = Asset.objects.values_list('Category', flat=True).distinct()

    context = {
        'total_assets': total_assets,
        'bonded_assets': bonded_assets,
        'non_bonded_assets': non_bonded_assets,
        'hardware_assets': hardware_assets,
        'software_assets': software_assets,
        'in_use_assets': in_use_assets,
        'available_assets': not_in_use_assets,
        'under_maintenance_assets': under_maintenance_assets,
        'asset_categories': distinct_categories,  # Still need this for the filter dropdown
        'user': user,
    }
 
    return render(request, "admin/dashboard.html", context)

def handle_file_upload(file, folder_path):
    """
    Handle file upload and return the relative file path with forward slashes
    """
    # Ensure folder_path uses forward slashes
    folder_path = folder_path.replace("\\", "/")  # Replace any backslashes with forward slashes
    
    # Create full path if it doesn't exist
    full_path = os.path.join(settings.MEDIA_ROOT, folder_path)
    os.makedirs(full_path, exist_ok=True)
    
    # Generate unique filename
    file_name = f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{file.name}"
    file_path = os.path.join(folder_path, file_name).replace("\\", "/")  # Ensure the file path uses forward slashes
    
    # Save file
    with open(os.path.join(settings.MEDIA_ROOT, file_path), 'wb+') as destination:
        for chunk in file.chunks():
            destination.write(chunk)
    
    return file_path


import logging
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.db import transaction
from django.utils import timezone
from .models import AssetNumberTracking, Asset

# Configure logging
logger = logging.getLogger(__name__)

def generate_unique_asset_number():
    """
    Generate a unique asset number with INT- Prefix and 5-digit sequential number
    
    Returns:
        str: Unique asset number in format INT-00001
    """
    try:
        # Use select_for_update to prevent race conditions in concurrent requests
        with transaction.atomic():
            # Retrieve or create the tracking record
            tracking, created = AssetNumberTracking.objects.get_or_create(
                pk=1,  # Ensure we always use the same record
                defaults={'LastGeneratedNumber': 0, 'Prefix': 'INT-'}
            )

            # Increment the last generated number
            tracking.LastGeneratedNumber += 1
            
            # Format the number with leading zeros
            formatted_number = f"{tracking.LastGeneratedNumber:05d}"
            
            # Construct the full asset number
            asset_number = f"{tracking.Prefix}{formatted_number}"
            
            # Ensure the number is unique
            while Asset.objects.filter(AssetNumber=asset_number).exists():
                tracking.LastGeneratedNumberr += 1
                formatted_number = f"{tracking.LastGeneratedNumber:05d}"
                asset_number = f"{tracking.Prefix}{formatted_number}"
            
            # Update the tracking record
            tracking.LastGeneratedDate = timezone.now()
            tracking.save()
            
            return asset_number
    
    except Exception as e:
        # Log the full error details
        logger.error(f"Error generating asset number: {e}", exc_info=True)
        raise

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator

@method_decorator(csrf_exempt, name='dispatch')
class GenerateAssetNumberView(APIView):
    permission_classes = [AllowAny]
    
    def get(self, request):
        try:
            # Generate the asset number
            asset_number = generate_unique_asset_number()
            
            return Response({
                'assetNumber': asset_number
            }, status=status.HTTP_200_OK)
        
        except Exception as e:
            # Log the full error details
            import logging
            logger = logging.getLogger(__name__)
            logger.error(f"Error generating asset number: {e}", exc_info=True)
            
            return Response({
                'error': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

from django.shortcuts import render, redirect
from django.contrib import messages
from .models import Vendor, Asset, Image, Document, Maintenance, Calibration
from .forms import AddAssetForm
import datetime
from django.shortcuts import render, redirect
from django.contrib import messages
from .models import Vendor, Asset, Image, Document, Maintenance, Calibration
from .forms import AddAssetForm
import datetime
from django.shortcuts import render, redirect
from django.contrib import messages
from .forms import AddAssetForm
from .models import Asset, Category, Vendor, Maintenance, Calibration, Image, Document
from django.shortcuts import render, redirect
from django.contrib import messages
from django.db import transaction
from datetime import datetime
from .forms import AddAssetForm
from .models import Asset, Category, Vendor, Maintenance, Calibration, Image, Document
from django.shortcuts import render, redirect
from django.contrib import messages
from django.db import transaction
from datetime import datetime
from .forms import AddAssetForm
from .models import Asset, Category, Vendor, Maintenance, Calibration, Image, Document

def add_hardware_asset(request):
    # Check if user is logged in
    user_id = request.session.get('user_id')
    if not user_id:
        return redirect('login')  # Redirect if not logged in

    try:
        user = User.objects.get(UserId=user_id)
    except User.DoesNotExist:
        messages.error(request, "User not found. Please log in again.")
        return redirect('login')

    # Fetch vendors and their associated categories
    vendors = Vendor.objects.prefetch_related('asset_set').all()
    vendor_data = [
        {
            'VendorID': vendor.VendorId,
            'VendorName': vendor.VendorName,
            'BgswVendorId': vendor.BgswVendorId,
            'VendorContact': vendor.VendorContact,
            'categories_used': vendor.asset_set.values_list('Category', flat=True).distinct()
        }
        for vendor in vendors
    ]

    # Fetch all categories
    categories = Category.objects.all()

    # Initialize the form
    form = AddAssetForm()

    if request.method == 'POST':
        print("Method is POST")
        form = AddAssetForm(request.POST, request.FILES)
        print(f"Form data: {request.POST}")
        print(f"Files data: {request.FILES}")

        # Handle vendor-specific validation
        vendor_id = request.POST.get('vendorId')
        if vendor_id:
            try:
                vendor = Vendor.objects.get(VendorId=vendor_id)
                form.fields['vendorName'].required = False
                form.fields['vendorContact'].required = False
            except Vendor.DoesNotExist:
                messages.error(request, "Selected vendor not found.")
                return render(request, 'admin/add asset.html', {
                    'form': form,
                    'vendors': vendor_data,
                    'categories': categories,
                    'user': user
                })
        else:
            form.fields['vendorName'].required = True
            form.fields['vendorContact'].required = True

        if form.is_valid():
            print("Form is valid")
            print(f"Cleaned data: {form.cleaned_data}")

            try:
                with transaction.atomic():
                    # Handle image upload
                    image_instance = None
                    if form.cleaned_data['image']:
                        image_file = form.cleaned_data['image']
                        file_name = handle_file_upload(image_file, 'assets/images')
                        image_instance = Image.objects.create(ImagePath=file_name)

                    # Handle document upload
                    document_instance = None
                    if form.cleaned_data['documents']:
                        doc_file = form.cleaned_data['documents']
                        file_name = handle_file_upload(doc_file, 'assets/documents')
                        document_instance = Document.objects.create(DocumentPath=file_name)

                    # Handle vendor selection or creation
                    if vendor_id:
                        vendor = Vendor.objects.get(VendorId=vendor_id)
                    else:
                        vendor = Vendor.objects.create(
                            VendorName=form.cleaned_data['vendorName'],
                            VendorContact=form.cleaned_data['vendorContact'],
                            VendorNotes=form.cleaned_data['description']
                        )

                    # Handle maintenance creation
                    maintenance = Maintenance.objects.create(
                        LastMaintenanceDate=form.cleaned_data.get('lastMaintenanceDate') or datetime.now().date(),
                        MaintenanceInterval=form.cleaned_data.get('maintenanceInterval') or 12,
                        MaintenanceNotes=''
                    )

                    # Handle calibration creation
                    calibration_instance = None
                    if form.cleaned_data['requiresCalibration']:
                        calibration_instance = Calibration.objects.create(
                            LastCalibrationDate=form.cleaned_data.get('lastCalibrationDate') or datetime.now().date(),
                            CalibrationAuthority=form.cleaned_data['calibrationAuthority'],
                            CalibrationNotes=form.cleaned_data['calibrationNotes'],
                            CalibrationInterval=form.cleaned_data.get('calibrationInterval') or 12
                        )

                    # Create the asset record
                    asset = Asset.objects.create(
                        AssetBondType=form.cleaned_data['asset_bond_type'],
                        AssetName=form.cleaned_data['assetName'],
                        cid=form.cleaned_data['cid'],  # Link to the selected category via cid
                        AssetNumber=form.cleaned_data['assetNumber'],
                        BondNumber=form.cleaned_data['bondNumber'],
                        PurchaseOrder=form.cleaned_data['purchaseOrder'],
                        PurchaseRequisition=form.cleaned_data['purchaseRequisition'],
                        Capex=form.cleaned_data['capex'],
                        SerialNumber=form.cleaned_data['serialNumber'],
                        PartNumber=form.cleaned_data['partNumber'],
                        AssetType=form.cleaned_data['assetType'],
                        AssetStatus=form.cleaned_data['assetStatus'],
                        AssetModel=form.cleaned_data['assetModel'],
                        Warehouse=form.cleaned_data['warehouse'],
                        Location=form.cleaned_data['location'],
                        AssetProvider=form.cleaned_data['assetProvider'],
                        AssetClassification=form.cleaned_data['assetClassification'],
                        PurchaseDate=form.cleaned_data['purchaseDate'],
                        Cost=form.cleaned_data['cost'],
                        Warranty=form.cleaned_data['warranty'],
                        BondExpiryDate=form.cleaned_data['bondExpiryDate'],
                        Specification=form.cleaned_data['specification'],
                        RequiresCalibration=form.cleaned_data['requiresCalibration'],
                        VendorID=vendor,
                        ImageID=image_instance,
                        DocumentID=document_instance,
                        MaintenanceID=maintenance,
                        CalibrationID=calibration_instance
                    )

                    messages.success(request, 'Asset added successfully!')
                    return redirect('Asset Inventory')

            except Exception as e:
                print(f"Exception in Add_Asset: {str(e)}")
                messages.error(request, f"Error adding asset: {str(e)}")
        else:
            print("Form is invalid")
            print("Form errors:", form.errors)

    return render(request, 'admin/add_hardware_asset.html', {
        'form': form,
        'vendors': vendor_data,
        'categories': categories,
        'user': user
    })
from django.shortcuts import render

def add_asset_selection(request):
    return render(request, 'admin/add_asset.html')


def add_software_asset(request):
    """
    View to handle the addition of software assets.
    """
    user_id = request.session.get('user_id')
    if not user_id:
        return redirect('login')  # Redirect if not logged in

    # Fetch user details
    user = User.objects.get(UserId=user_id)

    if request.method == 'POST':
        form = SoftwareAssetForm(request.POST)
        if form.is_valid():
            asset = form.save(commit=False)
            asset.AssetType = 'Software'  # Ensure the asset type is set to Software
            asset.AssetBondType = 'Non Bonded'
            asset.save()
            return redirect('Asset Inventory')  # Redirect to a success page
    else:
        form = SoftwareAssetForm()

    return render(request, 'admin/add_software_asset.html', {'form': form,'user': user})
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .models import Category

@csrf_exempt
def create_category(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            category_name = data.get('name')

            if not category_name:
                return JsonResponse({'success': False, 'message': 'Category name is required.'})

            # Create the new category
            category = Category.objects.create(Name=category_name)

            return JsonResponse({
                'success': True,
                'category_id': category.CategoryID,
                'category_name': category.Name
            })
        except Exception as e:
            return JsonResponse({'success': False, 'message': str(e)})
    return JsonResponse({'success': False, 'message': 'Invalid request method.'})
from django.shortcuts import render, redirect
from django.contrib import messages
from .models import Vendor

from django.http import HttpResponse
from .models import Vendor

def add_vendor(request):
    if request.method == 'POST':
        # Retrieve data from the POST request
        vendor_name = request.POST.get('vendorName')
        vendor_bgsw_id = request.POST.get('vendorBgswId')
        vendor_contact = request.POST.get('vendorContact')
        vendor_notes = request.POST.get('vendorNotes')

        try:
            # Create and save the vendor object
            Vendor.objects.create(
                VendorName=vendor_name,
                BgswVendorId=vendor_bgsw_id,
                VendorContact=vendor_contact,
                VendorNotes=vendor_notes
            )
            # Return a success response
            return HttpResponse("Vendor added successfully!,Please reload the page to update the Vendor Table", status=200)
        except Exception as e:
            # Return an error response
            return HttpResponse(f"Error adding vendor: {str(e)}", status=500)
    else:
        # Render the form for GET requests
        return render(request, 'admin/add_vendor.html')
from django.http import JsonResponse
from django.views.decorators.http import require_GET
from .models import Vendor, Asset  # Adjust the import based on your project structure

@require_GET
def get_vendors(request):
    try:
        print("Fetching vendors and their associated categories...")  # Debugging statement

        # Fetch vendors and their associated categories
        vendors = Vendor.objects.prefetch_related('asset_set').all()
        print(f"Total vendors fetched: {vendors.count()}")  # Debugging statement

        vendor_data = []

        for vendor in vendors:
            print(f"Processing vendor: {vendor.VendorName}")  # Debugging statement

            # Get distinct categories used by this vendor's assets
            categories_used = list(vendor.asset_set.values_list('Category', flat=True).distinct())
            print(f"Categories used by vendor '{vendor.VendorName}': {categories_used}")  # Debugging statement

            vendor_data.append({
                'VendorID': vendor.VendorId,
                'VendorName': vendor.VendorName,
                'BgswVendorId': vendor.BgswVendorId,
                'VendorContact': vendor.VendorContact,
                'categories_used': categories_used
            })

        # Dynamically fetch all unique categories from the Asset model (if needed)
        all_categories = list(Asset.objects.values_list('Category', flat=True).distinct())
        print(f"All unique categories across all assets: {all_categories}")  # Debugging statement

        print("Preparing JSON response...")  # Debugging statement

        return JsonResponse({
            'vendors': vendor_data,
            'all_categories': all_categories  # Optional: Include all categories if needed
        }, safe=False)

    except Exception as e:
        print(f"An error occurred: {str(e)}")  # Debugging statement
        return JsonResponse({
            'error': str(e)
        }, status=500)
from django.shortcuts import render, redirect
from datetime import datetime
from app.models import User, Asset, Category  # Import required models
from django.shortcuts import render, redirect
from django.db import models
from datetime import datetime
from .models import Asset, User, Category, AssetRequest
def Asset_Inventory(request):
    user_id = request.session.get('user_id')
    if not user_id:
        return redirect('login')  # Redirect if not logged in
    
    # Fetch user details
    user = User.objects.get(UserId=user_id)
    
    # Update asset availability
    update_asset_availability()
    
    # Fetch all assets
    assets = Asset.objects.all()
    
    # Get assets created today
    today = datetime.now().date()
    today_assets = Asset.objects.filter(
        CreationDate__year=today.year,
        CreationDate__month=today.month,
        CreationDate__day=today.day
    )
    
    # Get current and future asset requests
    current_date = datetime.now().date()
    asset_requests = AssetRequest.objects.filter(
        Status__in=['Completed'],
        EndDate__gte=current_date
    ).select_related('UserId', 'AssetID')
    
    # Create a dictionary to store all requests for each asset
    asset_request_dict = {}
    for req in asset_requests:
        if req.AssetID_id not in asset_request_dict:
            asset_request_dict[req.AssetID_id] = []
        asset_request_dict[req.AssetID_id].append({
            'user_name': req.UserId.username,
            'status': req.Status,
            'start_date': req.StartDate,
            'end_date': req.EndDate
        })
    
    # Attach requests to assets
    for asset in assets:
        asset.requests = asset_request_dict.get(asset.AssetID, [])
    
    # Fetch distinct category names
    asset_categories = Asset.objects.values_list('Category', flat=True).distinct()
    
    # Fetch distinct asset types
    asset_types = Asset.objects.values_list('AssetType', flat=True).distinct()
    
    # Fetch all fields of the Asset model
    asset_fields = [field.name for field in Asset._meta.get_fields() if not field.is_relation]
    
    # Fetch related fields from CalibrationID, MaintenanceID, and VendorID
    calibration_fields = []
    maintenance_fields = []
    vendor_fields = []
    
    # Check if CalibrationID is a related model
    if hasattr(Asset, 'CalibrationID'):
        calibration_fields = [f"CalibrationID.{field.name}" for field in Asset.CalibrationID.field.related_model._meta.get_fields()]
    
    # Check if MaintenanceID is a related model
    if hasattr(Asset, 'MaintenanceID'):
        maintenance_fields = [f"MaintenanceID.{field.name}" for field in Asset.MaintenanceID.field.related_model._meta.get_fields()]
    
    # Check if VendorID is a related model
    if hasattr(Asset, 'VendorID'):
        vendor_fields = [f"VendorID.{field.name}" for field in Asset.VendorID.field.related_model._meta.get_fields()]
    
    # Combine all fields
    all_fields = asset_fields + calibration_fields + maintenance_fields + vendor_fields
    
    # Map fields to simplified labels
    FIELD_LABELS = {
        'AssetID': 'Asset ID',
        'AssetName': 'Asset Name',
        'Category': 'Category',
        'AssetNumber': 'Asset Number',
        'BondNumber': 'Bond Number',
        'PurchaseOrder': 'Purchase Order',
        'PurchaseRequisition' : 'Purchase Requisition',
        'Capex': 'capex',
        'SerialNumber': 'Serial Number',
        'PartNumber': 'Part Number',
        'AssetType': 'Asset Type',
        'AssetStatus': 'Asset Status',
        'Warehouse': 'Warehouse',
        'Location': 'Location',
        'AssetProvider': 'Asset Provider',
        'AssetClassification': 'Asset Classification',
        'PurchaseDate': 'Purchase Date',
        'Cost': 'Cost',
        'Warranty': 'Warranty',
        'BondExpiryDate': 'Bond Expiry Date',
        'Specification': 'Specification',
        'RequiresCalibration': 'Requires Calibration',
        'CalibrationID.LastCalibrationDate': 'Last Calibration Date',
        'CalibrationID.CalibrationAuthor': 'Calibration Author',
        'CalibrationID.CalibrationNotes': 'Calibration Notes',
        'CalibrationID.CalibrationInterval': 'Calibration Interval',
        'CalibrationID.NextCalibrationDate': 'Next Calibration Date',
        'CalibrationID.CalibrationAuthority':'CalibrationAuthority',
        'MaintenanceID.LastMaintenanceDate': 'Last Maintenance Date',
        'MaintenanceID.MaintenanceInterval': 'Maintenance Interval',
        'MaintenanceID.MaintenanceNotes': 'Maintenance Notes',
        'MaintenanceID.NextMaintenanceDate': 'Next Maintenance Date',
        'VendorID.VendorName': 'Vendor Name',
        'VendorID.BgswVendorId': 'Vendor ID',
        'VendorID.VendorContact': 'Vendor Contact',
        'VendorID.VendorNotes': 'Vendor Info',
    }
    
    # Create a list of tuples with field names and their simplified labels
    fields_with_labels = [(field, FIELD_LABELS.get(field, field)) for field in all_fields]
    
    categories = Category.objects.all()   
    # Pass data to the template
    return render(request, 'admin/AssetInventory.html', {
        'assets': assets,
        'today_assets': today_assets,
        'user': user,
        'today_date': today,
        'asset_categories': asset_categories,
        'categories': categories,
        'asset_types': asset_types,  # Pass asset types to the template
        'fields_with_labels': fields_with_labels
    })
from django.http import HttpResponse

def export_assets(request):
    print("Export assets view called")
    
    if request.method == 'POST':
        # Retrieve form data
        asset_types = request.POST.getlist('AssetType')  # Matches the HTML form
        fields = request.POST.getlist('fields')  # Adjusted for dynamic field names
        export_format = request.POST.get('export_format')
        
        print(f"Asset types selected: {asset_types}")
        print(f"Fields selected: {fields}")
        print(f"Export format selected: {export_format}")
        
        # Apply filters based on asset types
        assets = Asset.objects.all()
        if asset_types:
            assets = assets.filter(Category__in=asset_types)
        print(f"Filtered assets count: {assets.count()}")
        
        # Prepare data based on selected fields
        selected_fields = fields if fields else [
            'AssetID', 'AssetName', 'Category', 'AssetNumber','BondNumber','PurchaseOrder', 'PurchaseRequisition', 'Capex', 'SerialNumber',
            'PartNumber', 'AssetType', 'AssetStatus', 'Warehouse', 'Location',
            'AssetProvider', 'AssetClassification', 'PurchaseDate', 'Cost',
            'Warranty', 'BondExpiryDate', 'Specification', 'RequiresCalibration', 'VendorID.VendorName'
        ]
        print(f"Selected fields for export: {selected_fields}")
        
        # Export based on format
        if export_format == 'csv':
            return export_csv(assets, selected_fields)
        else:
            print("Invalid export format")
            return HttpResponse("Invalid export format", status=400)
from datetime import datetime
import csv
from django.http import HttpResponse

def export_csv(assets, fields):
    print("Export CSV called")
    
    # Generate a timestamped filename
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{timestamp}_assetinfo.csv"
    
    # Create the HTTP response with CSV content type
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = f'attachment; filename="{filename}"'
    
    # Write the CSV content
    writer = csv.writer(response)
    writer.writerow(fields)  # Write the header row
    
    for asset in assets:
        row = []
        for field in fields:
            try:
                # Handle related fields (e.g., VendorID.VendorName)
                if '.' in field:
                    related_field, sub_field = field.split('.', 1)
                    related_object = getattr(asset, related_field, None)
                    value = getattr(related_object, sub_field, 'N/A') if related_object else 'N/A'
                else:
                    value = getattr(asset, field, 'N/A')
                
                # Convert value to string for CSV compatibility
                row.append(str(value) if value is not None else 'N/A')
            except AttributeError as e:
                print(f"Error processing field '{field}' for asset {asset.AssetID}: {e}")
                row.append('N/A')
        
        writer.writerow(row)
        print(f"Written row: {row}")
    
    return response

def delete_Asset(request, AssetID):
    """Delete asset based on the asset id"""
    Asset.objects.filter(AssetID=AssetID).delete()
    return redirect(reverse('Asset Inventory'))

    
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.http import JsonResponse
from .models import Asset, Vendor, Maintenance, Calibration
from django.views.decorators.http import require_http_methods
from datetime import datetime
# views.py
from django.shortcuts import render, redirect, get_object_or_404
from django.http import JsonResponse, HttpResponseBadRequest # Consider removing JsonResponse if not used
from django.views.decorators.http import require_http_methods
from django.contrib import messages
from django.urls import reverse
from .models import Asset, Vendor, Maintenance, Calibration, Image, Document
import os
from django.conf import settings
from django.db import transaction
from django.utils import timezone # Make sure timezone is imported
from django.shortcuts import render, redirect, get_object_or_404
from django.urls import reverse
from django.contrib import messages
from django.utils import timezone
from django.conf import settings
import os
from .models import Asset, Vendor, Maintenance, Calibration, Image, Document, Category # Make sure Category is imported

@require_http_methods(["POST"])
@transaction.atomic
def update_asset(request, asset_id):
    asset = get_object_or_404(Asset, AssetID=asset_id)
    asset_type_at_load = asset.AssetType

    # Fetch categories for the category selection modal (needed if rendering the edit page again on error, though redirect is current pattern)
    categories = Category.objects.all()

    if request.method == 'POST': # Process form submission
        try:
            print(f"Updating Asset ID: {asset_id} (Type: {asset_type_at_load})")
            print(f"Request POST data: {request.POST}")
            print(f"Request FILES data: {request.FILES}")

            # --- Common Fields Update ---
            asset.AssetName = request.POST.get('assetName', asset.AssetName)
            purchase_date_str = request.POST.get('purchaseDate')
            asset.PurchaseDate = purchase_date_str if purchase_date_str else None
            cost_str = request.POST.get('cost')
            asset.Cost = cost_str if cost_str else None
            asset.AssetStatus = request.POST.get('assetStatus', asset.AssetStatus)
            bond_type = request.POST.get('bondType')
            if bond_type:
                asset.AssetBondType = bond_type
                print(f"Updated Bond Type to: {bond_type}")
                
            # # ✅ Update AssetNumber
            # asset_number = request.POST.get("assetNumber")
            # if asset_number:
            #     asset.AssetNumber = str(asset_number).split(".")[0]  # remove decimals like 12345.0
            #     print(f"Updated Asset Number to: {asset.AssetNumber}")
                
            # # --- Update Bond Number ---
            #     bond_number = request.POST.get('bondNumber')
            #     if bond_number:
            #         # Ensure BondNumber is saved as string (to avoid .0 decimals issue)
            #         asset.BondNumber = str(bond_number).split('.')[0]
            #         print(f"Updated Bond Number to: {asset.BondNumber}")
            
            def update_field_from_post(asset, post_data, field_name, post_key, numeric=False):
                """
                Update a model field from POST request safely.
                - asset: The Asset object
                - post_data: request.POST
                - field_name: The model field name to update
                - post_key: The POST key name (input name in form)
                - numeric: If True, strip decimals (e.g., '123.0' → '123')
                """
                value = post_data.get(post_key)
                if value:
                    value = str(value).strip()
                    if numeric:
                        value = value.split('.')[0]  # remove .0 decimals if Excel upload
                    setattr(asset, field_name, value)
                    print(f"Updated {field_name} to: {value}")
                    
            # Update fields with helper function
            update_field_from_post(asset, request.POST, 'AssetNumber', 'assetNumber', numeric=True)
            update_field_from_post(asset, request.POST, 'BondNumber', 'bondNumber', numeric=True)
            update_field_from_post(asset, request.POST, 'PurchaseOrder', 'purchaseOrder', numeric=True)
            update_field_from_post(asset, request.POST, 'PurchaseRequisition', 'purchaseRequisition', numeric=True)
            update_field_from_post(asset, request.POST, 'Capex', 'capex', numeric=True)

            # --- Category & Type Specific Updates ---
            if asset_type_at_load == 'Software':
                print("Processing SOFTWARE asset update...")
                asset.AssetType = 'Software'
                # For software, 'category' holds the license type string
                submitted_license_type = request.POST.get('category')
                # Validate against choices if necessary or just assign
                asset.Category = submitted_license_type if submitted_license_type else None
                asset.cid = None # Software doesn't use the Category FK link
                print(f"Set Category (License Type) to: {asset.Category}")

                # Update other software fields
                renew_date_str = request.POST.get('renewDate')
                asset.RenewDate = renew_date_str if renew_date_str else None
                asset.AssetProvider = request.POST.get('assetProvider', asset.AssetProvider)
                software_version = request.POST.get('SoftwareVersion')
                asset.SoftwareVersion = software_version if software_version else None

                # Nullify hardware-specific fields
                asset.SerialNumber = None
                asset.BondNumber = None
                asset.PurchaseOrder=None
                asset.PurchaseRequisition=None
                asset.Capex=None
                asset.PartNumber = None
                asset.Warranty = None
                asset.Warehouse = None
                asset.Location = None
                asset.RequiresCalibration = False
                asset.Specification = None
                asset.VendorID = None
                asset.MaintenanceID = None
                asset.CalibrationID = None
                # asset.ImageID = None # Optional: Decide if software has images/docs
                # asset.DocumentID = None

            else: # Hardware or other AssetTypes
                print("Processing HARDWARE/OTHER asset update...")
                asset.AssetType = 'Hardware' # Or handle other AssetTypes if needed
                # *** FIX: Handle Category ForeignKey (cid) for Hardware ***
                # Remove the direct assignment to asset.Category here
                # asset.Category = submitted_category if submitted_category else None # REMOVE THIS LINE

                submitted_cid_str = request.POST.get('cid') # *** GET 'cid' from the form ***
                if submitted_cid_str:
                    try:
                        category_obj = Category.objects.get(CategoryID=int(submitted_cid_str))
                        asset.cid = category_obj # *** ASSIGN Category object to ForeignKey ***
                        print(f"Set Category Foreign Key (cid) to ID: {category_obj.CategoryID} Name: {category_obj.Name}")
                    except (Category.DoesNotExist, ValueError, TypeError):
                        messages.warning(request, f"Invalid or non-existent Category ID submitted: '{submitted_cid_str}'. Category not updated.")
                        # Decide behavior: keep old category or clear it?
                        # asset.cid = asset.cid # Keep old (default)
                        # asset.cid = None # Clear if invalid submitted
                elif 'cid' in request.POST: # If 'cid' was submitted but empty (e.g., user cleared selection somehow)
                    asset.cid = None # Clear the foreign key link
                    print("Cleared Category Foreign Key (cid) association.")
                # The asset.save() method will now update asset.Category (CharField) based on asset.cid

                # --- Update other fields specific to Hardware ---
                asset.AssetModel = request.POST.get('AssetModel', asset.AssetModel) # Added AssetModel
                asset.BondNumber = request.POST.get('bondNumber', asset.BondNumber)
                asset.PurchaseOrder = request.POST.get('purchaseOrder', asset.PurchaseOrder)
                asset.PurchaseRequisition = request.POST.get('purchaseRequisition', asset.PurchaseRequisition)
                asset.Capex = request.POST.get('bondNumber', asset.Capex)
                asset.SerialNumber = request.POST.get('serialNumber', asset.SerialNumber)
                asset.PartNumber = request.POST.get('partNumber', asset.PartNumber)
                asset.Warehouse = request.POST.get('warehouse', asset.Warehouse)
                asset.Location = request.POST.get('location', asset.Location)
                warranty_str = request.POST.get('warranty')
                asset.Warranty = int(warranty_str) if warranty_str and warranty_str.isdigit() else None
                asset.Specification = request.POST.get('specification', asset.Specification)
                # RequiresCalibration would need its own form field if editable

                # Nullify software-specific fields
                asset.RenewDate = None # Corrected typo RnewDate -> RenewDate

                # --- Vendor Update (Hardware Only) ---
                vendor_id_str = request.POST.get('vendorID')
                if vendor_id_str:
                    try:
                        vendor = Vendor.objects.get(VendorId=int(vendor_id_str))
                        asset.VendorID = vendor
                        print(f"Updated Vendor to ID: {vendor.VendorId} Name: {vendor.VendorName}")
                    except (Vendor.DoesNotExist, ValueError, TypeError):
                        messages.warning(request, f"Invalid or non-existent Vendor ID: '{vendor_id_str}'. Vendor not updated.")
                elif 'vendorID' in request.POST:
                     asset.VendorID = None
                     print("Cleared Vendor association.")

                # --- Maintenance Update (Hardware Only) ---
                # (Your existing maintenance logic seems okay)
                last_maintenance_date_str = request.POST.get('lastMaintenanceDate')
                maintenance_interval_str = request.POST.get('maintenanceInterval')
                if 'lastMaintenanceDate' in request.POST or 'maintenanceInterval' in request.POST:
                    if last_maintenance_date_str or maintenance_interval_str:
                        maintenance, created = Maintenance.objects.get_or_create(pk=asset.MaintenanceID_id) if asset.MaintenanceID_id else (Maintenance(), True)
                        maintenance.LastMaintenanceDate = last_maintenance_date_str if last_maintenance_date_str else None
                        maintenance.MaintenanceInterval = int(maintenance_interval_str) if maintenance_interval_str and maintenance_interval_str.isdigit() else None
                        maintenance.save()
                        asset.MaintenanceID = maintenance
                        print(f"{'Created' if created else 'Updated'} Maintenance Info")
                    elif asset.MaintenanceID:
                        asset.MaintenanceID = None
                        print("Unlinked Maintenance Info")


                # --- Calibration Update (Hardware Only, if required) ---
                # (Your existing calibration logic seems okay, assuming RequiresCalibration is handled)
                if asset.RequiresCalibration:
                    if any(f in request.POST for f in ['calibrationAuthority', 'lastCalibrationDate', 'calibrationInterval', 'calibrationNotes']):
                        calibration_authority = request.POST.get('calibrationAuthority')
                        last_calibration_date_str = request.POST.get('lastCalibrationDate')
                        calibration_interval_str = request.POST.get('calibrationInterval')
                        calibration_notes = request.POST.get('calibrationNotes')

                        if any([calibration_authority, last_calibration_date_str, calibration_interval_str, calibration_notes]):
                            calibration, created = Calibration.objects.get_or_create(pk=asset.CalibrationID_id) if asset.CalibrationID_id else (Calibration(), True)
                            calibration.CalibrationAuthority = calibration_authority
                            calibration.LastCalibrationDate = last_calibration_date_str if last_calibration_date_str else None
                            calibration.CalibrationInterval = int(calibration_interval_str) if calibration_interval_str and calibration_interval_str.isdigit() else None
                            calibration.CalibrationNotes = calibration_notes
                            calibration.save()
                            asset.CalibrationID = calibration
                            print(f"{'Created' if created else 'Updated'} Calibration Info")
                        elif asset.CalibrationID:
                            asset.CalibrationID = None
                            print("Unlinked Calibration Info")
                elif asset.CalibrationID:
                    asset.CalibrationID = None
                    print("Unlinked Calibration Info as RequiresCalibration is False")


                # --- File Uploads (Hardware Only) ---
                # (Your existing file upload logic seems okay)
                if 'assetImage' in request.FILES:
                    print("Processing Image Upload...")
                    image_file = request.FILES['assetImage']
                    relative_file_path = os.path.join('assets/images/', f"{asset.AssetNumber or asset.AssetID}_{image_file.name}") # Use AssetID as fallback if number is missing
                    full_file_path = os.path.join(settings.MEDIA_ROOT, relative_file_path)
                    # (rest of image handling code...)
                    # Ensure you handle potential errors during file operations
                    try:
                        # Delete old file logic
                        if asset.ImageID and asset.ImageID.ImagePath:
                             old_full_path = os.path.join(settings.MEDIA_ROOT, asset.ImageID.ImagePath)
                             # Check existence and difference before deleting
                             if os.path.normpath(old_full_path) != os.path.normpath(full_file_path) and os.path.isfile(old_full_path):
                                os.remove(old_full_path)
                                print(f"Deleted old image: {old_full_path}")

                        image, created = Image.objects.get_or_create(pk=asset.ImageID_id) if asset.ImageID_id else (Image(), True)
                        os.makedirs(os.path.dirname(full_file_path), exist_ok=True)
                        with open(full_file_path, 'wb+') as destination:
                            for chunk in image_file.chunks():
                                destination.write(chunk)
                        print(f"Saved new image to: {full_file_path}")
                        image.ImagePath = relative_file_path
                        image.ImageName = image_file.name
                        image.save()
                        asset.ImageID = image
                    except (OSError, IOError) as e:
                        messages.error(request, f"Error handling image file: {e}")
                        print(f"Error handling image file {full_file_path}: {e}")


                if 'assetDocument' in request.FILES:
                    print("Processing Document Upload...")
                    doc_file = request.FILES['assetDocument']
                    relative_file_path = os.path.join('assets/documents/', f"{asset.AssetNumber or asset.AssetID}_{doc_file.name}")
                    full_file_path = os.path.join(settings.MEDIA_ROOT, relative_file_path)
                    # (rest of document handling code...)
                    try:
                        # Delete old file logic
                        if asset.DocumentID and asset.DocumentID.DocumentPath:
                             old_full_path = os.path.join(settings.MEDIA_ROOT, asset.DocumentID.DocumentPath)
                             if os.path.normpath(old_full_path) != os.path.normpath(full_file_path) and os.path.isfile(old_full_path):
                                os.remove(old_full_path)
                                print(f"Deleted old document: {old_full_path}")

                        document, created = Document.objects.get_or_create(pk=asset.DocumentID_id) if asset.DocumentID_id else (Document(), True)
                        os.makedirs(os.path.dirname(full_file_path), exist_ok=True)
                        with open(full_file_path, 'wb+') as destination:
                            for chunk in doc_file.chunks():
                                destination.write(chunk)
                        print(f"Saved new document to: {full_file_path}")
                        document.DocumentPath = relative_file_path
                        document.DocumentName = doc_file.name
                        document.UploadDate = timezone.now().date()
                        document.save()
                        asset.DocumentID = document
                    except (OSError, IOError) as e:
                        messages.error(request, f"Error handling document file: {e}")
                        print(f"Error handling document file {full_file_path}: {e}")

            # --- Save the asset ---
            asset.save() # Save all changes. The model's save() method updates asset.Category name based on asset.cid for hardware.
            messages.success(request, f'Asset "{asset.AssetName}" updated successfully.')
            print(f"Successfully updated Asset ID: {asset_id}")
            return redirect(reverse('Asset Inventory')) # Redirect after successful POST

        except Exception as e:
            import traceback
            print("------------------- ERROR UPDATING ASSET -------------------")
            print(f"Asset ID: {asset_id}")
            print(f"Exception Type: {type(e)}")
            print(f"Exception Args: {e.args}")
            traceback.print_exc()
            print("----------------------------------------------------------")
            messages.error(request, f'An unexpected error occurred while updating asset: {str(e)}')
            # Redirect back even on error for standard form submissions
            return redirect(reverse('Asset Inventory')) # Or render the edit page again with errors

    else: # GET request - Show the form
        # This part is usually handled by a separate edit_asset view or function
        # but if you need to render the template from here on GET:
        context = {
            'asset': asset,
            'categories': categories # Pass categories for the modal
            # Add any other context needed for the edit template
        }
        # return render(request, 'your_template_for_editing.html', context)
        # Since you're likely reaching here only via POST in this structure,
        # a redirect on GET might make more sense, or this else block might not be hit.
        # If your edit modals are loaded on the inventory page itself, this GET block isn't used.
        pass # Or handle GET request appropriately if needed

    # Fallback redirect if POST logic somehow doesn't redirect (e.g., error before redirect)
    return redirect(reverse('Asset Inventory'))


from django.shortcuts import get_object_or_404
from django.http import JsonResponse
from django.views.decorators.http import require_POST
from django.views.decorators.csrf import csrf_exempt
from .models import User, Vendor, Asset, Calibration

@csrf_exempt
@require_POST
from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from django.core.mail import send_mail
from django.conf import settings
from .models import Asset

def send_email_notification(request):
    """
    Send email notifications to users, vendors, or calibration authorities
    related to an asset using Django's email backend.
    """
    try:
        recipient_type = request.POST.get('recipient_type')
        asset_id = request.POST.get('asset_id')
        email_content = request.POST.get('email_content')
        subject = request.POST.get('subject', 'Asset Management Notification')

        print(f"==== Email Request ====")
        print(f"Recipient Type: {recipient_type}")
        print(f"Asset ID: {asset_id}")
        print(f"Subject: {subject}")

        asset = get_object_or_404(Asset, AssetID=asset_id)
        print(f"Found Asset: {asset.AssetName} (ID: {asset.AssetID})")

        recipients = []

        # TODO: Replace this with your existing recipient collection logic
        # Example:
        # if recipient_type == "user" and asset.UserId:
        #     recipients.append(asset.UserId.email)
        # elif recipient_type == "vendor" and asset.VendorID:
        #     recipients.append(asset.VendorID.VendorContact)
        # elif recipient_type == "calibration" and asset.CalibrationID:
        #     recipients.append(asset.CalibrationID.CalibrationAuthorityEmail)

        print(f"Total recipients found: {len(recipients)}")
        print(f"Recipients list: {recipients}")

        if not recipients:
            print(f"No {recipient_type} email found for this asset - returning error")
            return JsonResponse({
                'success': False,
                'message': f'No {recipient_type} email found for this asset'
            })

        # === Django Email Sending ===
        try:
            recipient_list = list(set(recipients))  # Remove duplicates
            send_mail(
                subject=subject,
                message=email_content,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=recipient_list,
                fail_silently=False,
            )
            print("Email sent successfully via Django!")

            return JsonResponse({
                'success': True,
                'message': f'Email sent successfully to {len(recipient_list)} {recipient_type}(s)'
            })

        except Exception as e:
            print(f"ERROR sending email via Django: {str(e)}")
            return JsonResponse({
                'success': False,
                'message': f'Error sending email: {str(e)}'
            })

    except Exception as e:
        print(f"ERROR in send_email_notification: {str(e)}")
        import traceback
        traceback.print_exc()

        return JsonResponse({
            'success': False,
            'message': f'Error: {str(e)}'
        })


def get_email_template(request):
    """Return appropriate email template based on recipient type"""
    recipient_type = request.GET.get('type')
    asset_id = request.GET.get('asset_id')

    asset = get_object_or_404(Asset, AssetID=asset_id)

    templates = {
        'user': f"""Dear User,

This is regarding asset {asset.AssetName} (Asset Number: {asset.AssetNumber}).

[Insert your message here]

Thank you,
Asset Management Team
""",
        'vendor': f"""Dear Vendor,

This is regarding asset {asset.AssetName} (Model: {asset.AssetModel}, Serial Number: {asset.SerialNumber}).

[Insert your vendor-specific message here]

Regards,
Asset Management Team
""",
        'calibration': f"""Dear Calibration Authority,

This is regarding the calibration of asset {asset.AssetName} (Asset Number: {asset.AssetNumber}).

Last Calibration Date: {asset.CalibrationID.LastCalibrationDate if asset.CalibrationID else 'N/A'}
Calibration Certificate: {asset.CalibrationID.certificate if asset.CalibrationID else 'N/A'}

[Insert your calibration-specific message here]

Thank you,
Asset Management Team
"""
    }

    return JsonResponse({
        'success': True,
        'template': templates.get(
            recipient_type,
            "Dear Recipient,\n\n[Your message here]\n\nRegards,\nAsset Management Team"
        )
    })

def download_document(request, document_path):
    # Construct the full file path
    file_path = os.path.join(settings.MEDIA_ROOT, document_path)
    
    if os.path.exists(file_path):
        with open(file_path, 'rb') as file:
            response = HttpResponse(file.read(), content_type='application/octet-stream')
            response['Content-Disposition'] = f'attachment; filename={os.path.basename(file_path)}'
            return response
    else:
        raise Http404("File not found.")

import logging
from datetime import date, timedelta
from django.shortcuts import render, redirect
from django.contrib import messages



logger = logging.getLogger(__name__)

# Helper function to generate alert IDs
def get_alert_ids(today):
    """
    Generates a set of unique identifiers for all currently active alerts.
    These IDs are used for tracking viewed alerts in the session.
    """
    alert_ids = set()
    warning_days = 30  # Consistent warning threshold

    # --- Pending Asset Requests ---
    requested_assets = AssetRequest.objects.filter(
        Status='Pending',
        EndDate__gte=today
    )
    for req in requested_assets:
        alert_ids.add(f"request_{req.pk}")

    # --- Maintenance Alerts ---
    maintenance_assets_qs = Asset.objects.filter(
        MaintenanceID__isnull=False,
        MaintenanceID__LastMaintenanceDate__isnull=False
    ).select_related('MaintenanceID')
    for asset in maintenance_assets_qs:
        try:
            interval_days = asset.MaintenanceID.MaintenanceInterval * 30
            next_maintenance_date = asset.MaintenanceID.LastMaintenanceDate + timedelta(days=interval_days)
            if today <= next_maintenance_date <= today + timedelta(days=warning_days):
                alert_ids.add(f"maint_{asset.pk}")
        except AttributeError:
            continue  # Skip if maintenance data is incomplete

    # --- Bond Expiry Alerts ---
    bond_alerts_qs = Asset.objects.filter(
        BondExpiryDate__isnull=False,
        BondExpiryDate__gte=today,
        BondExpiryDate__lte=today + timedelta(days=warning_days)
    )
    for asset in bond_alerts_qs:
        alert_ids.add(f"bond_{asset.pk}")

    # --- Software Renewal Alerts ---
    software_renewal_qs = Asset.objects.filter(
        AssetType='Software',
        RenewDate__isnull=False,
        RenewDate__gte=today,
        RenewDate__lte=today + timedelta(days=warning_days)
    )
    for asset in software_renewal_qs:
        if hasattr(asset, 'RenewDate') and isinstance(asset.RenewDate, date):
            alert_ids.add(f"sw_{asset.pk}")

    # --- Warranty Alerts ---
    warranty_assets_qs = Asset.objects.filter(
        Warranty__isnull=False,
        PurchaseDate__isnull=False
    )
    # --- Return Request Alerts ---
    return_requests = RequestStage.objects.filter(
        StageName='ReturnRequest',
        StageDate__date=today
    )
    for req_stage in return_requests:
        alert_ids.add(f"return_request_{req_stage.RequestId_id}")
    for asset in warranty_assets_qs:
        try:
            warranty_duration_days = int(asset.Warranty) * 365
            warranty_expiry_date = asset.PurchaseDate + timedelta(days=warranty_duration_days)
            if today <= warranty_expiry_date <= today + timedelta(days=warning_days):
                alert_ids.add(f"warr_{asset.pk}")
        except (ValueError, TypeError):
            continue  # Skip if warranty calculation fails

    logger.debug(f"Generated current alert IDs: {alert_ids}")
    return alert_ids

# Alerts View with Proper Session Tracking
def Alerts(request):
    user_id = request.session.get('user_id')
    if not user_id:
        return redirect('login')
    try:
        user = User.objects.get(UserId=user_id)
    except User.DoesNotExist:
        messages.error(request, "User not found. Please log in again.")
        return redirect('login')

    today = date.today()
    warning_days = 30

    # --- Handle marking all alerts as read ---
    if 'mark_all_read' in request.GET:
        request.session['viewed_alert_ids'] = list(get_alert_ids(today))
        return redirect('alerts')  # Redirect to remove GET parameter

    # --- Session Tracking for New Alerts ---
    # 1. Get viewed alert IDs from session
    viewed_alert_ids = set(request.session.get('viewed_alert_ids', []))
    logger.debug(f"Viewed alert IDs from session: {viewed_alert_ids}")

    # 2. Get all *currently* active alert IDs
    current_alert_ids = get_alert_ids(today)  # Use the helper function

    # 3. Determine which alerts are new
    new_alert_ids = current_alert_ids - viewed_alert_ids
    logger.debug(f"Newly detected alert IDs: {new_alert_ids}")

    # --- End Session Tracking Logic ---
    all_alerts = []

    # --- 1. Pending Asset Requests (Priority 3) ---
    requested_assets = AssetRequest.objects.filter(
        Status='Pending',
        EndDate__gte=today
    ).select_related('AssetID', 'UserId').order_by('-RequestedAt')
    for req in requested_assets:
        alert_id = f"request_{req.pk}"
        all_alerts.append({
            'id': alert_id,
            'type': 'request',
            'priority': 3,
            'days_left': None,
            'data': req,
            'sort_date': req.RequestedAt.date(),
            'is_new': alert_id in new_alert_ids  # Mark as new if ID is in the new set
        })

    # --- 2. Maintenance Alerts (Priority 1 - High) ---
    maintenance_assets_qs = Asset.objects.filter(
        MaintenanceID__isnull=False,
        MaintenanceID__LastMaintenanceDate__isnull=False
    ).select_related('VendorID', 'MaintenanceID')
    for asset in maintenance_assets_qs:
        try:
            interval_days = asset.MaintenanceID.MaintenanceInterval * 30
            next_maintenance_date = asset.MaintenanceID.LastMaintenanceDate + timedelta(days=interval_days)
            if today <= next_maintenance_date <= today + timedelta(days=warning_days):
                days_left = (next_maintenance_date - today).days
                asset.next_maintenance_date_calculated = next_maintenance_date
                alert_id = f"maint_{asset.pk}"
                all_alerts.append({
                    'id': alert_id,
                    'type': 'high',  # Corresponds to Maintenance Due
                    'priority': 1,
                    'days_left': days_left,
                    'data': asset,
                    'sort_date': next_maintenance_date,
                    'is_new': alert_id in new_alert_ids
                })
        except AttributeError:
            logger.warning(f"Could not process maintenance for Asset {asset.pk}. Check MaintenanceID fields.")
            continue

    # --- 3. Bond Expiry Alerts (Priority 2 - Medium) ---
    bond_alerts_qs = Asset.objects.filter(
        BondExpiryDate__isnull=False,
        BondExpiryDate__gte=today,
        BondExpiryDate__lte=today + timedelta(days=warning_days)
    ).select_related('VendorID')
    for asset in bond_alerts_qs:
        days_left = (asset.BondExpiryDate - today).days
        alert_id = f"bond_{asset.pk}"
        all_alerts.append({
            'id': alert_id,
            'type': 'medium',  # Corresponds to Bond Expiry
            'priority': 2,
            'days_left': days_left,
            'data': asset,
            'sort_date': asset.BondExpiryDate,
            'is_new': alert_id in new_alert_ids
        })

    # --- 4. Software Renewal Alerts (Priority 2 - Medium/Software) ---
    software_renewal_qs = Asset.objects.filter(
        AssetType='Software',
        RenewDate__isnull=False,
        RenewDate__gte=today,
        RenewDate__lte=today + timedelta(days=warning_days)
    ).select_related('VendorID')
    for asset in software_renewal_qs:
        if hasattr(asset, 'RenewDate') and isinstance(asset.RenewDate, date):
            days_left = (asset.RenewDate - today).days
            alert_id = f"sw_{asset.pk}"
            all_alerts.append({
                'id': alert_id,
                'type': 'software',  # Specific type for filtering
                'priority': 2,  # Can share priority with bond or have its own
                'days_left': days_left,
                'data': asset,
                'sort_date': asset.RenewDate,
                'is_new': alert_id in new_alert_ids
            })
        else:
            logger.warning(f"Could not process software renewal for Asset {asset.pk}. Check RenewDate field.")

    # --- 5. Warranty Alerts (Priority 4 - Low) ---
    warranty_assets_qs = Asset.objects.filter(
        Warranty__isnull=False,
        PurchaseDate__isnull=False
    ).select_related('VendorID')
    for asset in warranty_assets_qs:
        try:
            warranty_duration_days = int(asset.Warranty) * 365
            warranty_expiry_date = asset.PurchaseDate + timedelta(days=warranty_duration_days)
            if today <= warranty_expiry_date <= today + timedelta(days=warning_days):
                days_left = (warranty_expiry_date - today).days
                asset.warranty_expiry_date_calculated = warranty_expiry_date
                alert_id = f"warr_{asset.pk}"
                all_alerts.append({
                    'id': alert_id,
                    'type': 'low',  # Corresponds to Warranty Expiry
                    'priority': 4,
                    'days_left': days_left,
                    'data': asset,
                    'sort_date': warranty_expiry_date,
                    'is_new': alert_id in new_alert_ids
                })
        except (ValueError, TypeError, AttributeError) as e:
            logger.warning(f"Could not calculate warranty for Asset {asset.pk}: {e}. Check Warranty and PurchaseDate fields.")
            continue
    # --- 6. Return Request Alerts (Priority 3 - Similar to Other Requests) ---
    return_requests = RequestStage.objects.filter(
        StageName='ReturnRequest',
        StageDate__date=today
    ).select_related('RequestId', 'StageBy').order_by('-StageDate')

    for req_stage in return_requests:
        alert_id = f"return_request_{req_stage.RequestId_id}"
        all_alerts.append({
            'id': alert_id,
            'type': 'return_request',  # New alert type
            'priority': 3,             # Same as asset requests
            'days_left': None,
            'data': req_stage,
            'sort_date': req_stage.StageDate.date(),
            'is_new': alert_id in new_alert_ids
        })

    # --- Sort all alerts ---
    all_alerts.sort(key=lambda x: (x['priority'], x.get('sort_date') or date.max))

    # --- Update Session ---
    # Add current alert IDs to the viewed set instead of replacing
    viewed_alert_ids.update(current_alert_ids)

    # Update the session with the expanded set of viewed alerts
    request.session['viewed_alert_ids'] = list(viewed_alert_ids)
    request.session.modified = True  # Explicitly mark the session as modified

    # Optional: Prevent the viewed_alert_ids list from growing too large
    if len(request.session['viewed_alert_ids']) > 1000:  # Arbitrary limit
        request.session['viewed_alert_ids'] = request.session['viewed_alert_ids'][-500:]

    logger.debug(f"Updated viewed alert IDs in session: {request.session['viewed_alert_ids']}")
    # --- End Update Session ---

    # Calculate alert counts for UI display
    new_request_alerts = len([a for a in all_alerts if a['type'] == 'request' and a['is_new']])
    new_other_alerts = len([a for a in all_alerts if a['type'] != 'request' and a['is_new']])

    context = {
        'alerts': all_alerts,
        'user': user,
        'new_request_alerts': new_request_alerts,
        'new_other_alerts': new_other_alerts,
        'has_new_alerts': bool(new_alert_ids),
    }

    return render(request, 'admin/alerts.html', context)

from django.views.decorators.http import require_POST
from django.shortcuts import get_object_or_404, redirect
from django.views.decorators.http import require_POST
from .models import AssetRequest, Asset


from celery import shared_task
from django.utils.timezone import now
from .models import AssetRequest, Asset

def update_asset_availability():
    today = now().date()

    # Set assets to "In Use" if start date has arrived
    requests_to_start = AssetRequest.objects.filter(StartDate=today, Status="Completed")
    for request in requests_to_start:
        asset = request.AssetID
        asset.AssetAvailability = "In Use"
        asset.save()
      
    # Set assets to "Available" if end date has passed
    requests_to_end = AssetRequest.objects.filter(EndDate__lt=today, Status="Surrendered")
    for request in requests_to_end:
        asset = request.AssetID
        asset.AssetAvailability = "Available"
        asset.save()

from django.shortcuts import render, redirect
from datetime import date
from app.models import User, Asset, Category  # Import required models

def MaintenancePage(request):
    user_id = request.session.get('user_id')
    if not user_id:
        return redirect('login')  # Redirect if not logged in

    # Fetch user details
    user = User.objects.get(UserId=user_id)
    
    assets = Asset.objects.filter(AssetType='Hardware', MaintenanceID__isnull=False)


    
    # Add dynamic status based on maintenance dates
    for asset in assets:
        if asset.MaintenanceID.NextMaintenanceDate < date.today():
            asset.dynamic_status = "Overdue"
        else:
            asset.dynamic_status = "Upcoming"

    # Fetch distinct category names
    asset_categories =  Asset.objects.filter(AssetType='Hardware').values_list('Category', flat=True).distinct()

    # Pass data to the template
    return render(request, 'admin/Maintenance.html', {
        'assets': assets,
        'user': user,
        'asset_categories': asset_categories  # Pass distinct categories to the template
    })



 
 
# views.py
from django.shortcuts import render, redirect
from django.db.models import Count, Avg, Q
from django.db.models.functions import ExtractMonth
from datetime import datetime, timedelta
from .models import Asset, User
from django.utils import timezone
 
from django.shortcuts import render, redirect
from .models import Asset  # Import your Asset model

from django.http import JsonResponse

from django.shortcuts import render, redirect
from django.http import JsonResponse
from .models import Asset, User

from django.db.models import Sum
def Reports(request):
    user_id = request.session.get('user_id')
    if not user_id:
        return redirect('login')
    
    user = User.objects.get(UserId=user_id)
    assets = Asset.objects.all()
    categories = Asset.objects.values_list('Category', flat=True).distinct()
    
  
    # Get detailed cost breakdown
    cost_breakdown = (
        Asset.objects.values('Category', 'AssetProvider', 'AssetClassification')
        .annotate(total_cost=Sum('Cost'))
        .order_by('Category', 'AssetProvider', 'AssetClassification')
    )
    
    context = {
        "user": user,
        "assets": assets,
        "categories": categories,
        "cost_breakdown": cost_breakdown,
    }
    return render(request, 'admin/reports.html', context)


def get_filtered_assets(request):
    category = request.GET.get('category', None)
    
    if category:
        assets = Asset.objects.filter(Category=category)
    else:
        assets = Asset.objects.all()
    
    asset_data = [
        {
            "AssetName": asset.AssetName,
            "Cost": float(asset.Cost),
            "idle_days": asset.idle_days,
        }
        for asset in assets
    ]
    
    return JsonResponse(asset_data, safe=False)
def get_cost_data(request):
    category = request.GET.get('category')
    
    # Base queryset
    queryset = Asset.objects.all()
    
    # Apply category filter if provided
    if category:
        queryset = queryset.filter(Category=category)
    
    # Calculate costs by AssetProvider
    csi_borrowed_cost = queryset.filter(AssetProvider='CSI-Borrowed').aggregate(total=Sum('Cost'))['total'] or 0
    csi_purchased_cost = queryset.filter(AssetProvider='CSI-Purchased').aggregate(total=Sum('Cost'))['total'] or 0
    bgsw_cost = queryset.filter(AssetProvider='BGSW').aggregate(total=Sum('Cost'))['total'] or 0
    
    # Calculate costs by AssetClassification
    consumables_cost = queryset.filter(AssetClassification='Consumables').aggregate(total=Sum('Cost'))['total'] or 0
    non_consumables_cost = queryset.filter(AssetClassification='Non Consumables').aggregate(total=Sum('Cost'))['total'] or 0
    
    # Calculate total CSI cost (borrowed + purchased)
    total_csi_cost = float(csi_borrowed_cost) + float(csi_purchased_cost)
    
    # Calculate total cost based on category filter
    total_cost = queryset.aggregate(total=Sum('Cost'))['total'] or 0
    
    return JsonResponse({
        'csi_borrowed_cost': float(csi_borrowed_cost),
        'csi_purchased_cost': float(csi_purchased_cost),
        'total_csi_cost': total_csi_cost,
        'bgsw_cost': float(bgsw_cost),
        'consumables_cost': float(consumables_cost),
        'non_consumables_cost': float(non_consumables_cost),
        'total_cost': float(total_cost)  # New total cost added
    })
    
from django.http import HttpResponse
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib.utils import ImageReader
from io import BytesIO
from datetime import datetime
from .models import Asset, AssetRequest

def download_asset_data_pdf(request):
    # Fetch the logged-in user
    user_id = request.session.get('user_id')
    if not user_id:
        return HttpResponse("User not logged in.", status=401)
    user = User.objects.get(UserId=user_id)

    # Fetch all assets from the database
    assets = Asset.objects.all()

    # Prepare asset data with the most recent RequestedAt date
    asset_data = []
    for asset in assets:
        
      asset_data.append({
    "AssetID": asset.AssetID,
    "AssetNumber": asset.AssetNumber or "NA",
    "BondNumber": asset.BondNumber or "NA",
    "PurchaseOrder": asset.PurchaseOrder or "NA",
    "PurchaseRequisition": asset.PurchaseRequisition or "NA",
    "Capex": asset.Capex or "NA",
    "AssetModel": asset.AssetModel or "NA",
    "SerialNumber": asset.SerialNumber or "NA",
    "PartNumber": asset.PartNumber or "NA",
    "AssetName": asset.AssetName or "NA",
    "Category": asset.Category or "NA",
    "AssetStatus": asset.AssetStatus or "NA",
})

     # Create a file-like buffer to receive PDF data
    buffer = BytesIO()

    # Create the PDF object, using the buffer as its "file"
    p = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter  # Get page dimensions

    # Add company name and logo (optional)
    company_name = "BOSCH"
    p.setFont("Helvetica-Bold", 18)
    p.drawString(50, height - 50, company_name)

    # Add user details and download timestamp
    p.setFont("Helvetica", 12)
    p.drawString(50, height - 80, f"Downloaded by: {user.username} ({user.email})")
    p.drawString(50, height - 100, f"Date and Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # Add a title to the PDF
    p.setFont("Helvetica-Bold", 16)
    p.drawString(50, height - 130, "Asset Data Report")

    # Add table headers
    # Add table headers
    p.setFont("Helvetica-Bold", 10)
    p.drawString(50, height - 160, "Asset ID")
    p.drawString(100, height - 160, "Asset Number")
    p.drawString(170, height - 160, "Asset Model")  # Added Asset Model
    p.drawString(250, height - 160, "Serial Number")
    p.drawString(330, height - 160, "Part Number")
    p.drawString(410, height - 160, "Name")
    p.drawString(480, height - 160, "Category")
    p.drawString(550, height - 160, "Status")
 
    # Draw a line under the headers
    p.line(50, height - 165, 600, height - 165)
 
    # Add asset data rows
    y_position = height - 180
    p.setFont("Helvetica", 9)
    for asset in asset_data:
        p.drawString(50, y_position, str(asset["AssetID"]))
        p.drawString(100, y_position, asset["AssetNumber"])
        p.drawString(170, y_position, asset["AssetModel"])  # Added Asset Model
        p.drawString(250, y_position, asset["SerialNumber"])
        p.drawString(330, y_position, asset["PartNumber"])
        p.drawString(410, y_position, asset["AssetName"])
        p.drawString(480, y_position, asset["Category"])
        p.drawString(550, y_position, asset["AssetStatus"])
        y_position -= 18  # Move down for the next row

    # Save the PDF
    p.showPage()
    p.save()

    # FileResponse sets the Content-Disposition header so that browsers present the option to save the file.
    buffer.seek(0)
    response = HttpResponse(buffer, content_type='application/pdf')
    response['Content-Disposition'] = 'attachment; filename="asset_data_report.pdf"'
    return response
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

from django.http import HttpResponse
from django.shortcuts import redirect
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.platypus import Image as ReportImage
from reportlab.lib.units import inch
from io import BytesIO
from datetime import datetime

def download_idle_report(request):
    # Check user authentication
    user_id = request.session.get('user_id')
    if not user_id:
        return redirect('login')
    
    # Get category from the request
    category = request.GET.get('category', '')
    
    # Filter assets based on category
    if category and category != 'all':
        assets = Asset.objects.filter(Category=category)
    else:
        assets = Asset.objects.all()
    
    # Create response object with PDF mime type
    filename = f"idle_report_{category if category else 'all'}_{datetime.now().strftime('%Y%m%d')}.pdf"
    response = HttpResponse(content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename="{filename}"'
    
    # Create the PDF object using ReportLab
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=72, leftMargin=72, topMargin=72, bottomMargin=72)
    
    # Container for PDF elements
    elements = []
    
    # Add title
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        spaceAfter=30
    )
    elements.append(Paragraph("Asset Idle Analysis Report", title_style))
    
    # Add metadata
    metadata_style = ParagraphStyle(
        'Metadata',
        parent=styles['Normal'],
        fontSize=12,
        spaceAfter=12
    )
    elements.append(Paragraph(f"Category: {category if category else 'All Categories'}", metadata_style))
    elements.append(Paragraph(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", metadata_style))
    elements.append(Spacer(1, 20))
    
    # Create chart only if there are assets
    if assets.exists():
        # Get data for chart
        asset_names = [asset.AssetName for asset in assets]
        idle_days = [asset.idle_days for asset in assets]
        
        # Create a single figure for the bar chart
        fig, ax = plt.subplots(figsize=(10, 6))
        bars = ax.bar(range(len(asset_names)), idle_days, color='#1e40af')
        
        # Customize chart
        ax.set_xticks(range(len(asset_names)))
        ax.set_xticklabels(asset_names, rotation=45, ha='right')
        ax.set_ylabel('Idle Days')
        ax.set_title(f'Asset Idle Days Analysis - {category if category else "All Categories"}')
        
        # Adjust layout
        plt.tight_layout()
        
        # Save chart to buffer
        chart_buffer = BytesIO()
        fig.savefig(chart_buffer, format='png', bbox_inches='tight', dpi=300)
        chart_buffer.seek(0)
        plt.close(fig)
        
        # Add chart to PDF
        chart_image = ReportImage(chart_buffer, width=6*inch, height=4*inch)
        elements.append(chart_image)
        elements.append(Spacer(1, 20))
    
    # Create table data
    table_data = [['Asset Name', 'Cost (Rs)', 'Idle Days']]
    for asset in assets:
        table_data.append([
            asset.AssetName,
            f"{float(asset.Cost):,.2f}",
            str(asset.idle_days)
        ])
    
    # Create table
    table = Table(table_data)
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e40af')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 12),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 1), (-1, -1), 10),
        ('ALIGN', (1, 1), (1, -1), 'RIGHT'),
        ('ALIGN', (2, 1), (2, -1), 'CENTER'),
    ]))
    elements.append(table)
    elements.append(Spacer(1, 20))
    
    # Calculate summary statistics
    total_assets = len(assets)

    if total_assets > 0:
        # Total idle days
        total_idle_days = sum(asset.idle_days for asset in assets)
        
        # Average idle days
        avg_idle_days = total_idle_days / total_assets
        
        # Total cost of all assets
        total_cost = sum(float(asset.Cost) for asset in assets)
        
        # Find the maximum and minimum idle days
        max_idle_days = max(asset.idle_days for asset in assets)
        min_idle_days = min(asset.idle_days for asset in assets)
        
        # Collect all assets with the highest idle days
        highest_idle_assets = [
            {"name": asset.AssetName, "idle_days": asset.idle_days, "cost": float(asset.Cost)}
            for asset in assets if asset.idle_days == max_idle_days
        ]
        
        # Collect all assets with the lowest idle days
        lowest_idle_assets = [
            {"name": asset.AssetName, "idle_days": asset.idle_days, "cost": float(asset.Cost)}
            for asset in assets if asset.idle_days == min_idle_days
        ]
    else:
        # Handle the case where there are no assets
        total_idle_days = 0
        avg_idle_days = 0
        total_cost = 0
        highest_idle_assets = []
        lowest_idle_assets = []
    
    # Add summary statistics
    summary_style = ParagraphStyle(
        'Summary',
        parent=styles['Normal'],
        fontSize=12,
        spaceAfter=12
    )

    elements.append(Paragraph("Summary Statistics:", styles['Heading2']))
    elements.append(Paragraph(f"Total Assets: {total_assets}", summary_style))
    elements.append(Paragraph(f"Total Idle Days: {total_idle_days}", summary_style))
    elements.append(Paragraph(f"Average Idle Days: {avg_idle_days:.2f}", summary_style))
    elements.append(Paragraph(f"Total Asset Cost: Rs{total_cost:,.2f}", summary_style))

    # Add highest idle days details
    elements.append(Paragraph(f"Highest Idle Days: {max_idle_days}", summary_style))
    for asset in highest_idle_assets:
        elements.append(Paragraph(f"- {asset['name']} (Cost: Rs{asset['cost']:,.2f})", summary_style))

    # Add lowest idle days details
    elements.append(Paragraph(f"Lowest Idle Days: {min_idle_days}", summary_style))
    for asset in lowest_idle_assets:
        elements.append(Paragraph(f"- {asset['name']} (Cost: Rs{asset['cost']:,.2f})", summary_style))
    
    # Build PDF
    doc.build(elements)
    pdf = buffer.getvalue()
    buffer.close()
    
    response.write(pdf)
    return response
def download_cost_analysis_pdf(request):
    # Fetch the category filter from the request
    category = request.GET.get('category', None)

    # Call the get_cost_data function to fetch dynamic cost data
    cost_data = get_cost_data(request)
    cost_data = cost_data.content.decode('utf-8')
    cost_data = json.loads(cost_data)

    # Extract updated cost data
    csi_borrowed_cost = cost_data['csi_borrowed_cost']
    csi_purchased_cost = cost_data['csi_purchased_cost']
    total_csi_cost = cost_data['total_csi_cost']
    bgsw_cost = cost_data['bgsw_cost']
    consumables_cost = cost_data['consumables_cost']
    non_consumables_cost = cost_data['non_consumables_cost']
    total_cost = cost_data['total_cost']

    # Initialize PDF buffer
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=72, leftMargin=72, topMargin=36, bottomMargin=36)
    elements = []
    styles = getSampleStyleSheet()

    # Define styles
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=18,
        spaceAfter=10,
        alignment=1
    )
    
    header_style = ParagraphStyle(
        'Header',
        parent=styles['Normal'],
        fontSize=16,
        textColor=colors.HexColor('#1e40af'),
        spaceAfter=20
    )

    # Add header
    elements.append(Paragraph("Cost Analysis", header_style))
    if category:
        elements.append(Paragraph(f"Category: {category}", styles['Normal']))
    elements.append(Spacer(1, 20))

    # Total Cost Summary
    total_cost_data = [[f"Total Cost of Assets\n Rs {total_cost:,.2f}"]]
    total_cost_table = Table(total_cost_data, colWidths=[7 * inch])
    total_cost_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#1e40af')),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 14),
        ('TOPPADDING', (0, 0), (-1, -1), 15),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 15),
    ]))
    elements.append(total_cost_table)
    elements.append(Spacer(1, 20))

    # Provider Cost Analysis
    provider_text = (
        f"Cost by Asset Provider\n"
        f"CSI-Borrowed: Rs {csi_borrowed_cost:,.2f}\n"
        f"CSI-Purchased: Rs {csi_purchased_cost:,.2f}\n"
        f"Total CSI: Rs {total_csi_cost:,.2f}\n"
        f"BGSW: Rs {bgsw_cost:,.2f}"
    )
    provider_data = [[provider_text]]
    provider_table = Table(provider_data, colWidths=[7 * inch])
    provider_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#1e40af')),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 12),
        ('TOPPADDING', (0, 0), (-1, -1), 15),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 15),
    ]))
    elements.append(provider_table)
    elements.append(Spacer(1, 20))

    # Classification Cost Analysis
    classification_data = [[f"Cost by Asset Classification\nConsumables: Rs {consumables_cost:,.2f}\nNon Consumables: Rs {non_consumables_cost:,.2f}"]]
    classification_table = Table(classification_data, colWidths=[7 * inch])
    classification_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#1e40af')),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 14),
        ('TOPPADDING', (0, 0), (-1, -1), 15),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 15),
    ]))
    elements.append(classification_table)
    elements.append(Spacer(1, 20))

    # Create bar charts with fixed color
    plt.style.use('default')
    
    # Provider costs chart
    plt.figure(figsize=(8, 4))
    providers = ['CSI-Borrowed', 'CSI-Purchased', 'BGSW']
    provider_costs = [csi_borrowed_cost, csi_purchased_cost, bgsw_cost]
    
    plt.bar(providers, provider_costs, color='#1e40af')
    plt.title("Cost by Asset Provider")
    plt.ylabel("Cost (Rs)")
    plt.xticks(rotation=45, ha='right')
    plt.grid(axis='y', linestyle='--', alpha=0.7)
    
    provider_buffer = BytesIO()
    plt.tight_layout()
    plt.savefig(provider_buffer, format='png', dpi=300, bbox_inches='tight')
    plt.close()
    provider_buffer.seek(0)
    provider_image = ReportLabImage(provider_buffer, width=7*inch, height=3.5*inch)
    elements.append(provider_image)
    elements.append(Spacer(1, 20))

    # Classification costs chart
    plt.figure(figsize=(8, 4))
    plt.bar(['Consumables', 'Non Consumables'], 
            [consumables_cost, non_consumables_cost],
            color='#1e40af')
    plt.title("Cost by Asset Classification")
    plt.ylabel("Cost (Rs)")
    plt.grid(axis='y', linestyle='--', alpha=0.7)
    
    classification_buffer = BytesIO()
    plt.savefig(classification_buffer, format='png', dpi=300, bbox_inches='tight')
    plt.close()
    classification_buffer.seek(0)
    classification_image = ReportLabImage(classification_buffer, width=7*inch, height=3.5*inch)
    elements.append(classification_image)

    # Detailed table
    headers = ["Category", "Asset Provider", "Classification", "Total Cost (Rs)"]
    table_data = [headers]

    # Fetch data dynamically
    queryset = Asset.objects.values(
        'Category', 
        'AssetProvider', 
        'AssetClassification'
    ).annotate(
        total_cost=Sum('Cost')
    )

    if category:
        queryset = queryset.filter(Category=category)

    # Add data rows
    for item in queryset:
        row = [
            item['Category'],
            item['AssetProvider'],
            item['AssetClassification'],
            f"Rs {item['total_cost']:,.2f}"
        ]
        table_data.append(row)

    # Create and style the table
    detailed_table = Table(table_data, colWidths=[1.75*inch, 1.75*inch, 1.75*inch, 1.75*inch])
    detailed_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e40af')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 12),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.white),
        ('TEXTCOLOR', (0, 1), (-1, -1), colors.black),
        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 1), (-1, -1), 10),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ('ALIGN', (-1, 0), (-1, -1), 'RIGHT'),  # Right align the cost column
        ('BOTTOMPADDING', (0, 1), (-1, -1), 10),
        ('TOPPADDING', (0, 1), (-1, -1), 10),
    ]))
    elements.append(Spacer(1, 20))
    elements.append(detailed_table)
    
    # Build PDF
    doc.build(elements)
    pdf = buffer.getvalue()
    buffer.close()

    # Create response
    response = HttpResponse(content_type='application/pdf')
    response['Content-Disposition'] = 'attachment; filename="cost_analysis_report.pdf"'
    response.write(pdf)
    return response

from django.http import HttpResponse
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image as ReportLabImage
from io import BytesIO
import json
import matplotlib.pyplot as plt
from PIL import Image as PILImage
from datetime import datetime
from .models import Asset, User
from django.db.models import Sum, Count
from reportlab.lib.units import inch

def download_combined_reports(request):
    # Get user info
    user_id = request.session.get('user_id')
    if not user_id:
        return HttpResponse("User not logged in.", status=401)
    
    user = User.objects.get(UserId=user_id)
    
    # Get category filter if any
    category = request.GET.get('category', None)
    
    # Create PDF buffer
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=72, leftMargin=72, topMargin=36, bottomMargin=36)
    elements = []
    styles = getSampleStyleSheet()
    
    # Add company header
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=18,
        spaceAfter=10,
        alignment=1
    )
    elements.append(Paragraph("Bosch Global Software Technologies Pvt Ltd", title_style))
    elements.append(Paragraph("Report", title_style))
    
    # Add metadata
    metadata_style = ParagraphStyle(
        'Metadata',
        parent=styles['Normal'],
        fontSize=10,
        spaceAfter=8
    )
    elements.append(Paragraph(f"Generated by: {user.username}", metadata_style))
    elements.append(Paragraph(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", metadata_style))
    elements.append(Spacer(1, 10))
    
    # Section heading style
    section_heading_style = ParagraphStyle(
        'SectionHeading',
        parent=styles['Heading1'],
        fontSize=14,
        spaceAfter=8
    )
    elements.append(Paragraph("1. Asset Category Distribution", section_heading_style))
    elements.append(Spacer(1, 5))
    
    # Get category distribution data
    category_data = Asset.objects.values('Category').annotate(count=Count('AssetID'))
    categories = [item['Category'] for item in category_data]
    counts = [item['count'] for item in category_data]
    
    # Create doughnut chart
    plt.figure(figsize=(6, 4))  # Reduced figure size for better proportions
    plt.pie(counts, labels=categories, autopct='%1.1f%%', pctdistance=0.85,
            colors=['#1e40af', '#2563eb', '#3b82f6', '#60a5fa', '#93c5fd'])

    # Adjust inner circle size (reduce from 0.70 to 0.60)
    centre_circle = plt.Circle((0, 0), 0.60, fc='white')  # Decreased inner circle size
    fig = plt.gcf()
    fig.gca().add_artist(centre_circle)

    plt.title('Asset Distribution by Category', pad=20)
    plt.tight_layout()

    # Save doughnut chart
    category_buffer = BytesIO()
    plt.savefig(category_buffer, format='png', dpi=300, bbox_inches='tight')
    plt.close()

    # Reset buffer position and add to elements with reduced width
    category_buffer.seek(0)
    category_image = ReportLabImage(category_buffer, width=4 * inch, height=3 * inch)  # Reduced width and height
    elements.append(category_image)
    elements.append(Spacer(1, 15))
    
    # Add category summary table
    category_table_data = [['Category', 'Number of Assets', 'Percentage']]
    total_assets = sum(counts)
    for cat, count in zip(categories, counts):
        percentage = (count / total_assets) * 100
        category_table_data.append([
            cat,
            str(count),
            f"{percentage:.1f}%"
        ])
    
    category_table = Table(category_table_data)
    category_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e40af')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
    ]))
    elements.append(category_table)
    elements.append(Spacer(1, 15))
    
    

    # 2. Asset Data Section
    elements.append(Paragraph("2. Asset Data Report", section_heading_style))
    elements.append(Spacer(1, 5))

    # Fetch assets from the database
    assets = Asset.objects.all()
    if category:
        assets = assets.filter(Category=category)

    # Asset data table
    asset_data = [
        ['Asset ID', 'Asset Number', 'Serial Number', 'Asset Model', 'Part Number', 'Name', 'Category', 'Status']
    ]
    for asset in assets:
        asset_data.append([
            str(asset.AssetID),
            asset.AssetNumber,
            asset.SerialNumber,
            asset.AssetModel,
            asset.PartNumber,
            asset.AssetName,
            asset.Category,
            asset.AssetStatus
        ])

    # Calculate column widths based on page width
    page_width = letter[0] - 144  # page width minus margins (72 pts on each side)
    # Distribution of column widths - adjusted for 8 columns
    col_widths = [
        page_width * 0.08,  # Asset ID - 8%
        page_width * 0.11,  # Asset Number - 11%
        page_width * 0.13,  # Serial Number - 13%
        page_width * 0.13,  # Asset Modal - 13%
        page_width * 0.14,  # Part Number - 14%
        page_width * 0.16,  # Name - 16%
        page_width * 0.12,  # Category - 12%
        page_width * 0.13   # Status - 13%
    ]

    # Create the table with specified column widths
    asset_table = Table(asset_data, colWidths=col_widths, repeatRows=1)
    asset_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e40af')),     # Header background color
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),               # Header text color
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),                           # Center align all cells
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),                 # Bold font for headers
        ('FONTSIZE', (0, 0), (-1, 0), 8),                                # Even smaller font size for headers
        ('FONTSIZE', (0, 1), (-1, -1), 7),                               # Further reduced font size for content
        ('BOTTOMPADDING', (0, 0), (-1, 0), 4),                           # Reduced padding below headers
        ('TOPPADDING', (0, 0), (-1, -1), 2),                             # Minimal top padding
        ('BOTTOMPADDING', (0, 1), (-1, -1), 2),                          # Minimal bottom padding
        ('LEFTPADDING', (0, 0), (-1, -1), 2),                            # Minimal left padding
        ('RIGHTPADDING', (0, 0), (-1, -1), 2),                           # Minimal right padding
        ('GRID', (0, 0), (-1, -1), 0.5, colors.black),                   # Thinner grid lines
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),                          # Middle vertical alignment
        ('WORDWRAP', (0, 0), (-1, -1), True),                            # Enable word wrapping
    ]))

    # Add the table to the elements list
    elements.append(asset_table)
    elements.append(Spacer(1, 15))
    
    # 3. Cost Analysis Section
    elements.append(Paragraph("3. Cost Analysis Report", section_heading_style))
    elements.append(Spacer(1, 5))

    # Get category filter from request
    category_filter = request.GET.get('category', None)

    # Calculate costs with category filter applied
    def get_filtered_cost(provider=None, classification=None):
        queryset = Asset.objects.all()
        if category_filter:
            queryset = queryset.filter(Category=category_filter)
        if provider:
            queryset = queryset.filter(AssetProvider=provider)
        if classification:
            queryset = queryset.filter(AssetClassification=classification)
        return queryset.aggregate(total=Sum('Cost'))['total'] or 0

    csi_borrowed_cost = get_filtered_cost(provider='CSI-Borrowed')
    csi_purchased_cost = get_filtered_cost(provider='CSI-Purchased')
    total_csi_cost = csi_borrowed_cost + csi_purchased_cost
    bgsw_cost = get_filtered_cost(provider='BGSW')
    consumables_cost = get_filtered_cost(classification='Consumables')
    non_consumables_cost = get_filtered_cost(classification='Non Consumables')

    # Calculate total cost with category filter
    total_cost_queryset = Asset.objects.all()
    if category_filter:
        total_cost_queryset = total_cost_queryset.filter(Category=category_filter)
    total_cost = total_cost_queryset.aggregate(total=Sum('Cost'))['total'] or 0

    # Define styles
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=18,
        spaceAfter=10,
        alignment=1
    )

    # Define bold style for section headings
    bold_style = ParagraphStyle(
        'BoldStyle',
        parent=styles['Normal'],
        fontSize=12,
        spaceAfter=8,
        fontName='Helvetica-Bold'
    )

    # 3.1 Overall Cost Summary
    elements.append(Paragraph("3.1 Overall Cost Summary", bold_style))  # Now properly defined

    total_cost_table_data = [
        [f"Total Cost: Rs {total_cost:,.2f}"]
    ]
    total_cost_table = Table(total_cost_table_data, colWidths=[4 * inch], rowHeights=[0.6 * inch])
    total_cost_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#1e40af')),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 14),
        ('LEFTPADDING', (0, 0), (-1, -1), 15),
        ('RIGHTPADDING', (0, 0), (-1, -1), 15),
        ('TOPPADDING', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
        ('BOX', (0, 0), (-1, -1), 2, colors.HexColor('#1e40af')),
    ]))
    elements.append(total_cost_table)
    elements.append(Spacer(1, 15))


    # 3.2 Provider Cost Analysis
    elements.append(Paragraph("3.2 Cost Analysis by Provider", bold_style))

    # Create provider chart
    plt.figure(figsize=(8, 4))
    providers = ['CSI-Borrowed', 'CSI-Purchased', 'BGSW']
    provider_costs = [csi_borrowed_cost, csi_purchased_cost, bgsw_cost]
    bars = plt.bar(providers, provider_costs, color='#1e40af')
    plt.title('Cost by Provider', fontsize=12)
    plt.ylabel('Cost (Rs)', fontsize=10)
    plt.xticks(rotation=45, ha='right', fontsize=8)

    # Add value labels
    for bar in bars:
        height = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2., height,
                f'Rs {height:,.2f}',
                ha='center', va='bottom', fontsize=8)

    plt.tight_layout()
    provider_buffer = BytesIO()
    plt.savefig(provider_buffer, format='png', dpi=300, bbox_inches='tight')
    plt.close()
    provider_buffer.seek(0)
    provider_image = ReportLabImage(provider_buffer, width=6 * inch, height=3 * inch)
    elements.append(provider_image)
    elements.append(Spacer(1, 10))

    # Provider cost table
    provider_table_data = [['Provider', 'Cost (Rs)', 'Percentage']]
    total_provider_cost = sum(provider_costs)
    for provider, cost in zip(providers, provider_costs):
        percentage = (cost / total_provider_cost * 100) if total_provider_cost > 0 else 0
        provider_table_data.append([
            provider,
            f"Rs{cost:,.2f}",
            f"{percentage:.1f}%"
        ])

    provider_table = Table(provider_table_data)
    provider_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e40af')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
    ]))
    elements.append(provider_table)
    elements.append(Spacer(1, 15))

    # 3.3 Classification Cost Analysis
    elements.append(Paragraph("3.3 Cost Analysis by Classification", bold_style))

    # Create classification chart
    plt.figure(figsize=(8, 4))
    classifications = ['Consumables', 'Non Consumables']
    classification_costs = [consumables_cost, non_consumables_cost]
    bars = plt.bar(classifications, classification_costs, color='#1e40af')
    plt.title('Cost by Classification', fontsize=12)
    plt.ylabel('Cost (Rs)', fontsize=10)
    plt.xticks(rotation=45, ha='right', fontsize=8)

    # Add value labels
    for bar in bars:
        height = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2., height,
                f'Rs{height:,.2f}',
                ha='center', va='bottom', fontsize=8)

    plt.tight_layout()
    classification_buffer = BytesIO()
    plt.savefig(classification_buffer, format='png', dpi=300, bbox_inches='tight')
    plt.close()
    classification_buffer.seek(0)
    classification_image = ReportLabImage(classification_buffer, width=6 * inch, height=3 * inch)
    elements.append(classification_image)
    elements.append(Spacer(1, 10))

    # Classification cost table
    classification_table_data = [['Classification', 'Cost (Rs)', 'Percentage']]
    total_classification_cost = sum(classification_costs)
    for classification, cost in zip(classifications, classification_costs):
        percentage = (cost / total_classification_cost * 100) if total_classification_cost > 0 else 0
        classification_table_data.append([
            classification,
            f"Rs{cost:,.2f}",
            f"{percentage:.1f}%"
        ])

    classification_table = Table(classification_table_data)
    classification_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e40af')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
    ]))
    elements.append(classification_table)
    elements.append(Spacer(1, 15))

    # 3.4 Cost per Asset Category Section
    elements.append(Paragraph("3.4 Cost Analysis by Asset Category", section_heading_style))
    elements.append(Spacer(1, 5))

    # Get category cost data with filter applied
    category_cost_data = Asset.objects.values('Category').annotate(total_cost=Sum('Cost'))
    if category_filter:
        category_cost_data = category_cost_data.filter(Category=category_filter)

    categories = [item['Category'] for item in category_cost_data]
    costs = [item['total_cost'] or 0 for item in category_cost_data]

    # Create category chart
    plt.figure(figsize=(8, 4))
    bars = plt.bar(categories, costs, color='#1e40af')
    plt.title('Cost Analysis by Asset Category', fontsize=12)
    plt.xlabel('Categories', fontsize=10)
    plt.ylabel('Total Cost (Rs)', fontsize=10)
    plt.xticks(rotation=45, ha='right', fontsize=8)

    # Add value labels
    for bar in bars:
        height = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2., height,
                f'Rs{height:,.2f}',
                ha='center', va='bottom', fontsize=8)

    plt.tight_layout()
    category_cost_buffer = BytesIO()
    plt.savefig(category_cost_buffer, format='png', dpi=300, bbox_inches='tight')
    plt.close()
    category_cost_buffer.seek(0)
    category_cost_image = ReportLabImage(category_cost_buffer, width=6 * inch, height=3 * inch)
    elements.append(category_cost_image)
    elements.append(Spacer(1, 15))

    # Category cost table
    category_cost_table_data = [['Category', 'Total Cost (Rs)']]
    for item in category_cost_data:
        category_cost_table_data.append([
            item['Category'],
            f"Rs{float(item['total_cost'] or 0):,.2f}"
        ])

    category_cost_table = Table(category_cost_table_data, repeatRows=1)
    category_cost_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e40af')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('RIGHTPADDING', (-1, 0), (-1, -1), 15),
    ]))
    elements.append(category_cost_table)
    elements.append(Spacer(1, 15))

    # 4. Idle Analysis Section
    elements.append(Paragraph("4. Asset Idle Analysis Report", section_heading_style))
    elements.append(Spacer(1, 5))

    # Idle analysis table (with max_idle_days column)
    idle_data = [['Asset Name', 'Cost (Rs)','Vendor','Idle Days', 'Max Idle Days']]  # Added Max Idle Days column
    if assets.exists():
        max_idle_days = max(asset.max_idle_days for asset in assets)  # Find the maximum max_idle_days
        for asset in assets:
            vendor_name = asset.VendorID.VendorName if asset.VendorID else "Unknown Vendor"  # Get vendor name
            idle_data.append([

                asset.AssetName,
                f"Rs {float(asset.Cost):,.2f}",
                vendor_name,
                str(asset.idle_days),
                str(asset.max_idle_days)  # Added max_idle_days
            ])
        idle_table = Table(idle_data)
        idle_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e40af')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ]))
        elements.append(idle_table)
        elements.append(Spacer(1, 10))

        # Find all assets with the maximum max_idle_days
        max_idle_assets = [asset for asset in assets if asset.max_idle_days == max_idle_days]
        max_idle_details = [['Maximum Idle Days Details']]  # Header row
        for asset in max_idle_assets:
            max_idle_details.append(['Asset Name', asset.AssetName])
            max_idle_details.append(['Cost (Rs)', f"Rs {float(asset.Cost):,.2f}"])
            max_idle_details.append(['Idle Days', str(asset.idle_days)])
            max_idle_details.append(['Max Idle Days', str(asset.max_idle_days)])  # Added max_idle_days
            max_idle_details.append(['---', '---'])  # Separator for clarity

        # Remove the last separator row if there are multiple assets
        if max_idle_assets:
            max_idle_details.pop()  # Remove the last '---' separator

        # Create and style the maximum idle details table
        max_idle_table = Table(max_idle_details, colWidths=[3 * inch, 3 * inch])
        max_idle_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e40af')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ]))
        elements.append(max_idle_table)
        elements.append(Spacer(1, 15))
        elements.append(Spacer(1, 5))

   

        
    
    # 5. Asset Provider Performance Section
    elements.append(Paragraph("5. Asset Provider Performance (Max Idle Days by Provider)", section_heading_style))
    elements.append(Spacer(1, 5))

    # Get max idle days data grouped by provider
    provider_max_idle_data = (
        Asset.objects.values('AssetProvider')
        .annotate(avg_max_idle_days=Avg('max_idle_days'))  # Use max_idle_days instead of idle_days
    )

    providers = [item['AssetProvider'] for item in provider_max_idle_data]
    avg_max_idle_days = [item['avg_max_idle_days'] or 0 for item in provider_max_idle_data]

    # Create bar chart
    plt.figure(figsize=(8, 4))
    plt.bar(providers, avg_max_idle_days, color='#1e40af')  # Use avg_max_idle_days
    plt.title('Average Max Idle Days by Provider', fontsize=12)  # Update title
    plt.xlabel('Providers', fontsize=10)
    plt.ylabel('Average Max Idle Days', fontsize=10)  # Update y-axis label
    plt.tight_layout()

    # Save provider performance chart
    provider_max_idle_buffer = BytesIO()
    plt.savefig(provider_max_idle_buffer, format='png', dpi=300)
    plt.close()
    provider_max_idle_buffer.seek(0)

    # Add the chart to the PDF
    provider_max_idle_image = ReportLabImage(provider_max_idle_buffer, width=6 * inch, height=3 * inch)
    elements.append(provider_max_idle_image)
    elements.append(Spacer(1, 15))
    
   # 6. Vendor Contributions by Category Section
    elements.append(Paragraph("6. Vendor Contributions by Category", section_heading_style))
    elements.append(Spacer(1, 5))

    # Get vendor contributions grouped by category with BGSW Vendor ID
    vendor_category_data = (
        Asset.objects.select_related('VendorID')  # Join with Vendor table
        .values(
            'VendorID__VendorName',
            'VendorID__BgswVendorId',  # Include BGSW Vendor ID
            'Category'
        )
        .annotate(
            total_assets=Count('AssetID'),
            total_cost=Sum('Cost')
        )
    )

    # Prepare data for the table with BGSW Vendor ID
    vendor_category_table_data = [
        ['Vendor Name', 'BGSW Vendor ID', 'Category', 'Number of Assets', 'Total Cost (Rs)']
    ]

    for item in vendor_category_data:
        vendor_name = item['VendorID__VendorName'] or "Unknown Vendor"
        bgsw_vendor_id = item['VendorID__BgswVendorId'] or "N/A"  # Handle null values
        
        vendor_category_table_data.append([
            vendor_name,
            bgsw_vendor_id,  # Add BGSW Vendor ID column
            item['Category'],
            str(item['total_assets']),
            f"Rs {float(item['total_cost']):,.2f}" if item['total_cost'] else "Rs 0.00"
        ])


    # Create and style the table
    vendor_category_table = Table(vendor_category_table_data)
    vendor_category_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e40af')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
    ]))
    elements.append(vendor_category_table)
    elements.append(Spacer(1, 15))

    # Build PDF
    doc.build(elements)
    pdf = buffer.getvalue()
    buffer.close()

    # Create response
    response = HttpResponse(content_type='application/pdf')
    response['Content-Disposition'] = 'attachment; filename="combined_asset_reports.pdf"'
    response.write(pdf)
    return response   
    
    




''' the users views will be here'''
from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from .models import AssetRequest


from django.db.models import Count
from django.db.models.functions import TruncMonth

from django.db.models import Count
from django.db.models.functions import TruncMonth

from django.utils import timezone
from django.db.models import Count
from django.db.models.functions import TruncMonth

def user_dashboard(request):
    # Retrieve the logged-in user's ID from the session
    user_id = request.session.get('user_id')
    if not user_id:
        return redirect('login')
    
    # Get current date for comparing asset requests
    current_date = timezone.now().date()
    
    # Fetch the logged-in user's details
    user = User.objects.get(UserId=user_id)
    
    # Get all asset requests for the logged-in user
    asset_requests = AssetRequest.objects.filter(UserId=user_id)
    
    # Fetch unique categories from the Asset model
    categories = Asset.objects.values_list('Category', flat=True).distinct()
    
    # Calculate asset counts by category for assets that are currently in use by the logged-in user
    asset_category_counts = (
        Asset.objects.filter(
            AssetAvailability="In Use",
            assetrequest__UserId=user_id,
            assetrequest__Status="Completed",
            assetrequest__StartDate__lte=current_date,  # Request has started
            assetrequest__EndDate__gte=current_date,    # Request hasn't ended
            assetrequest__SurrenderDate__isnull=True    # Asset hasn't been surrendered
        )
        .values("Category")
        .annotate(count=Count("AssetID"))
        .order_by("Category")
    )
    
    category_labels = [entry["Category"] for entry in asset_category_counts]
    category_data = [entry["count"] for entry in asset_category_counts]
    
    # Calculate monthly asset request counts for each status
    monthly_request_counts = (
        asset_requests.annotate(month=TruncMonth('RequestedAt'))
        .values('month', 'Status')
        .annotate(count=Count('RequestId'))
        .order_by('month', 'Status')
    )
    
    # Organize data into separate lists for each status
    months = sorted({entry['month'].strftime('%B') for entry in monthly_request_counts})
    approved_data = [0] * len(months)
    pending_data = [0] * len(months)
    rejected_data = [0] * len(months)
    surrendered_data = [0] * len(months)
    
    for entry in monthly_request_counts:
        month = entry['month'].strftime('%B')
        index = months.index(month)
        if entry['Status'] == 'Completed':
            approved_data[index] = entry['count']
        elif entry['Status'] == 'Pending':
            pending_data[index] = entry['count']
        elif entry['Status'] == 'Rejected':
            rejected_data[index] = entry['count']
        elif entry['Status'] == 'Surrendered':
            surrendered_data[index] = entry['count']
    
    context = {
        "asset_requests": asset_requests,
        "categories": categories,
        "category_labels": category_labels,
        "category_data": category_data,
        "monthly_labels": months,
        "approved_data": approved_data,
        "pending_data": pending_data,
        "rejected_data": rejected_data,
        "surrendered_data": surrendered_data,
        "user": user,
    }
    
    return render(request, "user/dashboard.html", context)

from django.http import HttpResponse
import csv
from reportlab.pdfgen import canvas
from .models import AssetRequest  # Import the AssetRequest model

def user_log_download_csv(request):
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="asset_requests.csv"'

    writer = csv.writer(response)
    writer.writerow(['Request ID', 'Asset Name', 'Status','Category', 'Start Date', 'End Date', 'Purpose'])

    # Query all asset requests
    asset_requests = AssetRequest.objects.all()

    for request in asset_requests:
        writer.writerow([
            request.RequestId,
            request.AssetID.AssetName,
            request.Status,
            request.AssetID.Category,
            request.StartDate,
            request.EndDate,
            request.Purpose
        ])

    return response


from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from django.http import HttpResponse
from datetime import datetime
from .models import AssetRequest  # Import your AssetRequest model

def user_log_download_pdf(request):
    # Create a Django HTTP response with PDF content type
    response = HttpResponse(content_type='application/pdf')
    response['Content-Disposition'] = 'attachment; filename="asset_requests.pdf"'

    # Create a PDF document
    doc = SimpleDocTemplate(response, pagesize=letter)
    elements = []

    # Add the company name
    styles = getSampleStyleSheet()
    company_name = Paragraph("<b>Bosch Global Software Technologies</b>", styles['Title'])
    elements.append(company_name)

    # Add download date and time
    current_datetime = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    download_info = Paragraph(f"<b>Downloaded on:</b> {current_datetime}", styles['Normal'])
    elements.append(download_info)

    # Add downloaded by user name
    user_id = request.session.get('user_id')
    if not user_id:
        return redirect('login')  # Redirect if not logged in
    user = User.objects.get(UserId=user_id)
    user_name = user.username
    downloaded_by = Paragraph(f"<b>Downloaded by:</b> {user_name}", styles['Normal'])
    elements.append(downloaded_by)

    # Add some spacing
    elements.append(Spacer(1, 20))

    # Query all asset requests
    asset_requests = AssetRequest.objects.all()

    # Prepare data for the table
    data = [["Request ID", "Asset Name", "Status","Category", "Start Date", "End Date", "Purpose"]]  # Header row
    for request in asset_requests:
        data.append([
            str(request.RequestId),
            str(request.AssetID.AssetName),
            str(request.Status),
            str(request.AssetID.Category),
            str(request.StartDate),
            str(request.EndDate),
            str(request.Purpose),
        ])

    # Create the table
    table = Table(data)

    # Define table style
    style = TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#001B2E")),  # Header background color
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),  # Header text color
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),  # Center-align all cells
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),  # Bold font for header
        ('FONTSIZE', (0, 0), (-1, 0), 12),  # Font size for header
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),  # Padding below header
        ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor("#F5F5F5")),  # Off-white background for data rows
        ('GRID', (0, 0), (-1, -1), 1, colors.black),  # Grid lines
    ])

    # Apply the style to the table
    table.setStyle(style)

    # Add the table to the elements list
    elements.append(table)

    # Build the PDF document
    doc.build(elements)

    return response


from django.shortcuts import render, redirect, get_object_or_404
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from .models import User
from django.contrib import messages
from django.contrib.auth.decorators import login_required, user_passes_test

def user_management(request):
    user_id = request.session.get('user_id')
    if not user_id:
        return redirect('login')  # Redirect if not logged in

    # Fetch user details
    user = User.objects.get(UserId=user_id)

    # Get all users
    user_list = User.objects.all().order_by('UserId')
    
    # Pagination
    page = request.GET.get('page', 1)
    paginator = Paginator(user_list, 10)  # Show 10 users per page
    
    try:
        users = paginator.page(page)
    except PageNotAnInteger:
        users = paginator.page(1)
    except EmptyPage:
        users = paginator.page(paginator.num_pages)
    
   
    context = {
        'users': users,
        'user':user,
    }
    
    return render(request, 'admin/user_management.html', context)




def delete_user(request, user_id):
    user = get_object_or_404(User, UserId=user_id)
    username = user.username
    user.delete()
    messages.success(request, f'User {username} deleted successfully.')
    return redirect('user_management')



from django.shortcuts import render, redirect
from .models import Asset, User
from django.shortcuts import render, redirect
from django.db import models
from .models import Asset, User

from django.shortcuts import render, redirect
from .models import Asset, User

def User_Asset_Inventory(request):
    user_id = request.session.get('user_id')
    if not user_id:
        return redirect('login')  # Redirect if not logged in
    
    update_asset_availability()
    
    # Fetch all assets
    assets = Asset.objects.all()
    
    # Fetch unique categories (Asset Types)
    categories = Asset.objects.values_list('Category', flat=True).distinct()
    asset_types = Asset.objects.values_list('AssetType', flat=True).distinct()

    # Fetch all fields of the Asset model (excluding related fields)
    asset_fields = [field.name for field in Asset._meta.get_fields() if not field.is_relation]
    
    # Define a mapping for user-friendly field names
    FIELD_LABELS = {
        'AssetID': 'Asset ID',
        'AssetName': 'Asset Name',
        'Category': 'Category',
        'AssetNumber': 'Asset Number',
        'BondNumber': 'Bond Number',
        'PurchaseOrder': 'Purchase Order',
        'PurchaseRequisition':'Purchase Requisition',
        'Capex':'Capex',
        'SerialNumber': 'Serial Number',
        'PartNumber': 'Part Number',
        'AssetType': 'Asset Type',
        'AssetStatus': 'Asset Status',
        'Warehouse': 'Warehouse',
        'Location': 'Location',
        'AssetProvider': 'Asset Provider',
        'AssetClassification': 'Asset Classification',
        'PurchaseDate': 'Purchase Date',
        'Cost': 'Cost',
        'Warranty': 'Warranty',
        'BondExpiryDate': 'Bond Expiry Date',
        'Specification': 'Specification',
        'RequiresCalibration': 'Requires Calibration',
    }
    
    # Create a list of tuples with field names and their user-friendly labels
    fields_with_labels = [(field, FIELD_LABELS.get(field, field)) for field in asset_fields]
    
    # Fetch user details
    user = User.objects.get(UserId=user_id)
    
    return render(request, 'user/AssetInventory2.html', {
        'user': user,
        'assets': assets,
        'categories': categories,
        'asset_types': asset_types,
        'fields_with_labels': fields_with_labels
    })
from django.shortcuts import get_object_or_404, redirect
from django.contrib import messages
from datetime import datetime
from .models import AssetRequest, User, Asset

from django.shortcuts import get_object_or_404, redirect
from django.contrib import messages
from datetime import datetime, date
from app.models import AssetRequest, Asset, User  # Adjust imports as needed
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.utils import timezone
from datetime import datetime, date
from .models import AssetRequest, RequestStage, Asset, User  # Import your models

def submit_request(request):
    if request.method == "POST":
        # Retrieve form data
        AssetID = request.POST.get("assetID")
        UserId = request.POST.get("userId")
        start_date_str = request.POST.get("start_date")  # Raw string from POST
        end_date_str = request.POST.get("end_date")      # Raw string from POST
        purpose = request.POST.get("purpose")

        # Fetch user and asset objects
        user = get_object_or_404(User, pk=UserId)
        asset = get_object_or_404(Asset, pk=AssetID)

        # Convert start_date and end_date strings to datetime objects
        try:
            start_date = datetime.strptime(start_date_str, "%Y-%m-%d").date()
            end_date = datetime.strptime(end_date_str, "%Y-%m-%d").date()
        except ValueError:
            messages.error(request, "Invalid date format. Please use YYYY-MM-DD.")
            return redirect("User_Asset_Inventory")

        # Get today's date
        today = date.today()

        # Check if the start_date is in the past
        if start_date < today:
            messages.error(request, "You cannot request an asset for dates before today.")
            return redirect("User_Asset_Inventory")

        # Check if the end_date is earlier than the start_date
        if end_date < start_date:
            messages.error(request, "The end date cannot be earlier than the start date.")
            return redirect("User_Asset_Inventory")

        # Check if the asset is already booked for the selected dates
        existing_request = AssetRequest.objects.filter(
            AssetID=asset,
            StartDate__lte=end_date,
            EndDate__gte=start_date,
        ).exclude(Status="Surrendered").exists()
        if existing_request:
            messages.error(request, "The asset is already booked for the selected dates.")
            return redirect("User_Asset_Inventory")

        # Create the new request
        asset_request = AssetRequest.objects.create(
            UserId=user,
            AssetID=asset,
            StartDate=start_date,
            EndDate=end_date,
            Purpose=purpose,
            Status='Pending',
            RequestedAt=timezone.now()
        )
        
        # Create corresponding RequestStage record
        RequestStage.objects.create(
            RequestId=asset_request,
            StageName='Request',
            StageBy=user,
            Comment='',
        )

        # Send email notification to admin
        email_sent = send_request_notification(
            request_obj=asset_request,
            action='request',  # Action type for a new request
            comment=f"New asset request submitted with purpose of  {asset_request.Purpose}",
            actor=user,
            notify_admin=True
        )

        if not email_sent:
            logger.warning(f"Failed to send admin notification for new asset request {asset_request.RequestId}")

        # Success message
        messages.success(request, "Your request has been submitted successfully.")
        return redirect("User_Asset_Inventory")

    # Redirect if not a POST request
    return redirect("User_Asset_Inventory")
 
from datetime import date
from datetime import date
from django.shortcuts import render, redirect
from django.contrib import messages
from .models import User, AssetRequest, RequestStage
from django.db.models import Q
from datetime import date
from django.shortcuts import render, redirect
from django.contrib import messages
from .models import User, AssetRequest, RequestStage

def user_asset_requests(request):
    user_id = request.session.get('user_id')
    if not user_id:
        return redirect('login')

    storage = messages.get_messages(request)
    for _ in storage:  # Iterate through messages to consume them
        pass

    user = User.objects.get(UserId=user_id)

    # -- Filters --
    status_filter = request.GET.get('status_filter', 'all')
    date_filter = request.GET.get('date_filter', 'all')

    # -- Asset Requests Data --
    asset_requests = AssetRequest.objects.filter(UserId=user)

    # Status Filter
    if status_filter != 'all':
        asset_requests = asset_requests.filter(Status__iexact=status_filter)  # Case-insensitive

    # Date Filter (Example - adjust logic as needed)
    today = date.today()
    if date_filter == 'today':
        asset_requests = asset_requests.filter(RequestedAt__date=today)
    elif date_filter == 'week':
        # Example: Get requests from the past week
        from datetime import timedelta
        start_date = today - timedelta(days=7)
        asset_requests = asset_requests.filter(RequestedAt__date__gte=start_date)
    elif date_filter == 'month':
        # Example: Get requests from the current month
        asset_requests = asset_requests.filter(RequestedAt__month=today.month, RequestedAt__year=today.year)

  

    # Enrich with "can_receive" flag
    for req in asset_requests:
        req.can_receive = RequestStage.objects.filter(
            RequestId=req,
            StageName='Issue',
            StageBy_id=1  # Admin's ID
        ).exists()

    # For adding comments to return requests (example):
    # if request.method == 'POST' and request.POST.get('action') == 'add_comment':
    #     request_id = request.POST.get('request_id')
    #     comment_text = request.POST.get('comment')
    #     #  Create the comment and associate it with the AssetRequest
    # Prepare data for display
    request_data = []
    return_data = []
    for asset_request in asset_requests:
        # Get all stages for this request
        stages = RequestStage.objects.filter(RequestId=asset_request.RequestId).order_by('StageDate')
        latest_stage_date = stages.last().StageDate if stages.exists() else None


        
        # Determine UI status and comments
        ui_status = get_ui_status(asset_request, stages)
        comments = get_comments(stages)
        
        # Create data object - ensure request_id is a string to avoid JavaScript issues
        data_obj = {
            'request_id': str(asset_request.RequestId),  # Convert to string to avoid JavaScript issues
            'asset_name': asset_request.AssetID.AssetName if hasattr(asset_request.AssetID, 'AssetName') else f"Asset {asset_request.AssetID.pk}",
            'user_name': asset_request.UserId.username,
            'start_date': asset_request.StartDate,
            'end_date': asset_request.EndDate,
            'purpose':asset_request.Purpose,
            'status': ui_status,
            'cycle_status' : asset_request.Status,
            'comments': comments,
            'stages': stages,
            'requested_at': asset_request.RequestedAt,
            'surrender_date': asset_request.SurrenderDate,
            'user_id': user_id,
'stage_date': latest_stage_date,

        }
        
        # Sort into correct category
        if asset_request.Status in ['ReturnRequested', 'ReturnAccepted', 'ReturnReceived', 'Surrendered']:
            return_data.append(data_obj)
       
        else:
           
            request_data.append(data_obj)
    # Get the current user for display
    current_user = request.user
    
    context = {
        'request_data': request_data,
        'return_data': return_data,
        'asset_requests': asset_requests,
        'user': current_user,
        'status_filter': status_filter,
        'date_filter': date_filter,
        'user':user,
        'user_id': user_id,  # Pass user_id also to main context
    }
    
    

    return render(request, 'user/UserAssetRequests.html', context)


from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from .models import AssetRequest, RequestStage, User
def send_request_notification(request_obj, action, comment="", actor=None, notify_admin=True):
    """
    Centralized function to send email notifications for asset request status changes
    
    Args:
        request_obj: The AssetRequest object
        action: String describing the action taken (e.g., 'approve', 'reject')
        comment: Optional comment from the actor
        actor: The User object who performed the action (admin or user)
        notify_admin: Boolean to determine if admins should be notified (default True)
    
    Returns:
        bool: True if email was sent successfully, False otherwise
    """
    # Import needed only if this function is in a different file
    

    # Define action to subject/message mapping
    action_details = {
        'approve': {
            'subject': 'Asset Request Approved',
            'message': 'An asset request has been approved.',
        },
        'reject': {
            'subject': 'Asset Request Rejected',
            'message': 'An asset request has been rejected.',
        },
        'issue': {
            'subject': 'Asset Issued',
            'message': 'An asset has been issued to user.',
        },
        'acknowledge': {
            'subject': 'Asset Receipt Acknowledged',
            'message': 'Receipt of an asset has been acknowledged by user.',
        },
        'mark_received': {
            'subject': 'Asset Receipt Confirmed',
            'message': 'An asset has been marked as received by user.',
        },
        'request_return': {
            'subject': 'Asset Return Requested',
            'message': 'A return has been requested for an asset.',
        },
        'accept_return': {
            'subject': 'Asset Return Request Accepted',
            'message': 'A return request for an asset has been accepted.',
        },
        'mark_returned': {
            'subject': 'Asset Marked as Returned',
            'message': 'An asset has been marked as returned.',
        },
        'cancel': {
            'subject': 'Asset Request Cancelled',
            'message': 'An asset request has been cancelled.',
        },
        'close_request': {
            'subject': 'Asset Request Closed',
            'message': 'An asset request has been closed and marked as surrendered.',
        },
        'add_comment': {
            'subject': 'New Comment Added',
            'message': 'A new comment has been added to an asset request.',
        },
        'request': {  # Add a new entry for 'request' action
            'subject': 'New Asset Request Submitted',
            'message': 'A new asset request has been submitted.',
        }
    }

    # If action not recognized, log it but try to handle gracefully
    if action not in action_details:
        logger.warning(f"Attempted to send notification for unrecognized action: {action}")
        # Create default information for unknown actions
        action_details[action] = {
            'subject': f'Asset Request Update: {action.replace("_", " ").title()}',
            'message': f'An asset request has been updated with action: {action.replace("_", " ").title()}.'
        }

    # Get the requester (for reference in email)
    requester = request_obj.UserId

    # Determine recipients
    if actor and actor.role == 'ADMIN':
        # Admin did the action → Notify the user
        recipient_email = requester.email if requester else None
        cc_email = actor.email if actor.email else None
    else:
        # User did the action → Notify admin(s)
        if notify_admin:
            recipient_users = User.objects.filter(role='ADMIN', email__isnull=False).exclude(email='')
            recipient_emails = [u.email for u in recipient_users]
        else:
            recipient_emails = []
        recipient_email = ", ".join(recipient_emails)
        cc_email = actor.email if actor and actor.email else None

    if not recipient_email:
        logger.warning("No valid recipient found for email notification.")
        return False

    # Prepare email content
    asset_name = request_obj.AssetID.AssetName if request_obj.AssetID else "Asset"
    actor_name = actor.username if actor else "System"

    subject = f"{action_details[action]['subject']} - Request #{request_obj.RequestId}"

    # Build email body
    body_lines = [
        f"Dear User/Admin,",
        f"\nThis is a notification regarding asset request (ID: {request_obj.RequestId}) for: '{asset_name}'.",
        f"\nAction: {action.replace('_', ' ').title()}",
        f"Status Update: {action_details[action]['message']}",
        f"Current Request Status: {request_obj.Status}",
        f"Requester: {requester.username if requester else 'Unknown User'}",
        f"Actioned By: {actor_name}",
    ]

    # Include additional details for 'request' action
    if action == 'request':
        body_lines.extend([
            f"\nRequest Details:",
            f"-------------------",
            f"Start Date: {request_obj.StartDate}",  
            f"End Date: {request_obj.EndDate}",      
            f"Purpose: {request_obj.Purpose}",       
            f"-------------------"
        ])

    if comment:
        body_lines.append(f"\nComment:\n--------------------\n{comment}\n--------------------")

    body_lines.append("\n\nYou can view complete details in the Asset Management portal.")
    body_lines.append("\nRegards,\nAsset Management System")

    body = "\n".join(body_lines)

    # Send email
    try:
        email_sent = send_outlook_email(
            recipient_email=recipient_email,
            subject=subject,
            body=body,
            cc_email=cc_email
        )
        return email_sent
    except Exception as e:
        logger.error(f"Error sending email notification: {e}")
        return False 

def acknowledge_asset_request(request, request_id):
    """
    Handles the acknowledgement of an asset by the user.
    """
    user_id = request.session.get('user_id')
    if not user_id:
        return redirect('login')

    user = get_object_or_404(User, UserId=user_id)
    asset_request = get_object_or_404(AssetRequest, RequestId=request_id, UserId=user)

    if asset_request.Status != 'Completed':
        messages.error(request, "This asset request cannot be acknowledged as it is not approved.")
        return redirect('user_asset_requests')

    # Check if an 'Issue' stage exists for this request (admin has issued)
    if not RequestStage.objects.filter(RequestId=asset_request, StageName='Issue').exists():
        messages.error(request, "This asset has not been issued yet.")
        return redirect('user_asset_requests')

    try:
        # Create an 'Acknowledge' stage
        RequestStage.objects.create(
            RequestId=asset_request,
            StageName='Acknowledge',
            StageBy=user,  # The user acknowledging the receipt
            Comment="Asset received by user."  # Optional comment
        )
        
        # Update the status for consistency
        asset_request.Status = 'Completed'
        asset_request.save()
        
        messages.success(request, "Asset receipt acknowledged successfully.")
        
        # Send email notification to admins
        email_sent = send_request_notification(
            asset_request, 
            'acknowledge', 
            "Asset received by user.", 
            user,
            notify_admin=True
        )
        
        if not email_sent:
            logger.warning(f"Failed to send admin notification for acknowledgement of request {request_id}")

    except Exception as e:
        messages.error(request, f"Error acknowledging asset: {e}")

    return redirect('user_asset_requests')


def user_update_request_status(request, request_id):
    """Handle status updates for asset requests"""
    if request.method != 'POST':
        return redirect('user_asset_requests')
        
    action = request.POST.get('action')
    comment = request.POST.get('comment', '')
    user_id = request.session.get('user_id')
    try:
        asset_request = AssetRequest.objects.get(RequestId=request_id)
        user = User.objects.get(UserId=user_id)
        
        # Map frontend actions to stage names and statuses
        action_mapping = {
            'approve': {'stage': 'Approve', 'status': 'Approved'},
            'reject': {'stage': 'Reject', 'status': 'Rejected'},
            'issue': {'stage': 'Issue', 'status': 'Approved'},  # Status remains approved
            'mark_received': {'stage': 'Acknowledge', 'status': 'Completed'},
            'request_return': {'stage': 'ReturnRequest', 'status': 'ReturnRequested'},
            'accept_return': {'stage': 'ReturnAccept', 'status': 'ReturnAccepted'},
            'mark_returned': {'stage': 'ReturnReceive', 'status': 'ReturnReceived'},
            'close_request': {'stage': 'ReturnClose', 'status': 'Surrendered'}
        }

        if action in action_mapping:
            # Create the stage
            stage = RequestStage(
                RequestId=asset_request,
                StageName=action_mapping[action]['stage'],
                StageBy=user,
                Comment=comment
            )
            stage.save()
            
            # Update the asset request status
            asset_request.Status = action_mapping[action]['status']
            asset_request.save()
            
            print(f"Updated request {request_id} with action {action} to status {action_mapping[action]['status']}")
            
            # Send email notification to admins for this action
            email_sent = send_request_notification(
                asset_request, 
                action, 
                comment, 
                user,
                notify_admin=True
            )
            
            if not email_sent:
                logger.warning(f"Failed to send admin notification for {action} on request {request_id}")

        # If adding comment only
        elif action == 'add_comment' and comment:
            # Determine most recent stage
            latest_stage = RequestStage.objects.filter(
                RequestId=asset_request
            ).order_by('-StageDate').first()

            if latest_stage:
                stage_name = latest_stage.StageName
            else:
                stage_name = 'Request'

            stage = RequestStage(
                RequestId=asset_request,
                StageName=stage_name,  # Use the same stage, just adding a comment
                StageBy=user,
                Comment=comment
            )
            stage.save()
            
            # Send comment notification to admins
            send_request_notification(
                asset_request,
                'add_comment',
                comment,
                user,
                notify_admin=True
            )

    except Exception as e:
        print(f"Error updating request: {e}")
        messages.error(request, f"Error updating request: {e}")

    return redirect('user_asset_requests')


def surrender_asset_request(request, request_id):
    user_id = request.session.get('user_id')
    if not user_id:
        return redirect('login')
        
    try:
        # Get the specific asset request for the logged-in user
        asset_request = AssetRequest.objects.get(
            RequestId=request_id,
            UserId=user_id
        )
        
        user = User.objects.get(UserId=user_id)
        
        # Print more detailed information for debugging
        print(f"Asset Request: {asset_request}")
        print(f"Current Status: {asset_request.Status}")
        
        # User can only request return when the asset is in Completed status
        if asset_request.Status == 'Completed':
            try:
                # Create a new stage for return request
                stage = RequestStage(
                    RequestId=asset_request,  # Pass the AssetRequest object directly
                    StageName='ReturnRequest',
                    StageBy=user,
                    Comment="Return requested by user."
                )
                
                print(f"Stage before save: {stage}")
                
                # Try to save with full validation
                stage.full_clean()  # This will validate the model
                stage.save()
                
                # Update asset request status
                asset_request.Status = 'ReturnRequested'
                asset_request.save()
                
                print(f"Stage after save: {stage}")
                print(f"Asset request status after save: {asset_request.Status}")
                
                # Send email notification to admins about return request
                email_sent = send_request_notification(
                    asset_request,
                    'request_return',
                    "Return requested by user.",
                    user,
                    notify_admin=True
                )
                
                if not email_sent:
                    logger.warning(f"Failed to send admin notification for return request {request_id}")
                
                messages.success(request, "Return request submitted successfully. Please wait for admin approval.")
            except ValidationError as ve:
                print(f"Validation Error: {ve}")
                messages.error(request, f"Validation error: {ve}")
            except Exception as e:
                print(f"Error saving stage: {e}")
                messages.error(request, f"Error creating return request: {e}")
        else:
            messages.error(request, f"Cannot request return for this asset. It must be in 'Completed' status. Current status: {asset_request.Status}")
            
    except AssetRequest.DoesNotExist:
        messages.error(request, "Request not found.")
    except User.DoesNotExist:
        messages.error(request, "User not found.")
    except Exception as e:
        print(f"Unexpected error: {e}")
        messages.error(request, f"Error requesting return: {e}")
    
    return redirect('user_asset_requests')

def cancel_asset_request(request, request_id):
    try:
        user_id = request.session.get('user_id')
        if not user_id:
            return redirect('login')
            
        asset_request = AssetRequest.objects.get(RequestId=request_id, UserId=user_id)
        user = get_object_or_404(User, UserId=user_id)
       
        # Only allow cancellation of pending requests
        if asset_request.Status == 'Pending':
            try:
                # Store asset info before deletion for email notification
                asset_id = asset_request.RequestId
                asset_name = asset_request.AssetID.AssetName if asset_request.AssetID else "Unknown Asset"
                
                # Send cancellation notification to admins before deletion
                email_sent = send_request_notification(
                    asset_request, 
                    'cancel', 
                    f"Request cancelled by user: {user.username}", 
                    user,
                    notify_admin=True
                )
                
                if not email_sent:
                    logger.warning(f"Failed to send admin notification for cancellation of request {request_id}")
                
                # Then delete the request
                asset_request.delete()
                messages.success(request, "Asset request successfully cancelled.")
                
                # Log the cancellation
                logger.info(f"Asset request {asset_id} for '{asset_name}' cancelled by user {user.username} (ID: {user_id})")
                
            except Exception as e:
                logger.error(f"Error during cancellation notification or deletion: {e}", exc_info=True)
                messages.error(request, f"Error cancelling request: {e}")
        else:
            messages.error(request, f"Cannot cancel this request. Only pending requests can be cancelled. Current status: {asset_request.Status}")
       
    except AssetRequest.DoesNotExist:
        messages.error(request, "Request not found.")
        logger.warning(f"Attempted to cancel non-existent asset request ID: {request_id}")
    except User.DoesNotExist:
        messages.error(request, "User session is invalid. Please log in again.")
        logger.warning(f"User not found during cancellation attempt for request ID: {request_id}")
    except Exception as e:
        messages.error(request, f"Error cancelling request: {e}")
        logger.error(f"Unexpected error during asset request cancellation: {e}", exc_info=True)
   
    return redirect('user_asset_requests')
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.utils import timezone
from django.db.models import Q
from .models import AssetRequest, RequestStage, Asset, User
from datetime import timedelta
from django.shortcuts import render, redirect
from django.contrib import messages
from django.utils import timezone
from datetime import timedelta
from .models import AssetRequest, RequestStage, User  # Import your models
from django.urls import reverse  # Import reverse

def asset_request_tracking(request):
    """
    View function to display the asset request tracking interface.
    Shows asset requests and returns with filtering capabilities.
    """
    user_id = request.session.get('user_id')
    if not user_id:
        return redirect('login')  # Redirect if not logged in

    try:
        user = User.objects.get(UserId=user_id)
    except User.DoesNotExist:
        messages.error(request, "User not found. Please log in again.")
        return redirect('login')
    # Get all asset requests
    asset_requests = AssetRequest.objects.select_related('AssetID', 'UserId').order_by('-RequestedAt').all()
    for asset_request in asset_requests:
        # Get all stages for this request
        stages = RequestStage.objects.filter(RequestId=asset_request.RequestId).order_by('StageDate')
        
        # Determine UI status and comments
        ui_status = get_ui_status(asset_request, stages)
    # Default filters
    status_filter = request.GET.get('status_filter', 'all')
    date_filter = request.GET.get('date_filter', 'all')
    
    # Apply status filter to requests
    if status_filter != 'all':
        status_mapping = {
            'requested': 'Pending',
            'approved': 'Approved',
            'issued': 'Approved',  # Custom status based on stages
            'received': 'Completed',  # Custom status based on stages
            'return-requested': 'ReturnRequested',
            'accepted': 'ReturnAccepted',
            'returned': 'ReturnReceived',
            'closed': 'Surrendered'
        }
        if status_filter in status_mapping:
            asset_requests = asset_requests.filter(Status=status_mapping[status_filter])
    
    # Apply date filter
    if date_filter != 'all':
        today = timezone.now().date()
        if date_filter == 'today':
            asset_requests = asset_requests.filter(RequestedAt__date=today)
        elif date_filter == 'week':
            week_ago = today - timedelta(days=7)
            asset_requests = asset_requests.filter(RequestedAt__date__gte=week_ago)
        elif date_filter == 'month':
            month_ago = today - timedelta(days=30)
            asset_requests = asset_requests.filter(RequestedAt__date__gte=month_ago)
    
    # Prepare data for display
    request_data = []
    return_data = []
    
    for asset_request in asset_requests:
        # Get all stages for this request
        stages = RequestStage.objects.filter(RequestId=asset_request.RequestId).order_by('StageDate')
        
        # Determine UI status and comments
        ui_status = get_ui_status(asset_request, stages)
        comments = get_comments(stages)
        
        # Get latest stage date if any
        latest_stage_date = stages.last().StageDate if stages.exists() else None

        # Create data object
        data_obj = {
            'request_id': asset_request.RequestId,
            'asset_name': asset_request.AssetID.AssetName if hasattr(asset_request.AssetID, 'AssetName') else f"Asset {asset_request.AssetID.pk}",
            'asset_number': asset_request.AssetID.AssetNumber,
            'user_name':  asset_request.UserId.username,
            'start_date': asset_request.StartDate,
            'end_date': asset_request.EndDate,
            'status': ui_status,
            'cycle_status': asset_request.Status,
            'comments': comments,
            'stages': stages,
            'requested_at': asset_request.RequestedAt,
            'surrender_date': asset_request.SurrenderDate,
            'stage_date': latest_stage_date,  # <-- Added here
            'user_id': asset_request.UserId.pk,
        }

        # Sort into correct category
        if asset_request.Status in ['ReturnRequested', 'ReturnAccepted', 'ReturnReceived', 'Surrendered']:
            return_data.append(data_obj)
        else:
            request_data.append(data_obj)

    
    # Get the current user for display
    current_user = request.user
    
    context = {
        'request_data': request_data,
        'return_data': return_data,
        'user': current_user,
        'status_filter': status_filter,
        'date_filter': date_filter,
        'user':user,
        'user_id': user_id,  # Pass user_id also to main context
    }
    
    return render(request, 'admin/asset_request_tracking.html', context)

from django.http import JsonResponse
from .models import User
from django.http import JsonResponse
from django.contrib.auth.models import User

def get_user_details(request, user_id):
    try:
        user = User.objects.get(pk=user_id)
        return JsonResponse({
            'name': user.username,
            'email': user.email,
            'phone': getattr(user, 'phone', 'Not Available')  # if phone field exists
        })
    except User.DoesNotExist:
        return JsonResponse({'error': 'User not found'}, status=404)


def get_ui_status(asset_request, stages):
    """Determines the UI status based on the AssetRequest status and stages"""
    # Define status mapping
    status_map = {
        'Pending': 'requested',
        'Approved': 'approved',
        'Rejected': 'rejected',
        'Completed': 'received',
        'ReturnRequested': 'return-requested',
        'ReturnAccepted': 'accepted', 
        'ReturnReceived': 'returned',
        'Surrendered': 'closed'
    }
    
    # If there are no stages, use the database status
    if not stages:
        return status_map.get(asset_request.Status, 'requested')
    
    # Get the most recent stage (assuming stages are ordered by date)
    latest_stage = stages.last() if hasattr(stages, 'last') else stages[-1]
    
    # Check the most recent stage
    if latest_stage.StageName == 'ReturnRequest':
        return 'return-requested'
    elif latest_stage.StageName == 'Acknowledge':
        # Only show as received if the DB status isn't something else that should take priority
        if asset_request.Status in ['ReturnRequested', 'ReturnAccepted', 'ReturnReceived']:
            return status_map.get(asset_request.Status)
        return 'received'
    elif latest_stage.StageName == 'Issue':
        return 'issued'
    
    # Fall back to database status mapping
    return status_map.get(asset_request.Status, 'requested')
def get_comments(stages):
    """Extracts comments from stages for display"""
    comments = []
    for stage in stages:
        if stage.Comment:
            comments.append({
                'date': stage.StageDate,
                'text': stage.Comment,
                'stage': stage.StageName,
                'user': stage.StageBy.username
            })
    return comments

from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from .models import AssetRequest, RequestStage
def request_history(request, request_id):
    """
    Fetches the history of an asset request, returning a timeline of stages.
    """
    asset_request = get_object_or_404(AssetRequest, RequestId=request_id)

    # Retrieve all stages related to this request, ordered by date
    stages = RequestStage.objects.filter(RequestId=asset_request).order_by('StageDate')
    
    # Map stage names to UI statuses
    stage_to_ui_status = {
        'Request': 'requested',
        'Approve': 'approved',
        'Issue': 'issued',
        'Acknowledge': 'received',
        'ReturnRequest': 'return-requested',
        'ReturnAccept': 'accepted',
        'ReturnReceive': 'returned',
        'ReturnClose': 'closed'
    }
    
    # Prepare response data as a flat array
    history_data = []
    for stage in stages:
        ui_status = stage_to_ui_status.get(stage.StageName, 'requested')
        history_data.append({
            "ui_status": ui_status,  # Add this field for the JavaScript
            "date": stage.StageDate.strftime('%Y-%m-%d %H:%M:%S'),
            "by": stage.StageBy.username,
            "comment": stage.Comment
        })

    return JsonResponse(history_data, safe=False)

# views.py

# Standard Django Imports
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.urls import reverse # Good practice for URLs

# Your Application Model Imports (adjust path if needed)
from .models import User, AssetRequest, RequestStage, Asset

# Imports for Outlook Automation & Logging
import logging
import platform

# --- Setup for pywin32 (Outlook Automation) ---
# Conditionally import win32com based on OS and availability
if platform.system() == "Windows":
    try:
        import win32com.client as win32
        # Optional: You could try getting the Outlook object here once
        # to see if it's available at startup, but it's often better
        # to do it within the function to handle cases where Outlook starts later.
    except ImportError:
        logging.error("CRITICAL: pywin32 library is not installed. Outlook automation will be disabled.")
        win32 = None # Flag that pywin32 is not available
else:
    logging.warning("Platform is not Windows. Outlook email automation (pywin32) is disabled.")
    win32 = None # Flag that we are not on Windows
import win32com.client as win32
import logging

# Setup logger
logger = logging.getLogger(__name__)

def send_outlook_email(recipient_email, subject, body, cc_email=None):
    """
    Sends an email using the locally installed Outlook application via pywin32.
    Automatically CCs a specified email (e.g., admin or system tracking address).
    
    Args:
        recipient_email (str): Primary recipient of the email.
        subject (str): Subject line of the email.
        body (str): Body text of the email.
        cc_email (str, optional): Email address to CC.

    Returns:
        bool: True if email was successfully queued/sent, False otherwise.
    """

    if not recipient_email:
        logger.warning("Cannot send email - no recipient provided.")
        return False

    # Send email using Django's email backend
    print("Sending email via Django...")
    try:
        from django.core.mail import send_mail
        from django.conf import settings
        
        # Convert recipients list to string for email
        recipient_list = list(set(recipient_email))  # Remove duplicates
        
        # Send the email
        send_mail(
            subject=subject,
            message=body,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=recipient_list,
            fail_silently=False,
        )
        print("Email sent successfully via Django!")
        
    except Exception as e:
        print(f"ERROR sending email via Django: {str(e)}")
        # Fallback: just log the email content for debugging
        print(f"Email would have been sent to: {recipient_email}")
        print(f"Subject: {subject}")
        print(f"Content: {body}")
        
        return JsonResponse({
            'success': False,
            'message': f'Error sending email: {str(e)}'
        })
from django.http import Http404
def update_request_status(request, request_id):
    """
    Handles status updates for asset requests triggered by an Admin/Manager.
    Sends notifications to the requesting user via Outlook if configured.
    """
    if request.method != 'POST':
        # Redirect GET requests back to the tracking page
        return redirect(reverse('asset_request_tracking')) # Use reverse for better URL management

    # Get data from the POST request
    active_tab = request.POST.get('active_tab', 'requests') # Keep track of the tab for redirection
    action = request.POST.get('action')
    comment = request.POST.get('comment', '').strip() # Remove leading/trailing whitespace
    user_id = request.session.get('user_id') # Get admin user ID from session

    # Validate required data
    if not action:
        messages.error(request, "Invalid request: Action is missing.")
        return redirect(reverse('asset_request_tracking') + f'?tab={active_tab}')
    if not user_id:
        messages.error(request, "Session expired or invalid. Please log in again.")
        # Redirect to login or tracking page depending on your auth setup
        return redirect(reverse('asset_request_tracking') + f'?tab={active_tab}')

    try:
        # Fetch objects safely using get_object_or_404
        requesting_admin = get_object_or_404(User, UserId=user_id)
        # Use select_related for efficiency - fetches related User and Asset in one query
        asset_request = get_object_or_404(
            AssetRequest.objects.select_related('UserId', 'AssetID'), # CHANGE 'RequestedBy' to 'UserId'
            RequestId=request_id
        )
    except Http404:
        messages.error(request, "Admin user or Asset Request not found.")
        return redirect(reverse('asset_request_tracking') + f'?tab={active_tab}')

    try:
        # Define the mapping from frontend action to backend stage and status
        action_mapping = {
            'approve': {'stage': 'Approve', 'status': 'Approved'},
            'reject': {'stage': 'Reject', 'status': 'Rejected'},
            'issue': {'stage': 'Issue', 'status': 'Approved'}, # Issuing keeps status Approved until user acknowledges
            'accept_return': {'stage': 'ReturnAccept', 'status': 'ReturnAccepted'},
            'mark_returned': {'stage': 'ReturnReceive', 'status': 'ReturnReceived'},
            'close_request': {'stage': 'ReturnClose', 'status': 'Surrendered'}
        }

        # Define which actions by the admin should trigger an Outlook email notification TO THE USER
        outlook_notification_actions = ['approve', 'reject', 'issue', 'accept_return','mark_returned','close_request']

        email_sent_status = None # Track if email was attempted and its success/failure

        # Process recognized actions
        if action in action_mapping:
            action_info = action_mapping[action]

            # --- Database Operations ---
            # 1. Create the new stage record
            stage = RequestStage(
                RequestId=asset_request,
                StageName=action_info['stage'],
                StageBy=requesting_admin, # The admin performing the action
                Comment=comment # Save the comment with the stage
            )
            stage.save()

            # 2. Update the main AssetRequest status
            asset_request.Status = action_info['status']
            asset_request.save()
            # --- End Database Operations ---

            logger.info(f"Admin '{requesting_admin.username}' (ID: {user_id}) performed action '{action}' "
                        f"on request {request_id}. New status: '{action_info['status']}'.")

            # --- Attempt to Send Outlook Notification ---
            if action in outlook_notification_actions:
                recipient = asset_request.UserId  # Changed from RequestedBy to UserId based on your comment
                if recipient and recipient.email:
                    recipient_email = recipient.email
                    subject = f"Update on Asset Request ID {asset_request.RequestId}: {action_info['status']}"
                    # Safely get asset name, handle if asset might be deleted (though unlikely if request exists)
                    asset_name = asset_request.AssetID.AssetName if asset_request.AssetID else "Asset Not Found"

                    # Construct a clear email body
                    body_lines = [
                        f"Dear {recipient.username or 'User'},", # Use username if available
                        f"\nThis email confirms an update to your asset request (ID: {asset_request.RequestId}) for the asset: '{asset_name}'.",
                        f"\nAction Taken by Admin: {action_info['stage']}",
                        f"The new status of your request is: {action_info['status']}",
                        f"Processed By: {requesting_admin.username}",
                    ]
                    if comment: # Include comment if provided
                        body_lines.append(f"\nAdmin Comment:\n--------------------\n{comment}\n--------------------")

                    body_lines.append("\n\nYou can view the request details in the Asset Management portal.")
                    body_lines.append("\nRegards,\nAsset Management Team")
                    body = "\n".join(body_lines)

                    # Call the Outlook helper function defined above
                    admin_emails = list(User.objects.filter(role='ADMIN', email__isnull=False).exclude(email='').values_list('email', flat=True))

                    if not admin_emails:
                        logger.warning("No admin emails found to CC.")
                        cc_email = None
                    else:
                        cc_email = ', '.join(admin_emails)  # Join multiple emails into one string

                    # Send email
                    email_sent_status = send_outlook_email(
                        recipient_email=recipient_email,
                        subject=subject,
                        body=body,
                        cc_email=cc_email  # CC all admins
                    )

                else:
                    # Cannot send email if user or email is missing
                    logger.warning(f"Cannot send Outlook notification for request {request_id} action '{action}': Requesting user '{recipient.username if recipient else 'N/A'}' has no email address configured.")
                    email_sent_status = False # Mark as failed due to missing recipient info
            # --- End Attempt to Send Outlook Notification ---

            # --- Provide User Feedback via Messages ---
            base_message = f"Request {request_id} status updated to '{action_info['status']}'."
            if action in outlook_notification_actions:
                if email_sent_status is True:
                    messages.success(request, f"{base_message} Outlook notification sent to user.")
                elif email_sent_status is False:
                    # Check if the failure was due to win32 being unavailable
                    if not win32:
                         messages.error(request, f"{base_message} Outlook automation is disabled/unavailable on this system. Email NOT sent.")
                    elif not (recipient and recipient.email):
                         messages.warning(request, f"{base_message} User email is missing. Outlook notification NOT sent.")
                    else:
                         messages.warning(request, f"{base_message} FAILED to send Outlook notification. Please check system logs or Outlook.")
                # If email_sent_status is None, means email wasn't attempted for this action
                else:
                     messages.success(request, base_message)
            else:
                 # Action was successful, but didn't require an email attempt
                 messages.success(request, base_message)
            # --- End User Feedback ---

        # Handle 'add_comment' specifically if it's a separate action button
        # (Current setup seems to bundle comment with main action, which is fine)
        # elif action == 'add_comment' and comment:
        #     # Logic to add comment without changing status - less common for admin actions
        #     # ... (save stage with comment, maybe notify user/admins via Outlook/Django mail) ...
        #     messages.success(request, f"Comment added to request {request_id}.")

        else:
            # Action provided was not in the mapping
            logger.warning(f"Admin '{requesting_admin.username}' attempted invalid action '{action}' on request {request_id}.")
            messages.warning(request, f"Invalid action '{action}' received for request {request_id}.")

    # Catch potential database errors or other unexpected issues
    except Exception as e:
        logger.error(f"Unexpected error processing action '{action}' for request {request_id} by admin '{requesting_admin.username}': {e}", exc_info=True)
        messages.error(request, f"An unexpected error occurred while updating the request: {e}")

    # Redirect back to the tracking page, maintaining the user's active tab
    redirect_url = reverse('asset_request_tracking') + f'?tab={active_tab}'
    return redirect(redirect_url)



def get_alert_counts(request):
    today = datetime.now().date()
   
    # Count pending asset requests (Info alerts) - exclude expired requests
    info_alert_count = AssetRequest.objects.filter(
        Status='Pending',
        EndDate__gte=today  # Only include requests that haven't expired
    ).count()
   
    # Get current alert IDs
    current_alert_ids = get_alert_ids(today)
   
    # Get viewed alert IDs from session
    viewed_alert_ids = set(request.session.get('viewed_alert_ids', []))
   
    # Check if there are any new alerts
    has_new_other_alerts = bool(current_alert_ids - viewed_alert_ids)
   
    # Store current alert IDs in session for next comparison
    request.session['current_alert_ids'] = list(current_alert_ids)
   
    return {
        'info_count': info_alert_count,
        'has_other_alerts': has_new_other_alerts
    }
 

from django.shortcuts import render, redirect
from .models import User, Asset  # Make sure Asset is imported
from django.db.models import F
 
def custom_report_builder(request):
    user_id = request.session.get('user_id')
    if not user_id:
        return redirect('login')
 
    user = User.objects.get(UserId=user_id)
 
    alert_counts = get_alert_counts(request)
 
    # Get unique categories from the Asset model
    categories = Asset.objects.values_list('Category', flat=True).distinct()
 
    context = {
        "user": user,
        'info_alert_count': alert_counts['info_count'],
        'has_other_alerts': alert_counts['has_other_alerts'],
        'categories': categories,
    }
 
    return render(request, 'admin/custom_reports.html', context)
from django.db.models.functions import TruncYear, Cast, Extract
from django.http import JsonResponse
from django.utils import timezone
from django.core.exceptions import ValidationError
 
from datetime import date, timedelta
 
from .models import Asset, AssetRequest  # Adjust import path as needed
 
from django.db.models import F, Value, FloatField, ExpressionWrapper, Q, Sum, Count, Avg, IntegerField
from django.db.models.functions import Cast, Greatest
from django.utils import timezone
from django.db.models import Func
def asset_stats_view(request):
    # Get query parameters
    chart_type = request.GET.get('chart_type', '')
    category = request.GET.get('category', '')
    status = request.GET.get('status', '')
    asset_provider = request.GET.get('asset_provider', '')  # New filter
   
    # Base queryset
    queryset = Asset.objects.all()
   
    # Apply filters
    if category:
        queryset = queryset.filter(Category=category)
    if status:
        queryset = queryset.filter(AssetStatus=status)
    if asset_provider:  # New filter
        queryset = queryset.filter(AssetProvider=asset_provider)
   
    # Generate chart data based on chart type
    try:
        if chart_type == 'bar':
            # Count assets by status
            data = queryset.values('AssetStatus').annotate(count=Count('AssetID'))
            return JsonResponse({
                'labels': [item['AssetStatus'] for item in data],
                'datasets': [{
                    'label': 'Number of Assets',
                    'data': [item['count'] for item in data],
                    'backgroundColor': ['#3498db', '#e74c3c', '#f39c12']
                }]
            })
       
        elif chart_type == 'pie':
            # Count assets by category
            data = queryset.values('Category').annotate(count=Count('AssetID'))
            return JsonResponse({
                'labels': [item['Category'] for item in data],
                'datasets': [{
                    'data': [item['count'] for item in data],
                    'backgroundColor': ['#3498db', '#e74c3c', '#f39c12', '#2ecc71', '#9b59b6']
                }]
            })
       
        elif chart_type == 'line':
            # Total asset cost over time
            data = queryset.annotate(year=TruncYear('PurchaseDate')).values('year').annotate(
                total_cost=Sum('Cost')
            ).order_by('year')
            return JsonResponse({
                'labels': [item['year'].year for item in data],
                'datasets': [{
                    'label': 'Total Asset Cost',
                    'data': [float(item['total_cost']) for item in data],
                    'borderColor': '#3498db',
                    'fill': False
                }]
            })
       
        elif chart_type == 'doughnut':
            data = queryset.values('AssetProvider').annotate(count=Count('AssetID'))
           
            return JsonResponse({
                'type': 'doughnut',  
                'data': {
                    'labels': [item['AssetProvider'] for item in data],
                    'datasets': [{
                        'data': [item['count'] for item in data],
                        'backgroundColor': [
                            '#3498db',
                            '#e74c3c',  
                            '#2ecc71',  
                            '#f39c12',  
                            '#9b59b6'  
                        ],
                        'hoverBackgroundColor': [
                            '#2980b9',  
                            '#c0392b',  
                            '#27ae60',  
                            '#d35400',  
                            '#8e44ad'  
                        ]
                    }]
                },
                'options': {
                    'responsive': True,
                    'maintainAspectRatio': False,
                    'plugins': {
                        'legend': {
                            'position': 'top',
                        }
                    }
                }
            })
       
        elif chart_type == 'table':
            # Use the already filtered queryset
            data = queryset.values('AssetProvider').annotate(
                count=Count('AssetID'),
                total_cost=Sum('Cost'),
            ).order_by('-count')
           
            return JsonResponse({
                'headers': ['Provider', 'Asset Count', 'Total Cost'],
                'rows': [
                    {
                        'provider': item['AssetProvider'],
                        'count': item['count'],
                        'total_cost': float(item['total_cost']),
                    }
                    for item in data
                ]
            })
       
        elif chart_type == 'radar':
            # Simple asset count by location
            data = queryset.values('Location').annotate(
                asset_count=Count('AssetID')
            ).order_by('-asset_count')  # Sort by count for better visualization
           
            # Create single dataset with locations as labels
            return JsonResponse({
                'labels': [item['Location'] or 'Unknown' for item in data],
                'datasets': [{
                    'label': 'Asset Count',
                    'data': [item['asset_count'] for item in data],
                    'borderColor': '#3498db',
                    'backgroundColor': '#3498db50'
                }]
            })
       
        elif chart_type == 'polar':
            # Asset type distribution
            data = queryset.values('AssetType').annotate(count=Count('AssetID'))
            return JsonResponse({
                'labels': [item['AssetType'] for item in data],
                'datasets': [{
                    'data': [item['count'] for item in data],
                    'backgroundColor': ['#3498db', '#e74c3c']
                }]
            })
       
        elif chart_type == 'bubble':
            # Use the FILTERED QUERYSET
            data = queryset.values('Category').annotate(
                total_cost=Sum('Cost'),
                asset_count=Count('AssetID')
            ).order_by('Category')
           
            # Prepare bubble chart data points
            categories = []
            datapoints = []
            colors = ['#3498db', '#2ecc71', '#e74c3c', '#f39c12', '#9b59b6']
           
            for index, item in enumerate(data):
                categories.append(item['Category'])
                datapoints.append({
                    'x': index,  # X-axis position (category index)
                    'y': float(item['total_cost']),  # Y-axis value (total cost)
                    'r': item['asset_count'] * 5  # Bubble size (asset count scaled)
                })
           
            return JsonResponse({
                'labels': categories,
                'datasets': [{
                    'label': 'Cost by Category',
                    'data': datapoints,
                    'backgroundColor': colors[:len(datapoints)]
                }]
            })
       
        elif chart_type == 'horizontalBar':
            try:
                # Use Django's timezone aware today
                today = timezone.now().date()
               
                # Subquery to calculate months since purchase
                months_since_purchase = Func(
                    F('PurchaseDate'),
                    Value(today),
                    function='DATEDIFF',
                    template='%(function)s(month, %(expressions)s)',
                    output_field=IntegerField()
                )
               
                data = queryset.annotate(
                    # Calculate warranty months left
                    warranty_months_left=ExpressionWrapper(
                        Greatest(
                            Value(0),
                            Cast(F('Warranty') * 12.0, output_field=FloatField()) -
                            Cast(months_since_purchase, output_field=FloatField())
                        ),
                        output_field=FloatField()
                    )
                ).order_by('-warranty_months_left')[:5]
               
                # Prepare the response
                return JsonResponse({
                    'labels': [
                        item.AssetName
                        for item in data
                    ],
                    'datasets': [{
                        'label': 'Months Left on Warranty',
                        'data': [
                            float(item.warranty_months_left)
                            for item in data
                        ],
                        'backgroundColor': '#3498db'
                    }]
                })
            except Exception as e:
                # Detailed error logging
                import traceback
                print("Full error traceback:")
                traceback.print_exc()
                return JsonResponse({'error': str(e)}, status=500)
       
        elif chart_type == 'stacked':
            # Asset usage across departments (using AssetRequest as a proxy)
            data = AssetRequest.objects.values('Status').annotate(
                pending=Count('RequestId', filter=Q(Status='Pending')),
                approved=Count('RequestId', filter=Q(Status='Approved')),
                completed=Count('RequestId', filter=Q(Status='Completed')),
                rejected=Count('RequestId', filter=Q(Status='Rejected')),
                surrendered=Count('RequestId', filter=Q(Status='Surrendered')),
 
            )
            return JsonResponse({
                'labels': [item['Status'] for item in data],
                'datasets': [
                    {
                        'label': 'Pending Requests',
                        'data': [item['pending'] for item in data],
                        'backgroundColor': '#3498db'
                    },
                    {
                        'label': 'Approved Requests',
                        'data': [item['approved'] for item in data],
                        'backgroundColor': '#3498db'
                    },
                    {
                        'label': 'Completed Requests',
                        'data': [item['completed'] for item in data],
                        'backgroundColor': '#2ecc71'
                    },
                    {
                        'label': 'Rejected Requests',
                        'data': [item['rejected'] for item in data],
                        'backgroundColor': '#e74c3c'
                    },
                    {
                        'label': 'Surrendered Requests',
                        'data': [item['surrendered'] for item in data],
                        'backgroundColor': '#e74c3c'
                    }
                ]
            })
       
        elif chart_type == 'scatter':
            # Maintenance frequency vs Cost
            data = queryset.values('Category', 'Cost', 'idle_days')
            return JsonResponse({
                'datasets': [{
                    'label': item['Category'],
                    'data': [{
                        'x': float(item['Cost']),
                        'y': item['idle_days']
                    }],
                    'backgroundColor': f'#{hash(item["Category"]):06x}'
                } for item in data]
            })
       
        elif chart_type == 'area':
            # Asset value depreciation by type (Hardware/Software)
            data = queryset.annotate(year=TruncYear('PurchaseDate')).values('year', 'AssetType').annotate(
                total_value=Sum('Cost')
            ).order_by('year', 'AssetType')
 
            # Organize data for the chart
            labels = sorted(set(item['year'].year for item in data))
           
            # Separate the data by asset type
            hardware_data = {item['year'].year: float(item['total_value']) for item in data if item['AssetType'] == 'Hardware'}
            software_data = {item['year'].year: float(item['total_value']) for item in data if item['AssetType'] == 'Software'}
           
            # Create two separate datasets
            datasets = [
                {
                    'label': 'Hardware Total Value',
                    'data': [hardware_data.get(year, 0) for year in labels],
                    'backgroundColor': 'rgba(52, 152, 219, 0.5)',  # Light blue with transparency
                    'borderColor': '#3498db',
                    'borderWidth': 2,
                    'fill': True,
                    'yAxisID': 'y'  # Primary y-axis
                },
                {
                    'label': 'Software Total Value',
                    'data': [software_data.get(year, 0) for year in labels],
                    'backgroundColor': 'rgba(231, 76, 60, 0.8)',  # More opaque red
                    'borderColor': '#e74c3c',
                    'borderWidth': 4,  # Thicker border
                    'pointRadius': 6,  # Larger points
                    'pointBackgroundColor': '#e74c3c',
                    'pointBorderColor': '#fff',
                    'pointBorderWidth': 2,
                    'fill': 'origin',  # Fill to axis
                    'yAxisID': 'y1'  # Secondary y-axis for software
                }
            ]
           
            # Enhanced chart options with clearer visibility settings
            chart_options = {
                'responsive': True,
                'maintainAspectRatio': False,
                'scales': {
                    'y': {
                        'position': 'left',
                        'title': {
                            'display': True,
                            'text': 'Hardware Value ($)',
                            'font': {
                                'size': 14,
                                'weight': 'bold'
                            }
                        },
                        'ticks': {
                            'beginAtZero': True
                        }
                    },
                    'y1': {
                        'position': 'right',
                        'title': {
                            'display': True,
                            'text': 'Software Value ($)',
                            'font': {
                                'size': 14,
                                'weight': 'bold',
                                'color': '#e74c3c'  # Matching software color
                            }
                        },
                        'ticks': {
                            'beginAtZero': True,
                            'color': '#e74c3c'  # Color the tick marks to match
                        },
                        'grid': {
                            'drawOnChartArea': False  # Only show grid lines for primary axis
                        }
                    }
                },
                'plugins': {
                    'tooltip': {
                        'mode': 'index',
                        'intersect': False
                    },
                    'legend': {
                        'position': 'top',
                        'labels': {
                            'font': {
                                'size': 14
                            },
                            'usePointStyle': True
                        }
                    }
                }
            }
           
            # Consider drawing software as a line chart for better visibility
            datasets[1]['type'] = 'line'  # Change the type to line for the software dataset
           
            return JsonResponse({
                'labels': labels,
                'datasets': datasets,
                'options': chart_options
            })
       
        
        elif chart_type == 'gauge':
            # Budget utilization
            total_cost = queryset.aggregate(total=Sum('Cost'))['total'] or 0
            budget_limit = 1000000  # Adjust this based on your actual budget
            utilization = min((total_cost / budget_limit) * 100, 100)
           
            return JsonResponse({
                'labels': ['Utilized', 'Remaining'],
                'datasets': [{
                    'data': [utilization, 100 - utilization],
                    'backgroundColor': ['#3498db', '#ecf0f1']
                }]
            })
       
        return JsonResponse({'error': 'Invalid chart type'}, status=400)
    except Exception as e:
        # Log the full error for debugging
        import traceback
        print(traceback.format_exc())
        return JsonResponse({'error': str(e)}, status=500)
# Add to views.py
from django.http import JsonResponse
from datetime import date, datetime  # ✅ Fixed import
import logging
 
logger = logging.getLogger(__name__)
 
def get_asset_data(request):
    try:
        user_id = request.session.get('user_id')
        if not user_id:
            return JsonResponse({"error": "Not authenticated"}, status=401)
       
        assets = Asset.objects.all().values()
        asset_list = list(assets)
 
        # Convert datetime objects to ISO format
        for asset in asset_list:
            for key, value in asset.items():
                if isinstance(value, (date, datetime)):  # ✅ No more attribute error
                    asset[key] = value.isoformat()
       
        return JsonResponse(asset_list, safe=False)
   
    except Exception as e:
        logger.error(f"Error in get_asset_data: {e}", exc_info=True)
        return JsonResponse({"error": "Internal Server Error"}, status=500)


# views.py
import pandas as pd
from django.shortcuts import render, redirect
from django.contrib import messages
from .models import Asset, Vendor, Category, AssetNumberTracking
from django.db import transaction
from datetime import datetime
import os
import uuid

# Set up logger
logger = logging.getLogger(__name__)
import pandas as pd
from django.shortcuts import render, redirect
from django.contrib import messages
from .models import Asset, Vendor, Category, AssetNumberTracking
from django.db import transaction
from datetime import datetime
import os
import uuid
import tempfile
import logging
# Set up logger
logger = logging.getLogger(__name__)
# Set up logger
logger = logging.getLogger(__name__)
 

import os
import pandas as pd
from datetime import datetime, date
import tempfile
import traceback
from django.shortcuts import render, redirect
from django.contrib import messages
from django.db import transaction
from .models import Vendor, Category, Asset, AssetNumberTracking
def upload_excel(request):
    import traceback
    import pandas as pd
    from datetime import datetime, date
    import os
    import tempfile
    from django.db import transaction
    from django.contrib import messages
    from django.shortcuts import redirect, render
    from app.models import Asset, Vendor, Category, AssetNumberTracking

    print("=== STARTING EXCEL UPLOAD PROCESS ===")
    
    if request.method == 'POST' and request.FILES.get('excel_file'):
        excel_file = request.FILES['excel_file']
        print(f"Received file: {excel_file.name}, Size: {excel_file.size} bytes")

        if not excel_file.name.endswith(('.xls', '.xlsx')):
            messages.error(request, 'Please upload an Excel file (.xls or .xlsx)')
            return redirect('upload_excel')

        try:
            # Save to temporary file
            with tempfile.NamedTemporaryFile(suffix='.xlsx', delete=False) as temp_file:
                file_path = temp_file.name
                for chunk in excel_file.chunks():
                    temp_file.write(chunk)

            df = pd.read_excel(file_path)
            df.columns = df.columns.str.strip()

            # Fix column names
            COLUMN_RENAMES = {
                'Warrenty': 'Warranty',
                'Classification': 'Asset Classification',
                'Model': 'Asset Model',
                'Storage  Location': 'Storage Location',
                'Stoarge type': 'Storage Type'
            }
            df.rename(columns=COLUMN_RENAMES, inplace=True)

            required_fields = ['Asset Name', 'Asset Number', 'Category', 'Vendor']
            missing_fields = [col for col in required_fields if col not in df.columns]
            if missing_fields:
                messages.error(request, f'Missing required columns: {", ".join(missing_fields)}')
                return redirect('upload_excel')

            success_count = 0

            # Helper to clean string/number values
            def clean_val(val):
                if pd.isnull(val):
                    return None
                if isinstance(val, float) and val.is_integer():
                    return str(int(val))  # remove ".0"
                return str(val).strip()

            # Start atomic transaction
            with transaction.atomic():
                for index, row in df.iterrows():
                    try:
                        get_val = lambda k: row.get(k) if pd.notnull(row.get(k)) else None

                        vendor_name = get_val('Vendor')
                        category_name = get_val('Category')
                        raw_asset_number = get_val('Asset Number')

                        # ✅ Fix asset number handling
                        asset_number = clean_val(raw_asset_number)
                        if asset_number and asset_number.lower() in ['nan', 'none', '', 'null']:
                            asset_number = None

                        # Check for duplicate
                        if asset_number and Asset.objects.filter(AssetNumber=asset_number).exists():
                            raise ValueError(f"Duplicate Asset Number '{asset_number}' found at row {index + 2}")

                        # Auto-generate if missing
                        if not asset_number or asset_number == 'Automatic Generated ID':
                            tracking, created = AssetNumberTracking.objects.get_or_create(
                                IsUsed=False,
                                defaults={'LastGeneratedNumber': 1, 'Prefix': 'INT-'}
                            )
                            if not created:
                                tracking.LastGeneratedNumber += 1
                                tracking.save()
                            asset_number = f"{tracking.Prefix}{tracking.LastGeneratedNumber:06d}"

                        # Extract other fields
                        asset_name = get_val('Asset Name')
                        bond_number = clean_val(get_val('Bond Number'))
                        purchase_order = clean_val(get_val('Purchase Order'))
                        purchase_requisition = clean_val(get_val('Purchase Requisition'))
                        capex = clean_val(get_val('Capex'))
                        serial_number = clean_val(get_val('Serial Number'))
                        part_number = clean_val(get_val('Part Number'))
                        asset_type = clean_val(get_val('Asset Type'))
                        asset_status = clean_val(get_val('Asset Status'))
                        asset_model = clean_val(get_val('Asset Model'))
                        asset_bond_type = clean_val(get_val('Asset Bond Type'))
                        specification = clean_val(get_val('Specification'))
                        asset_provider = clean_val(get_val('Asset Provider')) or 'BGSW'
                        asset_classification = clean_val(get_val('Asset Classification')) or 'Consumables'
                        warranty = clean_val(get_val('Warranty'))
                        location = clean_val(get_val('Location'))
                        storage_location = clean_val(get_val('Storage Location'))
                        rack_number = clean_val(get_val('Rack Number'))
                        storage_type = clean_val(get_val('Storage Type'))
                        cost = clean_val(get_val('Cost'))

                        # ✅ Fix Purchase Date parsing
                        purchase_date = None
                        pd_raw = get_val('Purchase Date')
                        if pd_raw == 'Random Date':
                            from random import randint
                            purchase_date = date(randint(2020, 2025), randint(1, 12), randint(1, 28))
                        elif pd_raw:
                            if isinstance(pd_raw, (datetime, date, pd.Timestamp)):
                                purchase_date = pd_raw.date() if hasattr(pd_raw, 'date') else pd_raw
                            else:
                                try:
                                    purchase_date = pd.to_datetime(str(pd_raw)).date()
                                except Exception:
                                    print(f"⚠️ Could not parse date '{pd_raw}' (row {index + 2})")

                        # Warehouse formatting
                        warehouse_parts = []
                        if storage_location:
                            warehouse_parts.append(f"Location: {storage_location}")
                        if rack_number:
                            warehouse_parts.append(f"Rack: {rack_number}")
                        if storage_type:
                            warehouse_parts.append(f"Type: {storage_type}")
                        warehouse = ", ".join(warehouse_parts) if warehouse_parts else None

                        # Vendor & Category creation
                        vendor = Vendor.objects.get_or_create(
                            VendorName=vendor_name, defaults={'VendorContact': ''}
                        )[0] if vendor_name else None

                        category = Category.objects.get_or_create(
                            Name=category_name
                        )[0] if category_name else None

                        # Save Asset
                        asset = Asset(
                            AssetName=asset_name,
                            AssetNumber=asset_number,
                            BondNumber=bond_number,
                            PurchaseOrder=purchase_order,
                            PurchaseRequisition=purchase_requisition,
                            Capex=capex,
                            SerialNumber=serial_number,
                            PartNumber=part_number,
                            AssetType=asset_type,
                            AssetStatus=asset_status,
                            AssetModel=asset_model,
                            AssetBondType=asset_bond_type,
                            Specification=specification,
                            AssetProvider=asset_provider,
                            AssetClassification=asset_classification,
                            PurchaseDate=purchase_date,
                            Cost=cost,
                            Warranty=warranty,
                            Location=location,
                            Warehouse=warehouse,
                        )
                        if vendor:
                            asset.VendorID = vendor
                        if category:
                            asset.cid = category

                        asset.save()
                        success_count += 1

                    except Exception as e:
                        messages.error(request, f"Row {index+2}: {str(e)}. Import aborted.")
                        raise  # rollback

            if success_count:
                messages.success(request, f'Successfully imported {success_count} assets.')

        except Exception as e:
            if not isinstance(e, transaction.TransactionManagementError):
                messages.error(request, f'Error: {str(e)}. Import aborted.')
            traceback.print_exc()
        finally:
            if os.path.exists(file_path):
                os.remove(file_path)

        return redirect('upload_excel')

    return render(request, 'admin/upload_excel.html')





























