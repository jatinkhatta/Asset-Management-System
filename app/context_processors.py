from datetime import date, timedelta
from django.conf import settings
from .models import AssetRequest, Asset, User

def new_alerts_count(request):
    """
    Context processor to calculate and pass the count of new alerts to all templates.
    """
    # Check if the user is authenticated using the session's user_id
    user_id = request.session.get('user_id')
    print(f"Session user_id: {user_id}")  # Debugging: Print the user_id from the session

    if not user_id:
        print("No user_id found in session. Returning 0 alerts.")  # Debugging: No user_id
        return {'total_new_alerts': 0}

    try:
        # Fetch the user from the custom User model
        user = User.objects.get(UserId=user_id)
        print(f"User fetched successfully: {user}")  # Debugging: Print the fetched user
    except User.DoesNotExist:
        print(f"User with UserId {user_id} does not exist. Returning 0 alerts.")  # Debugging: Invalid user
        return {'total_new_alerts': 0}

    # Get the current date
    today = date.today()
    print(f"Today's date: {today}")  # Debugging: Print today's date

    # Generate all active alert IDs using the helper function
    def get_alert_ids(today):
        alert_ids = set()
        warning_days = 30  # Consistent warning threshold

        # Pending Asset Requests
        requested_assets = AssetRequest.objects.filter(
            Status='Pending',
            EndDate__gte=today
        )
        print(f"Pending Asset Requests count: {requested_assets.count()}")  # Debugging: Count of pending requests
        for req in requested_assets:
            alert_ids.add(f"request_{req.pk}")

        # Maintenance Alerts
        maintenance_assets_qs = Asset.objects.filter(
            MaintenanceID__isnull=False,
            MaintenanceID__LastMaintenanceDate__isnull=False
        ).select_related('MaintenanceID')
        print(f"Maintenance Alerts count: {maintenance_assets_qs.count()}")  # Debugging: Count of maintenance alerts
        for asset in maintenance_assets_qs:
            try:
                interval_days = asset.MaintenanceID.MaintenanceInterval * 30
                next_maintenance_date = asset.MaintenanceID.LastMaintenanceDate + timedelta(days=interval_days)
                if today <= next_maintenance_date <= today + timedelta(days=warning_days):
                    alert_ids.add(f"maint_{asset.pk}")
            except AttributeError:
                print(f"AttributeError encountered for Maintenance Alert on Asset {asset.pk}")  # Debugging: Error handling
                continue

        # Bond Expiry Alerts
        bond_alerts_qs = Asset.objects.filter(
            BondExpiryDate__isnull=False,
            BondExpiryDate__gte=today,
            BondExpiryDate__lte=today + timedelta(days=warning_days)
        )
        print(f"Bond Expiry Alerts count: {bond_alerts_qs.count()}")  # Debugging: Count of bond expiry alerts
        for asset in bond_alerts_qs:
            alert_ids.add(f"bond_{asset.pk}")

        # Software Renewal Alerts
        software_renewal_qs = Asset.objects.filter(
            AssetType='Software',
            RenewDate__isnull=False,
            RenewDate__gte=today,
            RenewDate__lte=today + timedelta(days=warning_days)
        )
        print(f"Software Renewal Alerts count: {software_renewal_qs.count()}")  # Debugging: Count of software renewal alerts
        for asset in software_renewal_qs:
            alert_ids.add(f"sw_{asset.pk}")

        # Warranty Alerts
        warranty_assets_qs = Asset.objects.filter(
            Warranty__isnull=False,
            PurchaseDate__isnull=False
        )
        print(f"Warranty Alerts count: {warranty_assets_qs.count()}")  # Debugging: Count of warranty alerts
        for asset in warranty_assets_qs:
            try:
                warranty_duration_days = int(asset.Warranty) * 365
                warranty_expiry_date = asset.PurchaseDate + timedelta(days=warranty_duration_days)
                if today <= warranty_expiry_date <= today + timedelta(days=warning_days):
                    alert_ids.add(f"warr_{asset.pk}")
            except (ValueError, TypeError):
                print(f"ValueError or TypeError encountered for Warranty Alert on Asset {asset.pk}")  # Debugging: Error handling
                continue

        print(f"Generated current alert IDs: {alert_ids}")  # Debugging: Print all generated alert IDs
        return alert_ids

    # Get viewed alert IDs from the session
    viewed_alert_ids = set(request.session.get('viewed_alert_ids', []))
    print(f"Viewed alert IDs from session: {viewed_alert_ids}")  # Debugging: Print viewed alert IDs

    # Get all currently active alert IDs
    current_alert_ids = get_alert_ids(today)

    # Calculate new alerts
    new_alert_ids = current_alert_ids - viewed_alert_ids
    total_new_alerts = len(new_alert_ids)

    print(f"New alert IDs: {new_alert_ids}")  # Debugging: Print new alert IDs
    print(f"Total new alerts: {total_new_alerts}")  # Debugging: Print total new alerts

    return {'total_new_alerts': total_new_alerts}