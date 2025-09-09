from django.shortcuts import redirect
from django.contrib import messages

class RoleBasedAccessMiddleware:
    """Middleware to restrict user access based on role."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        restricted_routes = {
            'USER': ['/Add Asset/', '/Alerts/', '/MaintenancePage/', '/Reports/', '/Asset Inventory/', '/delete_Asset/','/Alerts/','/asset_request_tracking/','/user_management/'],  # Restricted for users
            'ADMIN': []  # Admins have full access
        }

        # Define public routes (no login required)
        public_routes = ['/documentation/']  # Add the documentation route here

        user_role = request.session.get('role')

        # If the requested path is in public routes, allow access without login
        if request.path in public_routes:
            return self.get_response(request)

        # If not logged in, force redirect to login (except login/register)
        if not user_role and request.path not in ['/login/', '/register/']:
            messages.error(request, "Please log in first.")
            return redirect("login")

        # Restrict access based on role
        for role, routes in restricted_routes.items():
            if user_role == role and request.path in routes:
                messages.error(request, "Access denied. You do not have permission.")
                return redirect("User_Asset_Inventory")

        return self.get_response(request)