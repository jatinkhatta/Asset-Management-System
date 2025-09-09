from django.core.management.base import BaseCommand
from app.models import Asset, AssetRequest
from datetime import date

class Command(BaseCommand):
    help = "Update asset availability based on active asset requests"

    def handle(self, *args, **kwargs):
        self.stdout.write("🔄 Running asset availability update...")

        today = date.today()
        updated_count = 0

        for asset in Asset.objects.all():
            old_status = asset.AssetAvailability

            active_requests = AssetRequest.objects.filter(
                AssetID=asset, StartDate__lte=today, EndDate__gte=today, Status="Completed"
            ).exists()

            asset.AssetAvailability = "In Use" if active_requests else "Available"

            if old_status != asset.AssetAvailability:  
                asset.save()
                updated_count += 1

        self.stdout.write(f"✅ Update completed | {updated_count} assets updated.")
