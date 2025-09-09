from django.core.management.base import BaseCommand
from datetime import date, timedelta
from app.models import Asset, AssetRequest

class Command(BaseCommand):
    help = 'Update idle days for all assets'

    def handle(self, *args, **kwargs):
        today = date.today()
        yesterday = today - timedelta(days=1)

        for asset in Asset.objects.all():
            # Check if the asset is currently in use (within StartDate and EndDate)
            active_requests = AssetRequest.objects.filter(
                AssetID=asset,
                Status='Completed',
                StartDate__lte=today,
                EndDate__gte=today
            )
            if active_requests.exists():
                # Set idle days to zero as the asset is in use
                asset.idle_days = 0
                asset.save()
                continue

            # Check if the asset's EndDate was yesterday
            recently_ended_requests = AssetRequest.objects.filter(
                AssetID=asset,
                Status='Completed',
                EndDate=yesterday
            )
            if recently_ended_requests.exists():
                # Reset idle days to 1 (or 0, depending on your definition)
                asset.idle_days = 1  # Change to 0 if you want idle days to start at 0
                asset.save()
                continue

            # Check if today is the StartDate of an approved request
            starting_requests = AssetRequest.objects.filter(
                AssetID=asset,
                Status='Completed',
                StartDate=today
            )
            if starting_requests.exists():
                # Reset idle days to zero as the asset is now in use
                asset.idle_days = 0
                asset.save()
                continue

            # Check if the asset was surrendered
            surrendered_requests = AssetRequest.objects.filter(
                AssetID=asset,
                Status='Surrendered',
                SurrenderDate__lt=today
            ).order_by('-SurrenderDate')  # Order by latest surrender date

            if surrendered_requests.exists():
                # Get the latest surrender date
                latest_surrender_date = surrendered_requests.first().SurrenderDate
                idle_days_since_surrender = (today - latest_surrender_date).days
                asset.idle_days = idle_days_since_surrender
            else:
                # Increment idle days normally (if no surrender date exists)
                asset.idle_days += 1

            # Save the updated idle days
            asset.save()

        self.stdout.write(self.style.SUCCESS('Idle days updated successfully'))