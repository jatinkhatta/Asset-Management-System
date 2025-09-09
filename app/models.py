from django.db import models
from django.utils.timezone import now

from django.core.validators import RegexValidator

class User(models.Model):
    UserId = models.AutoField(primary_key=True)
    username = models.CharField(max_length=255)
    password_hash = models.CharField(max_length=255)
    email = models.EmailField(unique=True)
    phone = models.CharField(
        max_length=15,
        validators=[RegexValidator(r'^\+?\d{10,15}$', message="Enter a valid phone number.")],
        null=True,
        blank=True
    )
    role = models.CharField(max_length=50, default='USER')
    created_at = models.DateTimeField(default=now)
    last_login = models.DateTimeField(null=True, blank=True)
    
    REQUIRED_FIELDS = ['email', 'role', 'password']
    
    def __str__(self):
        return f"UserID: {self.UserId}"

    class Meta:
        db_table = 'user'


from django.db import models

from django.db import models

class Vendor(models.Model):
    VendorId = models.AutoField(primary_key=True)
    VendorName = models.CharField(max_length=255)
    VendorContact = models.CharField(max_length=255)
    VendorNotes = models.TextField(null=True, blank=True)
    BgswVendorId = models.CharField(max_length=255, null=True, blank=True)

    def __str__(self):
        return f"Vendor Name: {self.VendorName} (ID: {self.VendorId})"

    class Meta:
        db_table = 'Vendor'  # Explicitly matches SQL Server table name


class Image(models.Model):
    ImageId = models.AutoField(primary_key=True)
    ImagePath = models.CharField(max_length=255)
    UploadDate = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Image Path: {self.ImagePath} (ID: {self.ImageId})"

    class Meta:
        db_table = 'Image'


class Document(models.Model):
    DocumentId = models.AutoField(primary_key=True)
    DocumentPath = models.CharField(max_length=255)
    UploadDate = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Document Path: {self.DocumentPath} (ID: {self.DocumentId})"

    class Meta:
        db_table = 'Document'


class Maintenance(models.Model):
    MaintenanceId = models.AutoField(primary_key=True)
    LastMaintenanceDate = models.DateField()
    MaintenanceInterval = models.IntegerField()  # Interval in months
    MaintenanceNotes = models.TextField(null=True, blank=True)

    @property
    def NextMaintenanceDate(self):
        from datetime import timedelta
        return self.LastMaintenanceDate + timedelta(days=self.MaintenanceInterval * 30)

    def __str__(self):
        return f"Maintenance ID: {self.MaintenanceId}"

    class Meta:
        db_table = 'Maintenance'


class Calibration(models.Model):
    CalibrationId = models.AutoField(primary_key=True)
    LastCalibrationDate = models.DateField()
    CalibrationAuthority = models.CharField(max_length=255, null=True, blank=True)
    certificate = models.CharField(max_length=255)
    CalibrationNotes = models.TextField(null=True, blank=True)
    CalibrationInterval = models.IntegerField()  # Interval in months

    @property
    def NextCalibrationDate(self):
        from datetime import timedelta
        return self.LastCalibrationDate + timedelta(days=self.CalibrationInterval * 30)

    def __str__(self):
        return f"Calibration ID: {self.CalibrationId}"

    class Meta:
        db_table = 'Calibration'
       

class Category(models.Model):
    """
    Model to store predefined and custom categories.
    """
    CategoryID = models.AutoField(primary_key=True)
    Name = models.CharField(max_length=255, unique=True)  # Allows any custom category name

    def __str__(self):
        return self.Name

    class Meta:
        db_table = 'Category'

from django.db import models

class Asset(models.Model):
    """
    Complete Asset model supporting both Hardware and Software assets.
    """
    # Choices for dropdown fields
    ASSET_TYPE_CHOICES = [
        ('Hardware', 'Hardware'),
        ('Software', 'Software')
    ]
    ASSET_STATUS_CHOICES = [
        ('Working', 'Working'),
        ('Under Maintenance', 'Under Maintenance'),
        ('Not Working', 'Not Working')
    ]
    ASSET_PROVIDER_CHOICES = [
        ('CSI-Borrowed', 'CSI-Borrowed'),
        ('CSI-Purchased', 'CSI-Purchased'),
        ('BGSW', 'BGSW')
    ]
    ASSET_CLASSIFICATION_CHOICES = [
        ('Consumables', 'Consumables'),
        ('Non Consumables', 'Non Consumables')
    ]
    ASSET_AVAILABILITY_CHOICES = [
        ('Available', 'Available'),
        ('In Use', 'In Use')
    ]
    ASSET_BOND_CHOICES = [
        ('Bonded', 'Bonded'),
        ('Non Bonded', 'Non Bonded')
    ]
    SOFTWARE_CATEGORY_CHOICES = [
        ('Shared License', 'Shared License'),
        ('PC Based License', 'PC Based License'),
        ('User Based License', 'User Based License'),
        ('Location Based License', 'Location Based License')
    ]

    # Common Fields
    AssetID = models.AutoField(primary_key=True)
    AssetBondType = models.CharField(max_length=50, choices=ASSET_BOND_CHOICES, null=True, blank=True)
    AssetName = models.CharField(max_length=255)  # Software Name or Hardware Name
    Category = models.CharField(max_length=255, null=True, blank=True)  # Populated dynamically
    cid = models.ForeignKey(
        'Category',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        db_column='cid',
        related_name='assets'
    )
    AssetNumber = models.CharField(max_length=50, unique=True, null=True, blank=True)
    BondNumber = models.CharField(max_length=100, null=True, blank=True)
    PurchaseOrder = models.CharField(max_length=100, null=True, blank=True)
    PurchaseRequisition = models.CharField(max_length=100, null=True, blank=True)
    Capex = models.CharField(max_length=100, null=True, blank=True)
    SerialNumber = models.CharField(max_length=50, null=True, blank=True)
    PartNumber = models.CharField(max_length=50, null=True, blank=True)
    AssetType = models.CharField(max_length=50, choices=ASSET_TYPE_CHOICES, default='Hardware')
    AssetStatus = models.CharField(max_length=50, choices=ASSET_STATUS_CHOICES, default='Working')
    AssetModel = models.CharField(max_length=255, null=True, blank=True)
    AssetAvailability = models.CharField(
        max_length=20, choices=ASSET_AVAILABILITY_CHOICES, default='Available'
    )
    Warehouse = models.CharField(max_length=255, null=True, blank=True)
    Location = models.CharField(max_length=255, null=True, blank=True)
    AssetProvider = models.CharField(max_length=50, choices=ASSET_PROVIDER_CHOICES, default='BGSW')
    AssetClassification = models.CharField(
        max_length=50, choices=ASSET_CLASSIFICATION_CHOICES, default='Consumables'
    )
    PurchaseDate = models.DateField(null=True, blank=True)
    Cost = models.DecimalField(max_digits=18, decimal_places=2, null=True, blank=True)
    Warranty = models.IntegerField(null=True, blank=True)  # Warranty in months
    BondExpiryDate = models.DateField(null=True, blank=True)
    Specification = models.TextField(null=True, blank=True)
    RequiresCalibration = models.BooleanField(default=False)

    # Software-Specific Fields
    SoftwareVersion = models.CharField(max_length=50, null=True, blank=True)
    RenewDate = models.DateField(null=True, blank=True)

    # Foreign Keys for Related Tables
    VendorID = models.ForeignKey(
        'Vendor', on_delete=models.CASCADE, db_column='VendorID', null=True, blank=True
    )
    ImageID = models.ForeignKey(
        'Image', on_delete=models.CASCADE, null=True, blank=True, db_column='ImageID'
    )
    DocumentID = models.ForeignKey(
        'Document', on_delete=models.CASCADE, null=True, blank=True, db_column='DocumentID'
    )
    MaintenanceID = models.ForeignKey(
        'Maintenance', on_delete=models.CASCADE, null=True, blank=True, db_column='MaintenanceID'
    )
    CalibrationID = models.ForeignKey(
        'Calibration', on_delete=models.CASCADE, null=True, blank=True, db_column='CalibrationID'
    )

    # Additional Fields
    idle_days = models.IntegerField(default=0)
    max_idle_days = models.IntegerField(default=0)
    CreationDate = models.DateTimeField(auto_now_add=True)

    def save(self, *args, **kwargs):
        """
        Override the save method to populate the `Category` field based on the asset type.
        """
        if self.AssetType == 'Software':
            # Directly populate the Category field for software assets
            if self.Category not in [choice[0] for choice in self.SOFTWARE_CATEGORY_CHOICES]:
                raise ValueError("Invalid software category.")
        elif self.cid:
            # Populate Category field from the linked Category table for hardware assets
            self.Category = self.cid.Name
        else:
            self.Category = None  # Clear Category if cid is not set

        super().save(*args, **kwargs)

    def __str__(self):
        return f"Asset Name: {self.AssetName} (ID: {self.AssetID})"

    class Meta:
        db_table = 'Asset'
class AssetNumberTracking(models.Model):
    LastGeneratedNumber = models.IntegerField(default=0)
    LastGeneratedDate = models.DateTimeField(auto_now_add=True)
    Prefix = models.CharField(max_length=10, default='INT-')
    IsUsed = models.BooleanField(default=False)  # New field to track usage

    def __str__(self):
        return f"{self.Prefix}{self.LastGeneratedNumber}"

    class Meta:
        db_table = 'AssetNumberTracking'


from django.db import models
from django.conf import settings
from django.core.exceptions import ValidationError

class AssetRequest(models.Model):
    STATUS_CHOICES = [
        ('Pending', 'Pending'),
        ('Approved', 'Approved'),
        ('Rejected', 'Rejected'),
        ('Completed','Completed'),
        ('ReturnRequested', 'Return Requested'),
        ('ReturnAccepted', 'Return Accepted'),
        ('ReturnReceived', 'Return Received'),
        ('Surrendered', 'Surrendered'),
    ]

    RequestId = models.AutoField(primary_key=True)
    UserId= models.ForeignKey(User, on_delete=models.CASCADE, db_column='UserId')
    AssetID = models.ForeignKey(
        'Asset',
        on_delete=models.CASCADE,
        db_column='AssetID'  # Explicitly set the column name
    )
    Status = models.CharField(max_length=50, choices=STATUS_CHOICES, default='Pending')
    StartDate = models.DateField()
    EndDate = models.DateField()
    Purpose = models.TextField(blank=True)
    RequestedAt = models.DateTimeField(auto_now_add=True)
    SurrenderDate = models.DateField(null=True, blank=True)

    def __str__(self):
        return f"Request {self.RequestId} - {self.AssetID} ({self.Status})"

    class Meta:
        db_table = 'AssetRequest'

class RequestStage(models.Model):
    STAGE_CHOICES = [
        ('Request', 'Request'),
        ('Approve', 'Approve'),
        ('Reject', 'Reject'),
        ('Issue', 'Issue'),
        ('Acknowledge', 'Acknowledge'),
        ('ReturnRequest', 'Return Request'),
        ('ReturnAccept', 'Return Accept'),
        ('ReturnReceive', 'Return Receive'),
        ('ReturnClose', 'Return Close'),
    ]

    StageId = models.AutoField(primary_key=True)
    RequestId = models.ForeignKey(AssetRequest, on_delete=models.CASCADE, related_name='stages')
    StageName = models.CharField(max_length=50, choices=STAGE_CHOICES)
    StageDate = models.DateTimeField(auto_now_add=True)
    StageBy =   models.ForeignKey(User, on_delete=models.CASCADE, db_column='UserId')
    Comment = models.TextField(blank=True)

    class Meta:
        db_table = 'RequestStage'
        ordering = ['StageDate']

    def clean(self):
        super().clean()
        
        valid_transitions = {
            'Request': ['Pending'],
            'Approve': ['Pending'],
            'Reject': ['Pending', 'Approved', 'ReturnRequested'],
            'Issue': ['Approved'],
            'Acknowledge': ['Approved'],
            'ReturnRequest': ['ReturnRequested', 'Completed'],  # Allow transition from Completed
            'ReturnAccept': ['ReturnRequested'],
            'ReturnReceive': ['ReturnAccepted'],
            'ReturnClose': ['ReturnReceived'],
        }

        if self.StageName not in valid_transitions:
            raise ValidationError(f"Invalid stage: {self.StageName}")

        if self.RequestId.Status not in valid_transitions[self.StageName]:
            raise ValidationError(
                f"Invalid transition: {self.RequestId.Status} → {self.StageName}"
            )

    def save(self, *args, **kwargs):
        self.full_clean()  # Enforce validation rules

        if self.RequestId.Status in ['Rejected', 'Surrendered']:
            raise ValidationError("Cannot modify completed requests")

        status_map = {
            'Approve': 'Approved',
            'Reject': 'Rejected',
            'ReturnRequest': 'ReturnRequested',
            'ReturnAccept': 'ReturnAccepted',
            'ReturnReceive': 'ReturnReceived',
            'ReturnClose': 'Surrendered',
        }

        if new_status := status_map.get(self.StageName):
            self.RequestId.Status = new_status

            if self.StageName == 'ReturnClose':
                import datetime
                self.RequestId.SurrenderDate = datetime.date.today()

            self.RequestId.save()

        super().save(*args, **kwargs) 



class ReportConfiguration(models.Model):
    name = models.CharField(max_length=255, unique=True)  # Unique name for the report
    json_data = models.CharField(max_length=255)  
    comment = models.TextField(blank=True, null=True)  # Optional comment
    created_at = models.DateTimeField(auto_now_add=True)  # Timestamp when the report was created
    updated_at = models.DateTimeField(auto_now=True)  # Timestamp when the report was last updated

    def __str__(self):
        return self.name