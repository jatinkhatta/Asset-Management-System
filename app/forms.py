from django import forms
from .models import User,Asset

class registerForm(forms.ModelForm):
    password = forms.CharField(widget=forms.PasswordInput, label="Password")

    class Meta:
        model = User
        fields = ['username', 'email', 'phone', 'password']  # <-- Added 'phone'

    def clean_username(self):
        username = self.cleaned_data.get('username')
        if User.objects.filter(username=username).exists():
            raise forms.ValidationError('Username already exists. Please choose a different one.')
        return username

from django import forms
from .models import Category

class AddAssetForm(forms.Form):
    # Fields for the form
    asset_bond_type = forms.CharField(max_length=255, required=True, label="Asset Bond Type")
    assetName = forms.CharField(max_length=255, required=True, label="Asset Name")
    

    # Hidden field for cid (foreign key to Category)
    cid = forms.ModelChoiceField(
        queryset=Category.objects.all(),
        required=True,
        widget=forms.HiddenInput()
    )

    # Visible field for category name (read-only)
    category = forms.CharField(
        max_length=255,
        required=False,
        widget=forms.TextInput(attrs={'readonly': 'readonly'}),
        label="Category"
    )

    assetNumber = forms.CharField(max_length=255, required=True, label="Asset Number")
    bondNumber = forms.CharField(max_length=255, required=False, label="Bond Number")
    purchaseOrder = forms.CharField(max_length=255, required=False, label="Purchase Order")
    purchaseRequisition = forms.CharField(max_length=255, required=False, label="Purchase Requisition")
    capex = forms.CharField(max_length=255, required=False, label="Capex")
    serialNumber = forms.CharField(max_length=255, required=False, label="Serial Number")
    partNumber = forms.CharField(max_length=255, required=True, label="Part Number")
    assetType = forms.CharField(max_length=255, required=True, label="Asset Type")
    assetStatus = forms.CharField(max_length=255, required=True, label="Asset Status")
    warehouse = forms.CharField(max_length=255, required=True, label="Warehouse")
    location = forms.CharField(max_length=255, required=True, label="Location")
    assetProvider = forms.CharField(max_length=255, required=True, label="Asset Provider")
    assetClassification = forms.CharField(max_length=255, required=True, label="Asset Classification")
    assetModel = forms.CharField(max_length=255, required=True, label="Asset Model")
    purchaseDate = forms.DateField(required=True, widget=forms.TextInput(attrs={'type': 'date'}))
    cost = forms.DecimalField(required=True, max_digits=10, decimal_places=2, label="Cost")
    warranty = forms.IntegerField(required=True, label="Warranty (Months)")
    bondExpiryDate = forms.DateField(required=False, widget=forms.TextInput(attrs={'type': 'date'}))
    specification = forms.CharField(widget=forms.Textarea, required=False)
    requiresCalibration = forms.BooleanField(required=False)
    image = forms.ImageField(required=False)
    documents = forms.FileField(required=False)

    # Fields for Vendor
    vendorName = forms.CharField(max_length=255, required=False, label="Vendor Name")
    vendorContact = forms.CharField(max_length=255, required=False, label="Vendor Contact")
    description = forms.CharField(widget=forms.Textarea, required=False, label="Vendor Notes")

    # Fields for Maintenance
    lastMaintenanceDate = forms.DateField(required=False, widget=forms.TextInput(attrs={'type': 'date'}))
    maintenanceInterval = forms.IntegerField(required=False, label="Maintenance Interval (Months)")

    # Fields for Calibration
    lastCalibrationDate = forms.DateField(required=False, widget=forms.TextInput(attrs={'type': 'date'}))
    calibrationAuthority = forms.CharField(max_length=255, required=False, label="Calibration Authority")
    calibrationNotes = forms.CharField(widget=forms.Textarea, required=False)
    calibrationInterval = forms.IntegerField(required=False, label="Calibration Interval (Months)")
    calibrationCertificate = forms.FileField(required=False)


from django import forms
from .models import Asset
from django import forms
from .models import Asset
class SoftwareAssetForm(forms.ModelForm):
    """
    Form for adding software assets.
    """
    class Meta:
        model = Asset
        fields = [
            'AssetName',
            'SoftwareVersion',
            'Category',
            'AssetProvider',
            'PurchaseDate',
            'RenewDate',
            'Cost',
            'AssetBondType',  # New field added here
        ]
        widgets = {
            'AssetName': forms.TextInput(attrs={'required': True}),
            'SoftwareVersion': forms.TextInput(attrs={'required': True}),
            'Category': forms.Select(choices=Asset.SOFTWARE_CATEGORY_CHOICES, attrs={'required': True}),
            'AssetProvider': forms.Select(choices=Asset.ASSET_PROVIDER_CHOICES, attrs={'required': True}),
            'PurchaseDate': forms.DateInput(attrs={'type': 'date', 'required': True}),
            'RenewDate': forms.DateInput(attrs={'type': 'date'}),
            'Cost': forms.NumberInput(attrs={'required': True}),
            'AssetBondType': forms.HiddenInput(),  # Hidden so user doesn't change it
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['AssetBondType'].initial = 'Non Bonded Assets'


    def clean_Category(self):
        """
        Validate that the selected Category is valid for software assets.
        """
        category = self.cleaned_data.get('Category')
        valid_categories = [choice[0] for choice in Asset.SOFTWARE_CATEGORY_CHOICES]
        if category not in valid_categories:
            raise forms.ValidationError("Invalid software category.")
        return category