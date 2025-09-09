from rest_framework import serializers
from .models import Asset, User, Vendor, Image, Document, Maintenance, Calibration, AssetRequest

class VendorSerializer(serializers.ModelSerializer):
    class Meta:
        model = Vendor
        fields = '__all__'

class ImageSerializer(serializers.ModelSerializer):
    class Meta:
        model = Image
        fields = '__all__'

class DocumentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Document
        fields = '__all__'

class MaintenanceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Maintenance
        fields = '__all__'

class CalibrationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Calibration
        fields = '__all__'

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'

class AssetSerializer(serializers.ModelSerializer):
    VendorName = serializers.CharField(source='VendorID.VendorName', read_only=True)
    ImagePath = serializers.CharField(source='ImageID.ImagePath', read_only=True)
    DocumentPath = serializers.CharField(source='DocumentID.DocumentPath', read_only=True)
    LastMaintenanceDate = serializers.DateField(source='MaintenanceID.LastMaintenanceDate', read_only=True)
    NextMaintenanceDate = serializers.SerializerMethodField()
    LastCalibrationDate = serializers.DateField(source='CalibrationID.LastCalibrationDate', read_only=True)
    NextCalibrationDate = serializers.SerializerMethodField()

    class Meta:
        model = Asset
        fields = '__all__'

    def get_NextMaintenanceDate(self, obj):
        if obj.MaintenanceID:
            return obj.MaintenanceID.NextMaintenanceDate
        return None

    def get_NextCalibrationDate(self, obj):
        if obj.CalibrationID:
            return obj.CalibrationID.NextCalibrationDate
        return None

class AssetRequestSerializer(serializers.ModelSerializer):
    UserName = serializers.CharField(source='UserId.username', read_only=True)
    AssetName = serializers.CharField(source='AssetID.AssetName', read_only=True)

    class Meta:
        model = AssetRequest
        fields = '__all__'