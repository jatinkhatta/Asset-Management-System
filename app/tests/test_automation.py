from django.test import LiveServerTestCase  # Change the import
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait, Select
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, NoSuchElementException
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.action_chains import ActionChains
import unittest
import time
import os
from datetime import datetime, timedelta
from selenium.webdriver.chrome.service import Service

class AssetManagementAutomationTest(LiveServerTestCase):  # Change the parent class
    databases = '__all__'  # This tells Django to use all configured databases
    
    @classmethod
    def setUpClass(cls):
        # Add this line to prevent database creation
        cls._force_database = True
        super().setUpClass()
        chrome_options = webdriver.ChromeOptions()
        # chrome_options.add_argument('--headless')  # Uncomment for headless testing
        
        service = Service(r"C:\\Users\\EBF3KOR\Desktop\\chromedriver-win64\\chromedriver.exe")
        cls.driver = webdriver.Chrome(service=service, options=chrome_options)
        cls.driver.maximize_window()
        cls.driver.implicitly_wait(10)
        cls.wait = WebDriverWait(cls.driver, 10)


    @classmethod
    def tearDownClass(cls):
        cls.driver.quit()
        super().tearDownClass()

    def setUp(self):
        """Setup test data"""
        # Create admin user
        from app.models import User  # Use absolute import path
        from django.utils.timezone import now
        from django.contrib.auth.hashers import make_password
        
        # Create an admin user
        admin_user = User.objects.create(
            username="adminuser",
            password_hash=make_password("Admin@2025"),
            email="fixed-term.Bhuvandeep.Kanekanti@bosch.com",
            phone="+1234567890",
            role="ADMIN",
            created_at=now(),
            last_login=now()
        )
        
        # Create a regular user
        regular_user = User.objects.create(
            username="regularuser",
            password_hash=make_password("Tarun@2025"),
            email="fixed-term.SaiTarun.Chiliveri@bosch.com",
            phone="+9876543210",
            role="USER",
            created_at=now(),
            last_login=now()
        )
        
        self.admin_email = "fixed-term.Bhuvandeep.Kanekanti@bosch.com"
        self.admin_password = "Admin@2025"
        self.user_email = "fixed-term.SaiTarun.Chiliveri@bosch.com"
        self.user_password = "Tarun@2025"
        self.base_url = self.live_server_url

    def login(self, email, password):
        """Generic login function"""
        self.driver.get(f"{self.base_url}/login/")
        self.driver.find_element(By.NAME, "email").send_keys(self.admin_email)
        self.driver.find_element(By.NAME, "password").send_keys(self.admin_password)
        self.driver.find_element(By.CSS_SELECTOR, "button[type='submit']").click()
        time.sleep(2)

    def test_01_user_registration(self):
        """Test user registration process"""
        self.driver.get(f"{self.base_url}/register/")
        
        # Fill registration form with valid data
        self.driver.find_element(By.NAME, "username").send_keys("testuser")
        self.driver.find_element(By.NAME, "email").send_keys("testuser@example.com")
        self.driver.find_element(By.NAME, "phone").send_keys("1234567890")
        self.driver.find_element(By.NAME, "password").send_keys("Test@1234")
        self.driver.find_element(By.NAME, "confirm-password").send_keys("Test@1234")

        # Submit form
        self.driver.find_element(By.CSS_SELECTOR, "button[type='submit']").click()
        
        try:
            # Wait for success message
            success_message = self.wait.until(
                EC.presence_of_element_located((By.CLASS_NAME, "success"))
            )
            self.assertIn("Signup successful", success_message.text)
            
            # Verify redirect to login page
            self.wait.until(
                EC.url_contains("/login")
            )
        except TimeoutException:
            self.fail("Registration failed or success message not found")

    def test_02_admin_login_and_dashboard(self):
        """Test admin login and dashboard access"""
        self.login(self.admin_email, self.admin_password)
        
        # Verify admin dashboard elements
        dashboard_elements = [
            "Asset Inventory",
            "Alerts",
            "Reports",
            "User Management"
        ]
        
        for element in dashboard_elements:
            self.assertTrue(
                self.driver.find_element(By.LINK_TEXT, element).is_displayed()
            )

    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.webdriver.common.by import By

    def test_add_vendor_and_asset(self):
        """Test adding a vendor and then creating an asset with that vendor"""
        # Login as admin
        self.login(self.admin_email, self.admin_password)
        
        try:
            # Navigate to add asset page
            self.driver.get(f"{self.base_url}/add-hardware-asset/")
            
            wait = WebDriverWait(self.driver, 10)

            # Function to add a custom vendor
            def add_custom_vendor(vendor_name, vendor_bgsw_id, vendor_contact, vendor_notes=""):
                # Open the Add Custom Vendor form in a new tab/window
                add_vendor_button = wait.until(
                    EC.element_to_be_clickable((By.ID, "add_custom_vendor_btn"))
                )
                add_vendor_button.click()
                
                # Switch to the new tab/window
                self.driver.switch_to.window(self.driver.window_handles[-1])
                
                # Wait for the form to load and fill out the details
                vendor_name_field = wait.until(
                    EC.presence_of_element_located((By.ID, "vendorName"))
                )
                vendor_name_field.send_keys(vendor_name)
                
                self.driver.find_element(By.ID, "vendorBgswId").send_keys(vendor_bgsw_id)
                self.driver.find_element(By.ID, "vendorContact").send_keys(vendor_contact)
                self.driver.find_element(By.ID, "vendorNotes").send_keys(vendor_notes)
                
                # Submit the form
                submit_button = self.driver.find_element(By.CSS_SELECTOR, ".submit-btn")
                submit_button.click()
                
                # Wait for success message or close window after a short delay
                wait.until(
                    EC.presence_of_element_located((By.XPATH, "//h2[contains(text(), 'Vendor added successfully')]"))
                )
                
                # Close the tab/window
                self.driver.close()
                
                # Switch back to the main window
                self.driver.switch_to.window(self.driver.window_handles[0])
            
            # Add the vendor "Tech Solutions"
            add_custom_vendor(
                vendor_name="Tech Solutions",
                vendor_bgsw_id="TS12345",  # Example BGSW Vendor ID
                vendor_contact="tech@example.com",
                vendor_notes="Primary IT equipment supplier"
            )
            
            # Refresh vendors list in the modal
            refresh_vendors_btn = wait.until(
                EC.element_to_be_clickable((By.ID, "refresh_vendors_btn"))
            )
            refresh_vendors_btn.click()
            
            # Wait for loading to finish
            wait.until(
                EC.invisibility_of_element_located((By.ID, "loading-indicator"))
            )
            
            # Open vendor selection modal
            select_vendor_btn = wait.until(
                EC.element_to_be_clickable((By.ID, "select_vendor_btn"))
            )
            select_vendor_btn.click()
            
            # Search for the newly added vendor
            vendor_search = wait.until(
                EC.presence_of_element_located((By.ID, "vendor_search"))
            )
            vendor_search.send_keys("Tech Solutions")
            
            search_vendor_btn = wait.until(
                EC.element_to_be_clickable((By.ID, "search_vendor_btn"))
            )
            search_vendor_btn.click()
            
            # Select the vendor from the table
            select_vendor_button = wait.until(
                EC.presence_of_element_located((By.CSS_SELECTOR, ".select-vendor-btn"))
            )
            select_vendor_button.click()
            
            # Verify that the vendor is selected
            selected_vendor_details = wait.until(
                EC.visibility_of_element_located((By.ID, "selected_vendor_details"))
            )
            assert "Tech Solutions" in selected_vendor_details.text
            
            # Continue with the rest of the asset creation...
            
            # Asset Bond Type (Select Non Bonded)
            bond_type_select = Select(wait.until(EC.presence_of_element_located((By.ID, "asset-bond-type"))))
            bond_type_select.select_by_visible_text("Non Bonded")
            
            # Asset Name
            asset_name_field = wait.until(EC.presence_of_element_located((By.NAME, "assetName")))
            asset_name_field.send_keys("Test Laptop")
            
            # Category Selection
            select_category_btn = wait.until(
                EC.element_to_be_clickable((By.ID, "select_category_btn"))
            )
            select_category_btn.click()
            
            category_search = wait.until(
                EC.presence_of_element_located((By.ID, "category_search"))
            )
            category_search.send_keys("Laptops")
            
            search_category_btn = wait.until(
                EC.element_to_be_clickable((By.ID, "search_category_btn"))
            )
            search_category_btn.click()
            
            select_category_button = wait.until(
                EC.presence_of_element_located((By.CSS_SELECTOR, ".select-category-btn"))
            )
            select_category_button.click()
            
            # Generate Asset Number
            generate_asset_number_btn = wait.until(
                EC.element_to_be_clickable((By.CSS_SELECTOR, ".generate-btn"))
            )
            generate_asset_number_btn.click()
            
            # Serial Number (Optional)
            serial_number_field = self.driver.find_element(By.NAME, "serialNumber")
            serial_number_field.send_keys("SN123456789")
            
            # Part Number (Required)
            part_number_field = self.driver.find_element(By.NAME, "partNumber")
            part_number_field.send_keys("PN987654321")
            
            # Asset Type (Select Hardware)
            asset_type_select = Select(self.driver.find_element(By.NAME, "assetType"))
            asset_type_select.select_by_visible_text("Hardware")
            
            # Asset Model (Required)
            asset_model_field = self.driver.find_element(By.NAME, "assetModel")
            asset_model_field.send_keys("Model X1")
            
            # Purchase Date (Today's date)
            purchase_date_field = self.driver.find_element(By.NAME, "purchaseDate")
            purchase_date_field.send_keys(datetime.now().strftime("%Y-%m-%d"))
            
            # Cost Conversion
            convert_cost_btn = self.driver.find_element(By.ID, "convert-cost-btn")
            convert_cost_btn.click()
            
            # In cost conversion modal
            convert_modal = wait.until(EC.visibility_of_element_located((By.ID, "convert-modal")))
            input_cost = convert_modal.find_element(By.ID, "input-cost")
            input_cost.send_keys("1000")  # Cost in INR
            
            convert_btn = convert_modal.find_element(By.ID, "convert-btn")
            convert_btn.click()
            
            save_cost_btn = wait.until(
                EC.element_to_be_clickable((By.ID, "save-btn"))
            )
            save_cost_btn.click()
            
            # Warranty (Years)
            warranty_field = self.driver.find_element(By.NAME, "warranty")
            warranty_field.send_keys("2")
            
            # Location (Required)
            location_field = self.driver.find_element(By.NAME, "location")
            location_field.send_keys("Main Office")
            
            # Asset Provider (Select BGSW)
            asset_provider_select = Select(self.driver.find_element(By.NAME, "assetProvider"))
            asset_provider_select.select_by_visible_text("BGSW")
            
            # Asset Classification (Select Consumables)
            asset_classification_select = Select(self.driver.find_element(By.NAME, "assetClassification"))
            asset_classification_select.select_by_visible_text("Consumables")
            
            # Warehouse Information
            warehouse_set_info_btn = self.driver.find_element(By.CSS_SELECTOR, "#warehouse + button")
            warehouse_set_info_btn.click()
            
            warehouse_modal = wait.until(EC.visibility_of_element_located((By.ID, "warehouseModal")))
            item_floor = warehouse_modal.find_element(By.ID, "itemFloor")
            storage_location = warehouse_modal.find_element(By.ID, "storageLocation")
            rack_number = warehouse_modal.find_element(By.ID, "rackNumber")
            storage_type = warehouse_modal.find_element(By.ID, "storageType")
            
            item_floor.send_keys("Ground Floor")
            storage_location.send_keys("Aisle 5")
            rack_number.send_keys("Rack 12")
            storage_type.send_keys("Zone C")
            
            save_warehouse_btn = warehouse_modal.find_element(By.CSS_SELECTOR, ".submit-btn")
            save_warehouse_btn.click()
            
            # Upload Image (Assuming we have an image file path)
            image_upload_container = self.driver.find_element(By.ID, "imageUploadContainer")
            image_upload_container.click()
            
            image_input = self.driver.find_element(By.ID, "image-input")
            image_input.send_keys("/path/to/test/image.jpg")  # Update with actual image path
            
            # Submit Form
            submit_btn = self.driver.find_element(By.CSS_SELECTOR, "button[type='submit']")
            submit_btn.click()
            
            # Verify Success
            success_message = wait.until(
                EC.presence_of_element_located((By.CLASS_NAME, "alert-success"))
            )
            assert "Asset added successfully" in success_message.text
            
        except Exception as e:
            self.driver.save_screenshot("test_failure.png")
            raise e

    def test_04_add_software_asset(self):
        """Test adding a software asset"""
        self.login(self.admin_email, self.admin_password)
        
        # Navigate to add software asset page
        self.driver.get(f"{self.base_url}/add-software-asset/")
        
        # Fill software asset form
        self.driver.find_element(By.NAME, "asset_number").send_keys("SW001")
        self.driver.find_element(By.NAME, "asset_name").send_keys("Test Software")
        
        # Select software type
        type_select = Select(self.driver.find_element(By.NAME, "asset_type"))
        type_select.select_by_visible_text("Software")
        
        # Fill license details
        self.driver.find_element(By.NAME, "license_key").send_keys("TEST-KEY-123")
        self.driver.find_element(By.NAME, "expiry_date").send_keys(
            (datetime.now() + timedelta(days=365)).strftime("%Y-%m-%d")
        )
        
        # Submit form
        self.driver.find_element(By.CSS_SELECTOR, "button[type='submit']").click()
        
        # Verify success
        self.wait.until(
            EC.presence_of_element_located((By.CLASS_NAME, "alert-success"))
        )

    def test_05_asset_inventory_features(self):
        """Test asset inventory features"""
        self.login(self.admin_email, self.admin_password)
        self.driver.get(f"{self.base_url}/Asset Inventory/")
        
        # Test search
        search_box = self.driver.find_element(By.ID, "searchBox")
        search_box.send_keys("Test")
        time.sleep(2)
        
        # Test filters
        type_filter = Select(self.driver.find_element(By.ID, "typeFilter"))
        type_filter.select_by_visible_text("Hardware")
        time.sleep(2)
        
        # Test sorting
        self.driver.find_element(By.CSS_SELECTOR, "th[data-column='asset_name']").click()
        time.sleep(1)

    def test_06_asset_request_workflow(self):
        """Test complete asset request workflow"""
        # User submits request
        self.login(self.user_email, self.user_password)
        self.driver.get(f"{self.base_url}/submit_request/")
        
        # Fill request form
        self.driver.find_element(By.NAME, "asset_type").send_keys("Hardware")
        self.driver.find_element(By.NAME, "description").send_keys("Test request")
        self.driver.find_element(By.NAME, "start_date").send_keys(
            datetime.now().strftime("%Y-%m-%d")
        )
        self.driver.find_element(By.NAME, "end_date").send_keys(
            (datetime.now() + timedelta(days=7)).strftime("%Y-%m-%d")
        )
        
        # Submit request
        self.driver.find_element(By.CSS_SELECTOR, "button[type='submit']").click()
        
        # Admin approves request
        self.login(self.admin_email, self.admin_password)
        self.driver.get(f"{self.base_url}/asset-request-tracking/")
        
        # Find and approve the latest request
        approve_button = self.driver.find_element(By.CSS_SELECTOR, ".approve-request")
        approve_button.click()
        
        # Verify approval
        self.wait.until(
            EC.presence_of_element_located((By.CLASS_NAME, "alert-success"))
        )

    def test_07_reports_generation(self):
        """Test reports generation"""
        self.login(self.admin_email, self.admin_password)
        
        # Test various reports
        report_urls = [
            '/asset_stats_view/',
            '/custom_report_builder/',
            '/download-asset-data-pdf/',
            '/download-cost-analysis/'
        ]
        
        for url in report_urls:
            self.driver.get(f"{self.base_url}{url}")
            time.sleep(2)
            # Verify page loaded successfully
            self.assertNotIn("Error", self.driver.title)

    def test_08_maintenance_management(self):
        """Test maintenance management features"""
        self.login(self.admin_email, self.admin_password)
        self.driver.get(f"{self.base_url}/MaintenancePage/")
        
        # Add maintenance record
        self.driver.find_element(By.ID, "add-maintenance").click()
        
        # Fill maintenance form
        self.driver.find_element(By.NAME, "asset_id").send_keys("HW001")
        self.driver.find_element(By.NAME, "maintenance_date").send_keys(
            datetime.now().strftime("%Y-%m-%d")
        )
        self.driver.find_element(By.NAME, "description").send_keys("Test maintenance")
        self.driver.find_element(By.NAME, "cost").send_keys("100")
        
        # Submit form
        self.driver.find_element(By.CSS_SELECTOR, "button[type='submit']").click()
        
        # Verify success
        self.wait.until(
            EC.presence_of_element_located((By.CLASS_NAME, "alert-success"))
        )

    def test_09_user_management(self):
        """Test user management features"""
        self.login(self.admin_email, self.admin_password)
        self.driver.get(f"{self.base_url}/users/")
        
        # Test user search
        search_box = self.driver.find_element(By.ID, "userSearchBox")
        search_box.send_keys("user@test.com")
        time.sleep(2)
        
        # Test user role update
        role_select = Select(self.driver.find_element(By.CSS_SELECTOR, ".user-role-select"))
        role_select.select_by_visible_text("Admin")
        
        # Verify role update
        self.wait.until(
            EC.presence_of_element_located((By.CLASS_NAME, "alert-success"))
        )

    def test_10_alerts_system(self):
        """Test alerts system"""
        self.login(self.admin_email, self.admin_password)
        self.driver.get(f"{self.base_url}/Alerts/")
        
        # Verify alerts page elements
        alert_elements = self.driver.find_elements(By.CLASS_NAME, "alert-item")
        self.assertGreater(len(alert_elements), 0)
        
        # Test alert acknowledgment
        if alert_elements:
            alert_elements[0].find_element(By.CLASS_NAME, "acknowledge-alert").click()
            time.sleep(1)
            # Verify alert was acknowledged
            self.wait.until(
                EC.presence_of_element_located((By.CLASS_NAME, "alert-success"))
            )

    def test_11_error_handling(self):
        """Test error handling and validation"""
        self.login(self.admin_email, self.admin_password)
        
        # Test invalid asset number
        self.driver.get(f"{self.base_url}/add-hardware-asset/")
        self.driver.find_element(By.NAME, "asset_number").send_keys("Invalid!")
        self.driver.find_element(By.CSS_SELECTOR, "button[type='submit']").click()
        
        # Verify error message
        self.wait.until(
            EC.presence_of_element_located((By.CLASS_NAME, "alert-danger"))
        )
        
        # Test duplicate asset number
        self.driver.find_element(By.NAME, "asset_number").clear()
        self.driver.find_element(By.NAME, "asset_number").send_keys("HW001")
        self.driver.find_element(By.CSS_SELECTOR, "button[type='submit']").click()
        
        # Verify duplicate error
        self.wait.until(
            EC.presence_of_element_located((By.CLASS_NAME, "alert-danger"))
        )

    def test_12_export_functionality(self):
        """Test data export functionality"""
        self.login(self.admin_email, self.admin_password)
        
        # Test various export formats
        export_formats = ['csv', 'pdf', 'excel']
        
        for format in export_formats:
            self.driver.get(f"{self.base_url}/export-assets/")
            format_select = Select(self.driver.find_element(By.NAME, "format"))
            format_select.select_by_value(format)
            
            # Submit export
            self.driver.find_element(By.ID, "export-button").click()
            time.sleep(2)
            
            # Verify file download (this might need adjustment based on your setup)
            # For now, we'll just verify no errors occurred
            self.assertNotIn("Error", self.driver.title)

if __name__ == '__main__':
    unittest.main(verbosity=2)

