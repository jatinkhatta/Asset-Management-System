from asset.settings import *  # Import all settings from your main settings file

# Disable test database creation
TEST_DATABASE_CREATE = False

# Use your existing database for tests
DATABASES = {
    'default': {
        'ENGINE': 'mssql',
        'NAME': 'ASSET_INVENTORY_SYSTEM2',
        'HOST': 'BMH-C-001GG\\SQLEXPRESS',
        'PORT': '',
        'OPTIONS': {
            'driver': 'ODBC Driver 17 for SQL Server',
            'Trusted_Connection': 'yes',
        },
    }
}