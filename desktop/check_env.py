import os
import sys

# Check python version
print(f"Python Version: {sys.version}")

# Check packages
packages = ['pandas', 'reportlab', 'tkinter', 'sqlite3']
for pkg in packages:
    try:
        __import__(pkg)
        print(f"Package '{pkg}': INSTALLED")
    except ImportError:
        print(f"Package '{pkg}': NOT INSTALLED")

# Check browser paths
user_profile = os.environ.get('USERPROFILE', '')
paths = {
    'Chrome Default': os.path.join(user_profile, 'AppData', 'Local', 'Google', 'Chrome', 'User Data', 'Default'),
    'Edge Default': os.path.join(user_profile, 'AppData', 'Local', 'Microsoft', 'Edge', 'User Data', 'Default'),
    'Firefox Profiles': os.path.join(user_profile, 'AppData', 'Roaming', 'Mozilla', 'Firefox', 'Profiles')
}

for name, path in paths.items():
    exists = os.path.exists(path)
    print(f"{name}: {'EXISTS' if exists else 'NOT FOUND'} (Path: {path})")
    if name == 'Firefox Profiles' and exists:
        try:
            profiles = os.listdir(path)
            print(f"  Firefox Profiles found: {profiles}")
        except Exception as e:
            print(f"  Error reading Firefox profiles directory: {e}")
