from cgauth_module import CGAuth

def print_header():
    """Display the application header"""
    print("\n" + "=" * 50)
    print("         CGAUTH LICENSE SYSTEM")
    print("=" * 50)

def print_menu():
    """Display the main menu options"""
    print("\n1. Test License Key")
    print("2. Test Username/Password")
    print("3. Show HWID")
    print("4. Exit")
    print("-" * 50)

def test_license():
    """Test license key authentication"""
    print("\n" + "-" * 50)
    license_key = input("Enter License Key: ")
    
    # Get the hardware ID for this machine
    hwid = CGAuth.get_hwid()
    print(f"Using HWID: {hwid}")
    print("\nAuthenticating...")
    
    # Authenticate the license key with the server
    result = CGAuth.auth_license(license_key, hwid)
    
    # Check if authentication was successful
    if result.get("success"):
        data = result["data"]
        print("\n✓ SUCCESS!")
        print("─" * 50)
        # Display license information
        print(f"App Name: {data['app_name']}")
        print(f"Status: {data['status']}")
        print(f"Days Remaining: {data['days_remaining']}")
        print(f"Hours Remaining: {data['hours_remaining']}")
        print(f"Expiry Date: {data['expiry_date']}")
        print("─" * 50)
        
        # Verify the license belongs to this application
        if data['app_name'] == CGAuth.YOUR_APP_NAME:
            print("✓ License belongs to this application")
        else:
            print("✗ License does not belong to this application")
    else:
        # Display error message if authentication failed
        print("\n✗ FAILED!")
        print(f"Error: {result.get('error')}")

def test_user():
    """Test username/password authentication"""
    print("\n" + "-" * 50)
    username = input("Enter Username: ")
    password = input("Enter Password: ")
    
    # Get the hardware ID for this machine
    hwid = CGAuth.get_hwid()
    print(f"Using HWID: {hwid}")
    print("\nAuthenticating...")
    
    # Authenticate the user credentials with the server
    result = CGAuth.auth_user(username, password, hwid)
    
    # Check if authentication was successful
    if result.get("success"):
        data = result["data"]
        print("\n✓ SUCCESS!")
        print("─" * 50)
        # Display user information
        print(f"Username: {data['identifier']}")
        print(f"App Name: {data['app_name']}")
        print(f"Status: {data['status']}")
        print(f"Days Remaining: {data['days_remaining']}")
        print(f"Hours Remaining: {data['hours_remaining']}")
        print("─" * 50)
    else:
        # Display error message if authentication failed
        print("\n✗ FAILED!")
        print(f"Error: {result.get('error')}")

def show_hwid():
    """Display the current machine's Hardware ID"""
    hwid = CGAuth.get_hwid()
    print("\n" + "─" * 50)
    print(f"Your HWID: {hwid}")
    print("─" * 50)

def main():
    """Main application loop"""
    print_header()
    
    # Main menu loop
    while True:
        print_menu()
        choice = input("Choice: ").strip()
        
        # Handle user menu selection
        if choice == "1":
            test_license()
        elif choice == "2":
            test_user()
        elif choice == "3":
            show_hwid()
        elif choice == "4":
            print("\nGoodbye!")
            break
        else:
            print("Invalid choice!")

# Entry point of the application
if __name__ == "__main__":
    main()