/**
 * CGAuth Example Program
 * 
 * Demonstrates how to use the CGAuth library for:
 * - License key authentication
 * - Username/password authentication
 * - Hardware ID (HWID) display
 */

#include "CGAuth.h"
#include <iostream>
#include <string>

/**
 * Display the main menu
 * Shows available authentication options
 */
void PrintMenu() {
    std::cout << "\n";
    std::cout << "========================================\n";
    std::cout << "       CGAUTH LICENSE SYSTEM\n";
    std::cout << "========================================\n";
    std::cout << "1. Test License Key\n";
    std::cout << "2. Test Username/Password\n";
    std::cout << "3. Show HWID\n";
    std::cout << "4. Exit\n";
    std::cout << "========================================\n";
    std::cout << "Choice: ";
}

/**
 * Test license key authentication
 * 
 * Process:
 * 1. Get license key from user input
 * 2. Generate hardware ID (HWID)
 * 3. Send authentication request to API
 * 4. Display result (success or error)
 */
void TestLicense() {
    std::string licenseKey;
    std::cout << "\nEnter License Key: ";
    std::getline(std::cin, licenseKey);

    // Generate HWID for this machine
    std::string hwid = CGAuth::GetHWID();
    std::cout << "Using HWID: " << hwid << "\n\n";
    std::cout << "Authenticating...\n";

    // Send authentication request
    json result = CGAuth::AuthLicense(licenseKey, hwid);

    // Check authentication result
    if (result["success"]) {
        // SUCCESS - Display license information
        auto data = result["data"];
        std::cout << "\n✓ SUCCESS!\n";
        std::cout << "────────────────────────────────\n";
        std::cout << "App Name: " << data["app_name"] << "\n";
        std::cout << "Status: " << data["status"] << "\n";
        std::cout << "Days Remaining: " << data["days_remaining"] << "\n";
        std::cout << "Hours Remaining: " << data["hours_remaining"] << "\n";
        std::cout << "Expiry Date: " << data["expiry_date"] << "\n";
        std::cout << "────────────────────────────────\n";
    }
    else {
        // FAILURE - Display error message
        std::cout << "\n✗ FAILED!\n";
        std::cout << "Error: " << result["error"] << "\n";
    }
}

/**
 * Test username/password authentication
 * 
 * Process:
 * 1. Get username and password from user input
 * 2. Generate hardware ID (HWID)
 * 3. Send authentication request to API
 * 4. Display result (success or error)
 */
void TestUser() {
    std::string username, password;
    std::cout << "\nEnter Username: ";
    std::getline(std::cin, username);

    std::cout << "Enter Password: ";
    std::getline(std::cin, password);

    // Generate HWID for this machine
    std::string hwid = CGAuth::GetHWID();
    std::cout << "Using HWID: " << hwid << "\n\n";
    std::cout << "Authenticating...\n";

    // Send authentication request
    json result = CGAuth::AuthUser(username, password, hwid);

    // Check authentication result
    if (result["success"]) {
        // SUCCESS - Display user information
        auto data = result["data"];
        std::cout << "\n✓ SUCCESS!\n";
        std::cout << "────────────────────────────────\n";
        std::cout << "Username: " << data["identifier"] << "\n";
        std::cout << "App Name: " << data["app_name"] << "\n";
        std::cout << "Status: " << data["status"] << "\n";
        std::cout << "Days Remaining: " << data["days_remaining"] << "\n";
        std::cout << "Hours Remaining: " << data["hours_remaining"] << "\n";
        std::cout << "────────────────────────────────\n";
    }
    else {
        // FAILURE - Display error message
        std::cout << "\n✗ FAILED!\n";
        std::cout << "Error: " << result["error"] << "\n";
    }
}

/**
 * Display the current machine's Hardware ID (HWID)
 * 
 * The HWID is used to bind licenses to specific machines
 * Users can copy this ID and register it with their license
 */
void ShowHWID() {
    std::string hwid = CGAuth::GetHWID();
    std::cout << "\nYour HWID: " << hwid << "\n";
}

/**
 * Main entry point of the program
 * 
 * Initializes cURL, displays menu, and handles user input
 */
int main() {
    // Initialize cURL library (required for HTTP requests)
    curl_global_init(CURL_GLOBAL_DEFAULT);

    int choice;
    std::string input;

    // Main program loop
    while (true) {
        PrintMenu();
        std::getline(std::cin, input);

        // Try to parse user input as integer
        try {
            choice = std::stoi(input);
        }
        catch (...) {
            // Invalid input - set to 0 (will show "Invalid choice")
            choice = 0;
        }

        // Handle user menu selection
        switch (choice) {
        case 1:
            // Test license key authentication
            TestLicense();
            break;
        case 2:
            // Test username/password authentication
            TestUser();
            break;
        case 3:
            // Display Hardware ID
            ShowHWID();
            break;
        case 4:
            // Exit program
            std::cout << "Goodbye!\n";
            curl_global_cleanup();  // Cleanup cURL resources
            return 0;
        default:
            // Invalid choice
            std::cout << "Invalid choice!\n";
        }
    }

    // Cleanup cURL resources (unreachable due to infinite loop)
    curl_global_cleanup();
    return 0;
}