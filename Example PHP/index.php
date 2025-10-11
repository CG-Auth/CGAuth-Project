<?php
/**
 * CGAuth License System - Main Entry Point
 * 
 * This file serves two purposes:
 * 1. Backend API handler (POST requests)
 * 2. Frontend UI (GET requests)
 */

// ========================================================================
// BACKEND API HANDLER (POST Requests)
// ========================================================================

// Check if this is a POST request (API call)
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Set JSON response header
    header('Content-Type: application/json');
    
    // Include the CGAuth class
    require_once 'CGAuth.php';
    
    // Get the authentication type from POST data
    $type = $_POST['type'] ?? '';
    
    // Generate Hardware ID for this server/machine
    $hwid = CGAuth::getHWID();
    
    try {
        // Handle different authentication types
        if ($type === 'license') {
            // LICENSE KEY AUTHENTICATION
            
            // Get license key from POST data
            $licenseKey = $_POST['license_key'] ?? '';
            
            // Validate input
            if (empty($licenseKey)) {
                throw new Exception("License key is required");
            }
            
            // Authenticate the license key
            $result = CGAuth::authLicense($licenseKey, $hwid);
            
        } elseif ($type === 'user') {
            // USERNAME/PASSWORD AUTHENTICATION
            
            // Get credentials from POST data
            $username = $_POST['username'] ?? '';
            $password = $_POST['password'] ?? '';
            
            // Validate input
            if (empty($username) || empty($password)) {
                throw new Exception("Username and password are required");
            }
            
            // Authenticate the user
            $result = CGAuth::authUser($username, $password, $hwid);
            
        } elseif ($type === 'hwid') {
            // HWID REQUEST - Just return the hardware ID
            $result = [
                'success' => true,
                'hwid' => $hwid
            ];
            
        } else {
            // Invalid authentication type
            throw new Exception("Invalid type");
        }
        
        // Return JSON response
        echo json_encode($result);
        
    } catch (Exception $e) {
        // Return error response
        echo json_encode([
            'success' => false,
            'error' => $e->getMessage()
        ]);
    }
    
    // Exit after handling API request
    exit;
}

// ========================================================================
// FRONTEND UI (GET Requests)
// ========================================================================
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CGAuth License System</title>
    <link href="css/styles.css" rel="stylesheet">
</head>
<body>
    <div class="container">
        <h1>🔐 CGAuth License System</h1>
        
        <!-- Tab Navigation -->
        <div class="tabs">
            <button class="tab active" onclick="switchTab('license')">License Key</button>
            <button class="tab" onclick="switchTab('user')">Username/Password</button>
            <button class="tab" onclick="switchTab('hwid')">HWID</button>
        </div>
        
        <!-- License Key Authentication Tab -->
        <div id="license-tab" class="tab-content active">
            <form id="license-form" onsubmit="authenticate(event, 'license')">
                <div class="form-group">
                    <label for="license_key">License Key:</label>
                    <input type="text" id="license_key" name="license_key" 
                           placeholder="Enter your license key" required>
                </div>
                <button type="submit">Authenticate</button>
            </form>
        </div>
        
        <!-- Username/Password Authentication Tab -->
        <div id="user-tab" class="tab-content">
            <form id="user-form" onsubmit="authenticate(event, 'user')">
                <div class="form-group">
                    <label for="username">Username:</label>
                    <input type="text" id="username" name="username" 
                           placeholder="Enter username" required>
                </div>
                <div class="form-group">
                    <label for="password">Password:</label>
                    <input type="password" id="password" name="password" 
                           placeholder="Enter password" required>
                </div>
                <button type="submit">Authenticate</button>
            </form>
        </div>
        
        <!-- Hardware ID Display Tab -->
        <div id="hwid-tab" class="tab-content">
            <div class="hwid-display">
                <strong>Your Hardware ID:</strong>
                <code id="hwid-value" onclick="copyHWID()">Loading...</code>
                <small style="display:block; margin-top:10px; color:#666;">Click to copy</small>
            </div>
        </div>
        
        <!-- Loading Indicator -->
        <div class="loading" id="loading">
            <p>⏳ Processing...</p>
        </div>
        
        <!-- Result Display Area -->
        <div class="result" id="result"></div>
    </div>
    
    <script>
        // ====================================================================
        // JAVASCRIPT FUNCTIONS
        // ====================================================================
        
        /**
         * Load HWID when page loads
         * Makes an AJAX request to get the server's hardware ID
         */
        window.onload = function() {
            // Fetch HWID from backend
            fetch('index.php', {
                method: 'POST',
                headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                body: 'type=hwid'
            })
            .then(r => r.json())
            .then(data => {
                // Display HWID if successful
                if (data.success) {
                    document.getElementById('hwid-value').textContent = data.hwid;
                }
            });
        };
        
        /**
         * Switch between tabs (License, User, HWID)
         * @param {string} tab - Tab name to switch to
         */
        function switchTab(tab) {
            // Remove active class from all tab contents and buttons
            document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
            document.querySelectorAll('.tab').forEach(el => el.classList.remove('active'));
            
            // Add active class to selected tab
            document.getElementById(tab + '-tab').classList.add('active');
            event.target.classList.add('active');
            
            // Hide any previous results
            hideResult();
        }
        
        /**
         * Handle authentication form submission
         * @param {Event} event - Form submit event
         * @param {string} type - Authentication type ('license' or 'user')
         */
        function authenticate(event, type) {
            // Prevent default form submission
            event.preventDefault();
            
            // Get form data
            const form = event.target;
            const formData = new FormData(form);
            formData.append('type', type);
            
            // Show loading indicator
            showLoading();
            hideResult();
            
            // Send authentication request to backend
            fetch('index.php', {
                method: 'POST',
                body: new URLSearchParams(formData)
            })
            .then(response => response.json())
            .then(data => {
                // Hide loading and show result
                hideLoading();
                showResult(data);
            })
            .catch(error => {
                // Handle network errors
                hideLoading();
                showResult({success: false, error: 'Network error: ' + error.message});
            });
        }
        
        /**
         * Display authentication result
         * @param {Object} data - Response data from API
         */
        function showResult(data) {
            const resultDiv = document.getElementById('result');
            
            // Set CSS class based on success/failure
            resultDiv.className = 'result show ' + (data.success ? 'success' : 'error');
            
            if (data.success) {
                // SUCCESS - Display license information
                const d = data.data;
                resultDiv.innerHTML = `
                    <h3>✓ Authentication Successful</h3>
                    <div class="result-item"><strong>App Name:</strong> ${d.app_name}</div>
                    <div class="result-item"><strong>Status:</strong> ${d.status}</div>
                    <div class="result-item"><strong>Days Remaining:</strong> ${d.days_remaining}</div>
                    <div class="result-item"><strong>Hours Remaining:</strong> ${d.hours_remaining}</div>
                    <div class="result-item"><strong>Expiry Date:</strong> ${d.expiry_date}</div>
                `;
            } else {
                // FAILURE - Display error message
                resultDiv.innerHTML = `<h3>✗ Authentication Failed</h3><p>${data.error}</p>`;
            }
        }
        
        /**
         * Hide result display
         */
        function hideResult() {
            document.getElementById('result').classList.remove('show');
        }
        
        /**
         * Show loading indicator
         */
        function showLoading() {
            document.getElementById('loading').classList.add('show');
        }
        
        /**
         * Hide loading indicator
         */
        function hideLoading() {
            document.getElementById('loading').classList.remove('show');
        }
        
        /**
         * Copy HWID to clipboard
         * Uses the Clipboard API to copy the hardware ID
         */
        function copyHWID() {
            const hwid = document.getElementById('hwid-value').textContent;
            
            // Copy to clipboard
            navigator.clipboard.writeText(hwid).then(() => {
                alert('HWID copied to clipboard!');
            });
        }
    </script>
</body>
</html>