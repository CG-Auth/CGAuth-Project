using System;
using System.Net;
using System.Windows.Forms;
using Newtonsoft.Json.Linq;
using static Example.CGAuth_Module;

namespace Example
{
    public partial class Test_Account : Form
    {
        public Test_Account()
        {
            InitializeComponent();
        }

        // Main authentication button click handler
        private void button1_Click(object sender, EventArgs e)
        {
            // Configure SSL/TLS certificate validation
            ServicePointManager.ServerCertificateValidationCallback = ValidateCert;
            // Force TLS 1.2 protocol for secure communication
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;

            // Get the hardware ID of the current machine
            string hwid = GetHWID();
            
            // Attempt to authenticate user with username, password, and HWID
            JObject result = AuthUser(Text_Username.Text, Text_Password.Text, hwid);

            // Check if authentication was successful
            if (result["success"].ToObject<bool>())
            {
                // Extract user data from the response
                JToken data = result["data"];
                string days = data["days_remaining"].ToString();
                string hours = data["hours_remaining"].ToString();
                string app_name = data["app_name"].ToString();

                // Build success message with subscription details
                string message = $"Login successful!\n\n" +
                               $"  • App Name: {app_name}\n" +
                               $"Status: {data["status"]}\n\n" +
                               $"Time Remaining:\n" +
                               $"  • Days: {days}\n" +
                               $"  • Hours: {hours}\n";

                // Verify that the license belongs to this application
                if (app_name == YOUR_APP_NAME)
                {
                    MessageBox.Show(message, "Success", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
                else
                {
                    // License is valid but for a different application
                    MessageBox.Show("This license does not belong to this application.",
                                  "Error",
                                  MessageBoxButtons.OK,
                                  MessageBoxIcon.Error);
                }
            }
            else
            {
                // Authentication failed - show error message
                MessageBox.Show($"Login failed!\nError: {result["error"]}",
                              "Error",
                              MessageBoxButtons.OK,
                              MessageBoxIcon.Error);
            }
        }
    }
}