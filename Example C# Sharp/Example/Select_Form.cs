using System;
using System.Windows.Forms;

namespace Example
{
    public partial class Select_Form : Form
    {
        public Select_Form()
        {
            InitializeComponent();
        }

        // Button click handler for License authentication option
        private void button1_Click(object sender, EventArgs e)
        {
            // Hide the current selection form
            this.Hide();
            
            // Create and show the License test form
            Test_License testLicenseForm = new Test_License();
            testLicenseForm.Show();
        }

        // Button click handler for Account authentication option
        private void button2_Click(object sender, EventArgs e)
        {
            // Hide the current selection form
            this.Hide();
            
            // Create and show the Account test form
            Test_Account testAccountForm = new Test_Account();
            testAccountForm.Show();
        }
    }
}