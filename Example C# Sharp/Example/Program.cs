using System;
using System.Windows.Forms;

namespace Example
{
    static class Program
    {
        // STAThread attribute required for Windows Forms applications
        [STAThread]
        static void Main()
        {
            // Enable visual styles for modern Windows UI appearance
            Application.EnableVisualStyles();
            
            // Set text rendering to use GDI+ for better compatibility
            Application.SetCompatibleTextRenderingDefault(false);
            
            // Start the application with the Select_Form as the main form
            Application.Run(new Select_Form());
        }
    }
}