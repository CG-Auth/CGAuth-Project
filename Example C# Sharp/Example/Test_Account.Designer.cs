
namespace Example
{
    partial class Test_Account
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            this.Button_Submit = new System.Windows.Forms.Button();
            this.Text_Username = new System.Windows.Forms.TextBox();
            this.Text_Password = new System.Windows.Forms.TextBox();
            this.SuspendLayout();
            // 
            // Button_Submit
            // 
            this.Button_Submit.Font = new System.Drawing.Font("Microsoft Sans Serif", 11.25F);
            this.Button_Submit.Location = new System.Drawing.Point(13, 44);
            this.Button_Submit.Name = "Button_Submit";
            this.Button_Submit.Size = new System.Drawing.Size(279, 53);
            this.Button_Submit.TabIndex = 0;
            this.Button_Submit.Text = "Submit";
            this.Button_Submit.UseVisualStyleBackColor = true;
            this.Button_Submit.Click += new System.EventHandler(this.button1_Click);
            // 
            // Text_Username
            // 
            this.Text_Username.Location = new System.Drawing.Point(13, 16);
            this.Text_Username.Name = "Text_Username";
            this.Text_Username.Size = new System.Drawing.Size(132, 20);
            this.Text_Username.TabIndex = 1;
            this.Text_Username.Text = "username";
            // 
            // Text_Password
            // 
            this.Text_Password.Location = new System.Drawing.Point(151, 16);
            this.Text_Password.Name = "Text_Password";
            this.Text_Password.Size = new System.Drawing.Size(141, 20);
            this.Text_Password.TabIndex = 2;
            this.Text_Password.Text = "password";
            // 
            // Form1
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(306, 109);
            this.Controls.Add(this.Text_Password);
            this.Controls.Add(this.Text_Username);
            this.Controls.Add(this.Button_Submit);
            this.MaximizeBox = false;
            this.MaximumSize = new System.Drawing.Size(322, 148);
            this.MinimizeBox = false;
            this.MinimumSize = new System.Drawing.Size(322, 148);
            this.Name = "Form1";
            this.ShowIcon = false;
            this.ShowInTaskbar = false;
            this.StartPosition = System.Windows.Forms.FormStartPosition.CenterScreen;
            this.Text = "Account Lisense";
            this.TopMost = true;
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.Button Button_Submit;
        private System.Windows.Forms.TextBox Text_Username;
        private System.Windows.Forms.TextBox Text_Password;
    }
}

