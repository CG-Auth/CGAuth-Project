
namespace Example
{
    partial class Test_License
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
            this.Text_License = new System.Windows.Forms.TextBox();
            this.Button_Submit = new System.Windows.Forms.Button();
            this.SuspendLayout();
            // 
            // Text_License
            // 
            this.Text_License.Location = new System.Drawing.Point(12, 12);
            this.Text_License.Name = "Text_License";
            this.Text_License.Size = new System.Drawing.Size(290, 20);
            this.Text_License.TabIndex = 0;
            this.Text_License.Text = "LICENSE-KEY";
            // 
            // Button_Submit
            // 
            this.Button_Submit.Font = new System.Drawing.Font("Microsoft Sans Serif", 11.25F);
            this.Button_Submit.Location = new System.Drawing.Point(12, 40);
            this.Button_Submit.Name = "Button_Submit";
            this.Button_Submit.Size = new System.Drawing.Size(290, 63);
            this.Button_Submit.TabIndex = 1;
            this.Button_Submit.Text = "Submit";
            this.Button_Submit.UseVisualStyleBackColor = true;
            this.Button_Submit.Click += new System.EventHandler(this.button1_Click);
            // 
            // Test_License
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(314, 113);
            this.Controls.Add(this.Button_Submit);
            this.Controls.Add(this.Text_License);
            this.MaximizeBox = false;
            this.MaximumSize = new System.Drawing.Size(330, 152);
            this.MinimizeBox = false;
            this.MinimumSize = new System.Drawing.Size(330, 152);
            this.Name = "Test_License";
            this.ShowIcon = false;
            this.ShowInTaskbar = false;
            this.StartPosition = System.Windows.Forms.FormStartPosition.CenterScreen;
            this.Text = "Test_License";
            this.TopMost = true;
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.TextBox Text_License;
        private System.Windows.Forms.Button Button_Submit;
    }
}