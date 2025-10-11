<Global.Microsoft.VisualBasic.CompilerServices.DesignerGenerated()>
Partial Class Test_Account
    Inherits System.Windows.Forms.Form

    'Form overrides dispose to clean up the component list.
    <System.Diagnostics.DebuggerNonUserCode()>
    Protected Overrides Sub Dispose(ByVal disposing As Boolean)
        Try
            If disposing AndAlso components IsNot Nothing Then
                components.Dispose()
            End If
        Finally
            MyBase.Dispose(disposing)
        End Try
    End Sub

    'Required by the Windows Form Designer
    Private components As System.ComponentModel.IContainer

    'NOTE: The following procedure is required by the Windows Form Designer
    'It can be modified using the Windows Form Designer.  
    'Do not modify it using the code editor.
    <System.Diagnostics.DebuggerStepThrough()>
    Private Sub InitializeComponent()
        Me.Text_Username = New System.Windows.Forms.TextBox()
        Me.Button_Submit = New System.Windows.Forms.Button()
        Me.Text_Password = New System.Windows.Forms.TextBox()
        Me.SuspendLayout()
        '
        'Text_Username
        '
        Me.Text_Username.Location = New System.Drawing.Point(13, 10)
        Me.Text_Username.Name = "Text_Username"
        Me.Text_Username.Size = New System.Drawing.Size(141, 20)
        Me.Text_Username.TabIndex = 3
        Me.Text_Username.Text = "username"
        '
        'Button_Submit
        '
        Me.Button_Submit.Font = New System.Drawing.Font("Microsoft Sans Serif", 14.25!, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, CType(162, Byte))
        Me.Button_Submit.Location = New System.Drawing.Point(13, 37)
        Me.Button_Submit.Name = "Button_Submit"
        Me.Button_Submit.Size = New System.Drawing.Size(314, 54)
        Me.Button_Submit.TabIndex = 2
        Me.Button_Submit.Text = "Submit"
        Me.Button_Submit.UseVisualStyleBackColor = True
        '
        'Text_Password
        '
        Me.Text_Password.Location = New System.Drawing.Point(155, 10)
        Me.Text_Password.Name = "Text_Password"
        Me.Text_Password.Size = New System.Drawing.Size(172, 20)
        Me.Text_Password.TabIndex = 4
        Me.Text_Password.Text = "password"
        '
        'Test_Account
        '
        Me.AutoScaleDimensions = New System.Drawing.SizeF(6.0!, 13.0!)
        Me.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font
        Me.ClientSize = New System.Drawing.Size(338, 101)
        Me.Controls.Add(Me.Text_Password)
        Me.Controls.Add(Me.Text_Username)
        Me.Controls.Add(Me.Button_Submit)
        Me.MaximizeBox = False
        Me.MaximumSize = New System.Drawing.Size(354, 140)
        Me.MinimizeBox = False
        Me.MinimumSize = New System.Drawing.Size(354, 140)
        Me.Name = "Test_Account"
        Me.ShowIcon = False
        Me.ShowInTaskbar = False
        Me.StartPosition = System.Windows.Forms.FormStartPosition.CenterScreen
        Me.Text = "Account System"
        Me.ResumeLayout(False)
        Me.PerformLayout()

    End Sub

    Friend WithEvents Text_Username As TextBox
    Friend WithEvents Button_Submit As Button
    Friend WithEvents Text_Password As TextBox
End Class
