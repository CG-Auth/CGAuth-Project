<Global.Microsoft.VisualBasic.CompilerServices.DesignerGenerated()> _
Partial Class Select_Form
    Inherits System.Windows.Forms.Form

    'Form overrides dispose to clean up the component list.
    <System.Diagnostics.DebuggerNonUserCode()> _
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
    <System.Diagnostics.DebuggerStepThrough()> _
    Private Sub InitializeComponent()
        Me.Button_Account = New System.Windows.Forms.Button()
        Me.Button_Key = New System.Windows.Forms.Button()
        Me.SuspendLayout()
        '
        'Button_Account
        '
        Me.Button_Account.Location = New System.Drawing.Point(12, 12)
        Me.Button_Account.Name = "Button_Account"
        Me.Button_Account.Size = New System.Drawing.Size(229, 133)
        Me.Button_Account.TabIndex = 0
        Me.Button_Account.Text = "Test Account License"
        Me.Button_Account.UseVisualStyleBackColor = True
        '
        'Button_Key
        '
        Me.Button_Key.Location = New System.Drawing.Point(251, 12)
        Me.Button_Key.Name = "Button_Key"
        Me.Button_Key.Size = New System.Drawing.Size(229, 133)
        Me.Button_Key.TabIndex = 1
        Me.Button_Key.Text = "Test Key License"
        Me.Button_Key.UseVisualStyleBackColor = True
        '
        'Select_Form
        '
        Me.AutoScaleDimensions = New System.Drawing.SizeF(6.0!, 13.0!)
        Me.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font
        Me.ClientSize = New System.Drawing.Size(492, 156)
        Me.Controls.Add(Me.Button_Key)
        Me.Controls.Add(Me.Button_Account)
        Me.MaximizeBox = False
        Me.MaximumSize = New System.Drawing.Size(508, 195)
        Me.MinimizeBox = False
        Me.MinimumSize = New System.Drawing.Size(508, 195)
        Me.Name = "Select_Form"
        Me.ShowIcon = False
        Me.ShowInTaskbar = False
        Me.StartPosition = System.Windows.Forms.FormStartPosition.CenterScreen
        Me.Text = "Select"
        Me.ResumeLayout(False)

    End Sub

    Friend WithEvents Button_Account As Button
    Friend WithEvents Button_Key As Button
End Class
