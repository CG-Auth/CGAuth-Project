<Global.Microsoft.VisualBasic.CompilerServices.DesignerGenerated()> _
Partial Class Test_License
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
        Me.Button_Submit = New System.Windows.Forms.Button()
        Me.Text_License = New System.Windows.Forms.TextBox()
        Me.SuspendLayout()
        '
        'Button_Submit
        '
        Me.Button_Submit.Font = New System.Drawing.Font("Microsoft Sans Serif", 14.25!, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, CType(162, Byte))
        Me.Button_Submit.Location = New System.Drawing.Point(12, 35)
        Me.Button_Submit.Name = "Button_Submit"
        Me.Button_Submit.Size = New System.Drawing.Size(314, 59)
        Me.Button_Submit.TabIndex = 0
        Me.Button_Submit.Text = "Submit"
        Me.Button_Submit.UseVisualStyleBackColor = True
        '
        'Text_License
        '
        Me.Text_License.Location = New System.Drawing.Point(12, 10)
        Me.Text_License.Name = "Text_License"
        Me.Text_License.Size = New System.Drawing.Size(314, 20)
        Me.Text_License.TabIndex = 1
        Me.Text_License.Text = "LICENSE-KEY"
        '
        'Test_License
        '
        Me.AutoScaleDimensions = New System.Drawing.SizeF(6.0!, 13.0!)
        Me.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font
        Me.ClientSize = New System.Drawing.Size(338, 101)
        Me.Controls.Add(Me.Text_License)
        Me.Controls.Add(Me.Button_Submit)
        Me.MaximizeBox = False
        Me.MaximumSize = New System.Drawing.Size(354, 140)
        Me.MinimizeBox = False
        Me.MinimumSize = New System.Drawing.Size(354, 140)
        Me.Name = "Test_License"
        Me.ShowIcon = False
        Me.ShowInTaskbar = False
        Me.StartPosition = System.Windows.Forms.FormStartPosition.CenterScreen
        Me.Text = "License System"
        Me.TopMost = True
        Me.ResumeLayout(False)
        Me.PerformLayout()

    End Sub

    Friend WithEvents Button_Submit As Button
    Friend WithEvents Text_License As TextBox
End Class
