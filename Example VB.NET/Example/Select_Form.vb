Public Class Select_Form
    ''' <summary>
    ''' Event handler for Account authentication button
    ''' Opens the username/password authentication form
    ''' </summary>
    Private Sub Button_Account_Click(sender As Object, e As EventArgs) Handles Button_Account.Click
        ' Show the account authentication form
        Test_Account.Show()
        ' Hide the current selection form
        Me.Hide()
    End Sub

    ''' <summary>
    ''' Event handler for License Key authentication button
    ''' Opens the license key authentication form
    ''' </summary>
    Private Sub Button_Key_Click(sender As Object, e As EventArgs) Handles Button_Key.Click
        ' Show the license key authentication form
        Test_License.Show()
        ' Hide the current selection form
        Me.Hide()
    End Sub
End Class