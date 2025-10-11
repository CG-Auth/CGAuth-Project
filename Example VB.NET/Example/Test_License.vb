Imports System.Net

Public Class Test_License
    ''' <summary>
    ''' Event handler for Submit button - processes license key authentication
    ''' </summary>
    Private Sub Button_Submit_Click(sender As Object, e As EventArgs) Handles Button_Submit.Click
        ' Configure SSL/TLS settings for secure communication
        ' Set custom certificate validation callback
        ServicePointManager.ServerCertificateValidationCallback = AddressOf ValidateCert
        ' Force TLS 1.2 protocol for secure connection
        ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12

        ' Generate unique hardware ID for this machine
        Dim hwid As String = GetHWID()
        
        ' Authenticate using license key and HWID
        Dim result = AuthLicense(Text_License.Text, hwid)
        
        ' Check if authentication was successful
        If result("success").ToObject(Of Boolean)() Then
            ' Extract authentication data from response
            Dim data = result("data")
            Dim days = data("days_remaining").ToString()
            Dim hours = data("hours_remaining").ToString()
            Dim app_name = data("app_name").ToString()

            ' Build success message with license details
            Dim message As String = "Login successful!" & vbCrLf & vbCrLf &
                               "  • App Name: " & app_name & vbCrLf &
                               "Status: " & data("status").ToString() & vbCrLf & vbCrLf &
                               "Time Remaining:" & vbCrLf &
                               "  • Days: " & days & vbCrLf &
                               "  • Hours: " & hours & vbCrLf

            ' Verify that the license belongs to this application
            If app_name = YOUR_APP_NAME Then
                ' Display success message
                MsgBox(message, MsgBoxStyle.Information, "Success")
            Else
                ' Warn user that license is for a different application
                MsgBox("This license does not belong to this application.", MsgBoxStyle.Critical, "Success")
            End If
        Else
            ' Display error message if authentication failed
            MsgBox("Login failed!" & vbCrLf &
                   "Error: " & result("error").ToString(),
                   MsgBoxStyle.Critical, "Error")
        End If
    End Sub
End Class