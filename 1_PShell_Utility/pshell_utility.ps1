$Mainname = Read-Host -Prompt "Type 1 if its a username `nType 2 if its the Full Name (This is the full Display Name in AD) `nInput"
#$un = Read-Host -Prompt "Type in the Username ()"
#$dp = Read-Host -Prompt "Type in the Display Name (John Smith)"

if ( $Mainname -eq 1) {
    $un = Read-Host -Prompt "Type in the Username ()" 
    
    
    $Highlight = @{
        True = 'Green'
        False = 'Red'
    }

    $User = Get-ADUser $un  -Properties Enabled,LockedOut,DisplayName,GivenName,SurName,Mail,LastLogon,Created,passwordlastset,Passwordneverexpires,msDS-UserPasswordExpiryTimeComputed, Description, office, Canonicalname, homephone, mobilephone, officephone, ipphone, Department |
        Select-Object Enabled,
        @{Expression={$_.LockedOut};Label='Locked';}, 
        @{Expression={$_.DisplayName};Label='Display Name';},
        @{Expression ={$_.GivenName};Label='Name';}, `
        @{Expression ={$_.SurName}; Label='Last Name'; }, 
        @{Expression ={$_.SamAccountName}; Label='UserName'; },
        Mail,
        @{Expression ={[DateTime]::FromFileTime($_.LastLogon)}; Label='Last Logon';}, 
        @{Expression={$_.Created};Label='Date Created';}, 
        @{Expression={$_.passwordlastset};Label='PW Last Reset';}, 
        @{Expression={$_.Passwordneverexpires};Label='PW Never Expires';},
        @{Name="PW Exp Date";Expression={[datetime]::FromFileTime($_."msDS-UserPasswordExpiryTimeComputed")}},
        Description, 
        Office,
        Department,
        HomePhone,
        MobilePhone, 
        OfficePhone,
        IPPhone,
        Canonicalname | Format-list | Out-String

    $User -split "`n" | ForEach-Object {
        $Output = $False
        If ($_ -match 'Enabled|PW Never Expires|Locked') {
            ForEach ($Entry in $Highlight.Keys){
                $Text = $_ -split $Entry
                If ($Text.count -gt 1) { 
                    Write-Host $Text[0] -NoNewline
                    Write-Host $Entry -ForegroundColor $Highlight.$Entry
                    $Output = $true
                    Break
                }
            }
        }

        If (-not $Output) { Write-Host $_ }
    }

    $un | Clip

    $template = Read-Host -Prompt "Type the number associated with the issue of the account 
                                    `n1.Details of the user
                                    `n2.Account locked
                                    `n3.Lorem ipsum 
                                    `n4.Lorem ipsum 2
                                    `n5.Lorem ipsum 3
                                    `n6.Lorem ipsum
                                    `n7.Lorem ipsum
                                    `n8.Lorem ipsum
                                    `n9.Password Reset
                                    `n Input"
    switch ( $template ) {

        '1' {
            Unlock-ADAccount -Identity $un

            $Primary_account = (Get-ADUser $un -Properties * | Select-Object DisplayName, @{Expression ={$_.SamAccountName}; Label='UserName'; }, EmailAddress, Office, homephone, mobilephone, officephone, ipphone | Out-String).trim()
            Write-Output $Primary_account | Clip
        }
        '2' { Unlock-ADAccount -Identity "$un"

            $Primary_account = (Get-ADUser "$un" -Properties * | Select-Object DisplayName,@{Expression ={$_.SamAccountName}; Label='UserName'; }, EmailAddress, Office, homephone, mobilephone, officephone, ipphone | Out-String).trim()
            Write-Output $Primary_account "`nThe account is unlocked" | Clip
        }

        '3' {
            Unlock-ADAccount -Identity $un

            $Primary_account = (Get-ADUser $un -Properties * | Select-Object DisplayName, @{Expression ={$_.SamAccountName}; Label='UserName'; }, EmailAddress, Office, homephone, mobilephone, officephone, ipphone | Out-String).trim()
            Write-Output $Primary_account "`nLorem ipsum" | Clip
        }

        '4' {
            Unlock-ADAccount -Identity $un

            $Primary_account = (Get-ADUser $un -Properties * | Select-Object DisplayName, @{Expression ={$_.SamAccountName}; Label='UserName'; }, EmailAddress, Office, homephone, mobilephone, officephone, ipphone | Out-String).trim()
            Write-Output $Primary_account "`nLorem ipsum" | Clip
        }

        '5' {
            Unlock-ADAccount -Identity $un

            $Primary_account = (Get-ADUser $un -Properties * | Select-Object DisplayName, @{Expression ={$_.SamAccountName}; Label='UserName'; }, EmailAddress, Office, homephone, mobilephone, officephone, ipphone | Out-String).trim()
            Write-Output $Primary_account "`nLorem ipsum" | Clip

        }

        '6' {
            Unlock-ADAccount -Identity $un

            $Primary_account = (Get-ADUser $un -Properties * | Select-Object DisplayName, @{Expression ={$_.SamAccountName}; Label='UserName'; }, EmailAddress, Office, homephone, mobilephone, officephone, ipphone | Out-String).trim()
            Write-Output $Primary_account "`nLorem ipsum." | Clip
        } 

        '7' {
            Unlock-ADAccount -Identity $un

            $Primary_account = (Get-ADUser $un -Properties * | Select-Object DisplayName, @{Expression ={$_.SamAccountName}; Label='UserName'; }, EmailAddress, Office, homephone, mobilephone, officephone, ipphone | Out-String).trim()
            Write-Output $Primary_account "`n Lorem ipsum" | Clip
        }

        '8' {
            Unlock-ADAccount -Identity $un

            $Primary_account = (Get-ADUser $un -Properties * | Select-Object DisplayName, @{Expression ={$_.SamAccountName}; Label='UserName'; }, EmailAddress, Office, homephone, mobilephone, officephone, ipphone | Out-String).trim()
            Write-Output $Primary_account "`nUser requested a new folder to be created. The full path of the folder is:
                                           `n..." | Clip
        }
        '9' {
            Unlock-ADAccount -Identity $un

            function Get-RandomCharacters($length, $characters) {
                $random = 1..$length | ForEach-Object { Get-Random -Maximum $characters.length }
                $private:ofs=""
                return [String]$characters[$random]
            }
             
            function Scramble-String([string]$inputString){     
                $characterArray = $inputString.ToCharArray()   
                $scrambledStringArray = $characterArray | Get-Random -Count $characterArray.Length     
                $outputString = -join $scrambledStringArray
                return $outputString 
            }
             
            $pswd = Get-RandomCharacters -length 5 -characters 'abcdefghiklmnoprstuvwxyz'
            $pswd += Get-RandomCharacters -length 1 -characters 'ABCDEFGHKLMNOPRSTUVWXYZ'
            $pswd += Get-RandomCharacters -length 1 -characters '1234567890'
            $pswd += Get-RandomCharacters -length 1 -characters '!$%&=?@#*+'
             
            $pswd = Scramble-String $pswd 
             
            Write-Host $pswd
            Unlock-ADAccount -Identity $un
            
            Set-ADAccountPassword –Identity $un –Reset –NewPassword (ConvertTo-SecureString -AsPlainText $pswd -Force)
            
            $Primary_account = (Get-ADUser $un -Properties * | Select-Object DisplayName, EmailAddress, Office, homephone, mobilephone, officephone, ipphone | Out-String).trim()
            Write-Output $Primary_account "`nUser requested a new password" | Clip
        }
}

    

} elseif ( $Mainname -eq 2) {
        $dp = Read-Host -Prompt "Type in the Display Name (John Smith)"
        $dpun = Get-AdUser -filter "DisplayName -like '$dp'" | Select-Object Samaccountname 
        
        $Highlight = @{
        True = 'Green'
        False = 'Red'
    }

    $User = Get-ADUser $dpun.SamAccountName -Properties Enabled,LockedOut,DisplayName,GivenName,SurName,Mail,LastLogon,Created,passwordlastset,Passwordneverexpires,msDS-UserPasswordExpiryTimeComputed, Description, office, Canonicalname, homephone, mobilephone, officephone, ipphone, Department |
        Select-Object Enabled,
        @{Expression={$_.LockedOut};Label='Locked';}, 
        @{Expression={$_.DisplayName};Label='Display Name';},
        @{Expression ={$_.GivenName};Label='Name';}, `
        @{Expression ={$_.SurName}; Label='Last Name'; }, 
        @{Expression ={$_.SamAccountName}; Label='UserName'; },
        Mail,
        @{Expression ={[DateTime]::FromFileTime($_.LastLogon)}; Label='Last Logon';}, 
        @{Expression={$_.Created};Label='Date Created';}, 
        @{Expression={$_.passwordlastset};Label='PW Last Reset';}, 
        @{Expression={$_.Passwordneverexpires};Label='PW Never Expires';},
        @{Name="PW Exp Date";Expression={[datetime]::FromFileTime($_."msDS-UserPasswordExpiryTimeComputed")}},
        Description, 
        Office,
        Department,
        HomePhone,
        MobilePhone, 
        OfficePhone,
        IPPhone,
        Canonicalname | Format-list | Out-String

    $User -split "`n" | ForEach-Object {
        $Output = $False
        If ($_ -match 'Enabled|PW Never Expires|Locked') {
            ForEach ($Entry in $Highlight.Keys){
                $Text = $_ -split $Entry
                If ($Text.count -gt 1) { 
                    Write-Host $Text[0] -NoNewline
                    Write-Host $Entry -ForegroundColor $Highlight.$Entry
                    $Output = $true
                    Break
                }
            }
        }

        If (-not $Output) { Write-Host $_ }
    }

    $dpun.SamAccountName | Clip

    $template = Read-Host -Prompt "Type the number associated with the issue of the account 
                                    `n1.Details of the user (Blank with no template)
                                    `n2.Account locked
                                    `n3.Lorem ipsum 
                                    `n4.Lorem ipsum
                                    `n5.Lorem ipsum
                                    `n6.Lorem ipsum
                                    `n7.Lorem ipsum
                                    `n8.Folder creation
                                    `n9.Password reset
                                    `n Input"
    switch ( $template ) {

        '1' {
            Unlock-ADAccount -Identity $dpun.SamAccountName

            $Primary_account = (Get-ADUser $dpun.SamAccountName -Properties * | Select-Object DisplayName, @{Expression ={$_.SamAccountName}; Label='UserName'; }, EmailAddress, Office, homephone, mobilephone, officephone, ipphone | Out-String).trim()
            Write-Output $Primary_account | Clip
        }
        '2' { Unlock-ADAccount -Identity $dpun.SamAccountName

            $Primary_account = (Get-ADUser $dpun.SamAccountName -Properties * | Select-Object DisplayName,@{Expression ={$_.SamAccountName}; Label='UserName'; }, EmailAddress, Office, homephone, mobilephone, officephone, ipphone | Out-String).trim()
            Write-Output $Primary_account "`nThe account is unlocked" | Clip
        }

        '3' {
            Unlock-ADAccount -Identity $dpun.SamAccountName

            $Primary_account = (Get-ADUser $dpun.SamAccountName -Properties * | Select-Object DisplayName, @{Expression ={$_.SamAccountName}; Label='UserName'; }, EmailAddress, Office, homephone, mobilephone, officephone, ipphone | Out-String).trim()
            Write-Output $Primary_account "`nLorem ipsum" | Clip
        }

        '4' {
            Unlock-ADAccount -Identity $dpun.SamAccountName

            $Primary_account = (Get-ADUser $dpun.SamAccountName -Properties * | Select-Object DisplayName, SamAccountName, EmailAddress, Office, homephone, mobilephone, officephone, ipphone | Out-String).trim()
            Write-Output $Primary_account "`nLorem ipsum" | Clip
        }

        '5' {
            Unlock-ADAccount -Identity $dpun.SamAccountName

            $Primary_account = (Get-ADUser $dpun.SamAccountName -Properties * | Select-Object DisplayName, @{Expression ={$_.SamAccountName}; Label='UserName'; }, EmailAddress, Office, homephone, mobilephone, officephone, ipphone | Out-String).trim()
            Write-Output $Primary_account "`nLorem ipsum" | Clip

        }

        '6' {
            Unlock-ADAccount -Identity $dpun.SamAccountName

            $Primary_account = (Get-ADUser $dpun.SamAccountName -Properties * | Select-Object DisplayName, @{Expression ={$_.SamAccountName}; Label='UserName'; }, EmailAddress, Office, homephone, mobilephone, officephone, ipphone | Out-String).trim()
            Write-Output $Primary_account "`nLorem ipsum" | Clip
        } 

        '7' {
            Unlock-ADAccount -Identity $dpun.SamAccountName

            $Primary_account = (Get-ADUser $dpun.SamAccountName -Properties * | Select-Object DisplayName, @{Expression ={$_.SamAccountName}; Label='UserName'; }, EmailAddress, Office, homephone, mobilephone, officephone, ipphone | Out-String).trim()
            Write-Output $Primary_account "`nLorem ipsum" | Clip
        }

        '8' {
            Unlock-ADAccount -Identity $dpun.SamAccountName

            $Primary_account = (Get-ADUser $dpun.SamAccountName -Properties * | Select-Object DisplayName, @{Expression ={$_.SamAccountName}; Label='UserName'; }, EmailAddress, Office, homephone, mobilephone, officephone, ipphone | Out-String).trim()
            Write-Output $Primary_account "`nLorem ipsum
                                            `n..." | Clip
        }
        '9' {
            Unlock-ADAccount -Identity $dpun.SamAccountName

            function Get-RandomCharacters($length, $characters) {
                $random = 1..$length | ForEach-Object { Get-Random -Maximum $characters.length }
                $private:ofs=""
                return [String]$characters[$random]
            }
             
            function Scramble-String([string]$inputString){     
                $characterArray = $inputString.ToCharArray()   
                $scrambledStringArray = $characterArray | Get-Random -Count $characterArray.Length     
                $outputString = -join $scrambledStringArray
                return $outputString 
            }
             
            $pswd = Get-RandomCharacters -length 5 -characters 'abcdefghiklmnoprstuvwxyz'
            $pswd += Get-RandomCharacters -length 1 -characters 'ABCDEFGHKLMNOPRSTUVWXYZ'
            $pswd += Get-RandomCharacters -length 1 -characters '1234567890'
            $pswd += Get-RandomCharacters -length 1 -characters '!$%&=?@#*+'
             
            $pswd = Scramble-String $pswd 
             
            Write-Host $pswd
            Unlock-ADAccount -Identity $dpun.SamAccountName
            
            Set-ADAccountPassword –Identity $dpun.SamAccountName –Reset –NewPassword (ConvertTo-SecureString -AsPlainText $pswd -Force)
            
            $Primary_account = (Get-ADUser $dpun.SamAccountName -Properties * | Select-Object DisplayName, EmailAddress, Office, homephone, mobilephone, officephone, ipphone | Out-String).trim()
            Write-Output $Primary_account "`nUser requested a new password" | Clip
            }
        }   
    }

