Import-Module -Force PasswordstatePowerShell

Describe "Get-PasswordStateAPITypePath" {
    It "Default" {
        Get-PasswordStateAPITypePath | Should -Be "winapi"
    }

    It "Standard" {
        Set-PasswordStateAPIType -APIType Standard
        Get-PasswordStateAPITypePath | Should -Be "api"
    }

    It "Windows Integrated" {
        Set-PasswordStateAPIType -APIType 'Windows Integrated'
        Get-PasswordStateAPITypePath | Should -Be "winapi"
    }
}

Describe "Get-PasswordStateAPIURL" {
    Set-PasswordStateAPIType -APIType 'Windows Integrated'
    It "Folders" {
        Get-PasswordStateAPIURL -Resource folders | Should -Be https://PasswordState/winapi/folders/
    }

    It "lists" {
        Get-PasswordStateAPIURL -Resource passwordlists -ResourceID 66 | Should -Be https://PasswordState/winapi/passwordlists/66
    }
}

$TestPasswordListName = "TestListFromExistingList"
Describe "List" {
    It "New from existing list" {
        $PasswordList = New-PasswordstateList -PasswordList $TestPasswordListName -CopySettingsFromPasswordListID 166 -CopyPermissionsFromPasswordListID 166
        $PasswordList | Should -Not -BeNullOrEmpty
    }

    #Skipping this as it seems to work based on the api documentation, suspcious there is additional undocumented requirements
    It "New from list template" -Skip {
        $PasswordList = New-PasswordstateList -PasswordList "TestListFromTemplate" -CopySettingsFromTemplateID 1 -CopyPermissionsFromTemplateID 1
        $PasswordList | Should -Not -BeNullOrEmpty
    }

    It "Get by ID" {
        $PasswordList = Get-PasswordstateList -ID 166 
        $PasswordList.PasswordListID | Should -Be 166
    }

    It "Get all" {
        $Results = Get-PasswordstateList -All 
        $Results | Should -Not -BeNullOrEmpty
    }

    It "Find by Name" {
        $PasswordList = Find-PasswordstateList -PasswordList $TestPasswordListName 
        $PasswordList.PasswordList | Should -Be $TestPasswordListName 
    }
}

Describe "Password" {
    $PesterGeneratedPhrase = "Pester generated test"
    $PasswordTitle = "$PesterGeneratedPhrase password"

    It "Generate random" {
        $PasswordstateRandomPassword = Get-PasswordstateRandomPassword
        $PasswordstateRandomPassword | Should -Not -BeNullOrEmpty
    }
    
    $PasswordList = Find-PasswordstateList -PasswordList $TestPasswordListName

    Context "Password New Get Set" {
        $Password = New-PasswordstatePassword -PasswordListID $PasswordList.PasswordListID -Title $PasswordTitle -UserName "username" -Password "password"
        It "New" {        
            $Password | Should -Not -BeNullOrEmpty
        }
    
        It "Get" {
            $PasswordRetrieved = Get-PasswordstatePassword -ID $Password.PasswordID
            $PasswordRetrieved | Should -Not -BeNullOrEmpty
        }
        
        It "Set" {
            $Password.Title | should -Be $PasswordTitle
            $NewPasswordTitle = $PasswordTitle + "2"
            $PasswordUpdated = Set-PasswordstatePassword -PasswordID $Password.PasswordID -Title $NewPasswordTitle
            $PasswordUpdated.Title | should -Be $NewPasswordTitle
            Set-PasswordstatePassword -PasswordID $Password.PasswordID -Title $PasswordTitle
        }

        It "Find across all password lists" {
            $PasswordResult = Find-PasswordstatePassword -Search $Password.Title
            $PasswordResult.Title | should -Be $PasswordTitle
        }

        It "Find from password list" {
            $PasswordResult = Find-PasswordstatePassword -Search $Password.Title -PasswordListID $Password.PasswordListID
            $PasswordResult.Title | should -Be $PasswordTitle
        }
    }
}