
function Mainmenu()
{

    Write-Host -ForegroundColor White -BackgroundColor DarkGray "******************************************************************************************************************************"
    Write-Host -ForegroundColor White -BackgroundColor DarkGray "***************************** Script de despliegue de usuarios, grupos, roles y permisos Azure********************************"
    Write-Host -ForegroundColor White -BackgroundColor DarkGray "******************************************************************************************************************************"
    
    Do {
    Write-Host -ForegroundColor White -BackgroundColor DarkGray "
    <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<< Menu >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
    (X) 1. Desplegar permisos nueva suscripción
    (X) 2. Reenviar invitaciones Azure AD para usuarios pendientes de aceptar
    (X) 3. Añadir un nuevo usuario y dar permisos
    (X) 4. Dar de baja usuario y quitar permisos
    (X) 5. Salir"

    $global:menu = read-host -prompt "Selecciona una opcion y presiona Intro"
    }
    until ($menu -eq "1" -or $menu-eq "2" -or $menu-eq "3" -or $menu -eq "4" -or $menu -eq "5")

    if ($menu -eq 1){

        #######Login in Azure CSP Subscription and Select desire Subscription to deploy permissionns#######
    
        Write-Host -ForegroundColor White -BackgroundColor Green "******************************************************************************************************************************"
        Write-Host -ForegroundColor White -BackgroundColor Green "***************************************************Login Azure Account********************************************************"
        Write-Host -ForegroundColor White -BackgroundColor Green "******************************************************************************************************************************"
    
        Login

        Subscriptions 
    
        ######Import Custom Roles in new Azure Subscription########## 
    
        Write-Host -ForegroundColor White -BackgroundColor Green "******************************************************************************************************************************"
        Write-Host -ForegroundColor White -BackgroundColor Green "*****************************************Creation and Import of Custom RBAC Roles*********************************************"
        Write-Host -ForegroundColor White -BackgroundColor Green "******************************************************************************************************************************"
    
        Importrolesrbac
    
        ######Create Azure AD Groups and Associate Custom Roles to Groups#######
    
        Write-Host -ForegroundColor White -BackgroundColor Green "******************************************************************************************************************************"
        Write-Host -ForegroundColor White -BackgroundColor Green "*****************************************************Prepare Azure AD*********************************************************"
        Write-Host -ForegroundColor White -BackgroundColor Green "******************************************************************************************************************************"
    
        Prepareadtenant
    
        #######Give permissions to new Azure Subscription#########
        Write-Host -ForegroundColor White -BackgroundColor Green "******************************************************************************************************************************"
        Write-Host -ForegroundColor White -BackgroundColor Green "*************************************************Assign User Permissions******************************************************"
        Write-Host -ForegroundColor White -BackgroundColor Green "******************************************************************************************************************************"
    
        Permissions
    
    
    
    }
    elseif ($menu -eq 2){
    
        resendinvitation
    }
    elseif ($menu -eq 3){
    
        adduser
    }
    elseif ($menu -eq 4){
    
        removeuser
    }
    elseif ($menu -eq 5){
    
        Write-Log -Level Info "Saliendo del Script"
    
        exit
    
    }
}
function Login()
{
    ######Login Azure#####

    $global:credentials = Get-Credential 

    Write-Log -level Info -Message "Iniciando sesion en Azure con el usuario $($credentials.UserName)"

    Login-AzAccount -Credential $credentials | Out-Null 
 
}
function subscriptions()
{
   
   ######Define EA Seidor ID to show only all subscriptions of CSP Tenant#####

   $seidorea = '654623d6-1504-4f22-a146-b7c72637766a'

   ######Obtain all Azure Subscriptions#####
        
   Write-Log -Level Info -Message "Obteniendo todas las subscripciones CSP a las que el usuario $($credentials.UserName) tiene acceso"
        
   $subs = Get-AzSubscription
        
   ######Create empty Array to save Tenant/tenants to deploy Roles and Permissions#####
        
   $Tennants = @()
        
   foreach ($sub in $subs){
        
     if ($sub.TenantId -ne $seidorea){
        
         $Tennants += $sub
    
     }
   }
        
   $global:cspsubscriptions = @($Tennants | Out-GridView -Title "Selecciona la subscripcion para la configuración y despliegue de permisos" -PassThru)

}
function Prepareadtenant()
{

    ######Conection to Azure AD#######

    $global:tenantdata = Connect-AzureAD -TenantId $tenantid -Credential $credentials

    
    ######Creation of AD Groups and Assigns to Custom Roles######

    $azureadgroups = @("DST_Administrador","DST_NOC_avanzado","DST_NOC_basico","DST_Operador_avanzado","DST_Operador_basico","DST_Tecnico_2nivel","DST_Reportes")

    foreach ($group in $azureadgroups){


        $existgroup = Get-AzureADGroup -SearchString "$($group)"

        if ($nul -eq $existgroup){


            Write-Log -Level Info "Creando Grupo $($group) en Azure AD"

            New-AzureADGroup -MailNickName "$($group)" -MailEnabled:$false -SecurityEnabled:$true -DisplayName "$($group)" | Out-Null

        }

        else {

            Write-Log -Level Info "El grupo $($group) ya existia en Azure AD"

        }

        $ObjGroup = (Get-AzureADGroup -SearchString "$($group)")


        if ($group -like "DST_Administrador"){

            $rol = "Administrador RD"
        }
        elseif ($group -like "DST_NOC_avanzado"){

            $rol = "NOC Avanzado RD"
        }
        elseif ($group -like "DST_NOC_basico"){

            $rol = "NOC Basico RD"
        }
        elseif ($group -like "DST_Operador_avanzado"){

            $rol = "Operador Avanzado RD"
        }
        elseif ($group -like "DST_Operador_basico"){

            $rol = "Operador Basico RD"
        }
        elseif ($group -like "DST_Tecnico_2nivel") {

            $rol = "Tecnico Nivel2 RD"
            
        }
        elseif($group -like "DST_Reportes"){

            $rol = "Reports Azure RD"

        }
        
        $minutes = 1
        
        $SecondsPerLoop = (($minutes * 60)/100)
    
        Write-log -level Info "Esperando $($minutes) minuto para hacer efectiva la creación del grupo $($group) en Azure AD." 

        if($DEBUG_MODE -eq $true){ $SecondsPerLoop = 0.001 } 

            $TimeStart = (Get-Date -Format "HH:mm") ; $TimeEnd = (Get-Date).AddMinutes($minutes) ; $TimeEnd = "$($TimeEnd.Hour):$($TimeEnd.Minute)"

            for ($a=1; $a -lt 100; $a++)
            {
                $TimeNow = (Get-Date -Format "HH:mm")
                Write-Progress -Activity "Creando el Grupo '$($group) en Azure AD' >> Inicio de la espera: $($TimeStart) / Reanudación: $($TimeEnd) / Actual: $($TimeNow)" -PercentComplete $a -CurrentOperation "$a% complete" -Status "Please wait."
                Start-Sleep -Milliseconds ($SecondsPerLoop*1000) -ErrorAction SilentlyContinue
            }  


        New-AzRoleAssignment -ObjectId "$($ObjGroup.ObjectId)" -RoleDefinitionName "$($Rol)" -Scope "/subscriptions/$($NewSuscriptionDeploymentID)" | Out-Null
 

    }


                
}
function Importrolesrbac()
{
        $TempPath = $env:TEMP
        $ScriptFullPathName = "C:\Users\vmarquez2\OneDrive - SEIDOR SA\Azure\Scripts\Aplicar Permisos Suscripciones Azure\Aplicar-Permisos-CSP.ps1" #######Path Script CSP Pemrissions#####
        Write-Log -Level Info "Creando ficheros Json para importar roles personalizados RBAC...."

        Json-ReParse -InputFile $ScriptFullPathName -OutputFile "$($TempPath)\AdministradorRD.json"    -ScrtExpr "#<ROL>#AdministradorRD#"
        Json-ReParse -InputFile $ScriptFullPathName -OutputFile "$($TempPath)\NOCAvanzadoRD.json"      -ScrtExpr "#<ROL>#NOCAvanzadoRD#"
        Json-ReParse -InputFile $ScriptFullPathName -OutputFile "$($TempPath)\NOCbasicoRD.json"        -ScrtExpr "#<ROL>#NOCbasicoRD#"
        Json-ReParse -InputFile $ScriptFullPathName -OutputFile "$($TempPath)\OperadorAvanzadoRD.json" -ScrtExpr "#<ROL>#OperadorAvanzadoRD#"
        Json-ReParse -InputFile $ScriptFullPathName -OutputFile "$($TempPath)\OperadorBasicoRD.json"   -ScrtExpr "#<ROL>#OperadorBasicoRD#"
        Json-ReParse -InputFile $ScriptFullPathName -OutputFile "$($TempPath)\Tecniconivel2RD.json"    -ScrtExpr "#<ROL>#Tecniconivel2RD#"
        Json-ReParse -InputFile $ScriptFullPathName -OutputFile "$($TempPath)\ReportsAzureRD.json"     -ScrtExpr "#<ROL>#ReportsAzureRD#"

        ########Import Json Files created previously to create Roles#########

        Write-Log -Level Info "Creando roles personalizados en la Subscripcion $($cspsubscriptions.name)"

        Write-Log -Level Info "Importing Rol Administrador RD ..."

        New-AzRoleDefinition -InputFile "$($TempPath)\AdministradorRD.json"
        
        Write-Log -Level Info "Importing Rol NOC Avanzado..."

        New-AzRoleDefinition -InputFile "$($TempPath)\NOCAvanzadoRD.json"

        Write-Log -Level Info "Importing Rol NOC Basico..."

        New-AzRoleDefinition -InputFile "$($TempPath)\NOCbasicoRD.json" 

        Write-Log -Level Info "Importing Rol Operador Avanzado..."

        New-AzRoleDefinition -InputFile "$($TempPath)\OperadorAvanzadoRD.json" 

        Write-Log -Level Info "Importing Rol Operador Basico..."

        New-AzRoleDefinition -InputFile "$($TempPath)\OperadorBasicoRD.json" 

        Write-Log -Level Info "Importing Rol Tecnico Nivel 2...."

        New-AzRoleDefinition -InputFile "$($TempPath)\Tecniconivel2RD.json" 

        Write-Log -Level Info "Importing Rol Reports Azure..."

        New-AzRoleDefinition -InputFile "$($TempPath)\ReportsAzureRD.json" 

        #######Time Wait to allow Azure to create Custom Roles##########


        $minutes = 10
        $SecondsPerLoop = (($minutes * 60)/100)
    
        Write-log -level Info "Esperando $($minutes) minutos para hacer efectiva la creación de roles..." 

        if($DEBUG_MODE -eq $true){ $SecondsPerLoop = 0.001 } 

            $TimeStart = (Get-Date -Format "HH:mm") ; $TimeEnd = (Get-Date).AddMinutes($minutes) ; $TimeEnd = "$($TimeEnd.Hour):$($TimeEnd.Minute)"

            for ($a=1; $a -lt 100; $a++)
            {
                $TimeNow = (Get-Date -Format "HH:mm")
                Write-Progress -Activity "Aplicando Roles en la suscripcion '$($cspsubscriptions.name)' >> Inicio de la espera: $($TimeStart) / Reanudación: $($TimeEnd) / Actual: $($TimeNow)" -PercentComplete $a -CurrentOperation "$a% complete" -Status "Please wait."
                Start-Sleep -Milliseconds ($SecondsPerLoop*1000) -ErrorAction SilentlyContinue
            }  


        Write-Log -Level Info "Borrando ficheros Json creados de forma temporal para la creacion de los roles en Azure..."

        Remove-Item -Force -Path "$($TempPath)\AdministradorRD.json"
        Remove-Item -Force -Path "$($TempPath)\NOCAvanzadoRD.json"
        Remove-Item -Force -Path "$($TempPath)\NOCbasicoRD.json"
        Remove-Item -Force -Path "$($TempPath)\OperadorAvanzadoRD.json"
        Remove-Item -Force -Path "$($TempPath)\OperadorBasicoRD.json"
        Remove-Item -Force -Path "$($TempPath)\Tecniconivel2RD.json"
        Remove-Item -Force -Path "$($TempPath)\ReportsAzureRD.json"

}
function Permissions()
{
    Connect-AzureAD -TenantId $tenantid -Credential $credentials
    
    #######Import CSV with Users Pemrissions#######

    $users = Import-Csv -Path 'C:\temp\Roles CSP.csv' -Header @("Username","Email","Rol","ADGroup","RolAD")

    foreach ($user in $users){

        ######Obatin User Name########

        Write-Log -Level Info "Obtaining Username for user $($user.username)"

        $username = $user.Username

        ######Obatin Email Address########

        Write-Log -Level Info "Obtaining Email Address for user $($username)"

        $email= $user.email

        $guest = $email.Replace("@","_")

        $guest = "$($guest)#EXT#@$($tenantData.TenantDomain)"

        ######Obating Rol User########

        Write-Log -Level Info "Obtaining Rol - $($user.rol) - for User $($username)"

        $rol = $user.Rol

        ######Obatin AD Group########

        Write-Log -Level Info "Obtaining AD Group - $($user.adgroup) - for User $($username)"

        $adgroup = $user.ADGroup

        ######Obatin Rol AD########

        $adrol = $user.RolAD

        if ($adrol -notlike $null)
        {
            Write-Log -Level Info "Obtaining Rol AD - $($adrol) - for User $($username)"
        }


        #####Creation of User in Azure AD######

        New-AzureADMSInvitation -InvitedUserDisplayName $username -InvitedUserEmailAddress $email -SendInvitationMessage $false -InviteRedirectURL  https://myapps.azure.com -InvitedUserType Member
         

        Start-Sleep -Seconds 30

        #############################################################################################
        ######################################Assing Groups##########################################
        #############################################################################################

        ######List All Azure AD Users######

        $AllAzUsers = (Get-AzureADUser -All:$true)

        ######Obain Azure AD User ID########

        
        foreach ($azuser in $AllAzUsers){

            if ($guest -eq $azuser.userprincipalname){

                $useridguest = $azuser.ObjectId
            }
        }

        #######Obtain Azure AD Group ID#######

        $ObjGroupid = (Get-AzureADGroup -SearchString "$($adgroup)").ObjectId

        #######Add User Guest to Azure AD Group######

        Write-Log -Level Info "Adding User $($username) to Azure AD Group $($adgroup)"
        
        Add-AzureADGroupMember -ObjectId $ObjGroupid -RefObjectId $useridguest

        
        
        if ($adrol -notlike $null)
        {
            Connect-MsolService -Credential $credentials | Out-Null

            Write-Log -Level Info "Adding Rol $($adrol) to user $username in Azure AD"

            Add-MsolRoleMember -RoleMemberEmailAddress $guest -RoleName "$($adrol)"

        }

        Pause

        
    }

}
function Resendinvitation()
{
     ######Conection to Azure AD#######

     Write-Log -Level Info "Connectando a AzureAD..."

     $global:tenantdata = Connect-AzureAD -TenantId $tenantid -Credential $credentials

     ########################################

     Write-Log -Level Info "Obteniendo el listado de usuarios que todavía no han aceptado la invitacion..."

     $pendingusers = Get-AzureADUser -Filter "UserState eq 'PendingAcceptance'" 

    if ($null -ne $pendingusers){

        Write-Host -BackgroundColor DarkGray -ForegroundColor White "Los siguientes usuarios no han aceptado la invitación en AzureAD:"

        $pendingusers | Format-Table -Property DisplayName,UserPrincipalName,UserState,UserStateChangedOn

        do {

            $response = Read-Host -Prompt  "¿Desea reenviar la invitación a los usuarios? [Y/N]"

        } 
        until ($response -eq 'n' -or $response -eq 'y')

        if ($response -eq 'y'){

            foreach ($pendinguser in $pendingusers){

                $domainroot = $tenantData.TenantDomain
                $domain = "#EXT#@$domainroot"
                $email1 = $pendingusers.UserPrincipalName.Replace('_','@')
                $email2 = $email1 -replace ("$domain","")
                Pause
                New-AzureADMSInvitation -InvitedUserDisplayName $pendinguser.DisplayName -InvitedUserEmailAddress $email2 -SendInvitationMessage $true -InviteRedirectURL  https://myapps.azure.com -InvitedUserType Member

            }
   
        }
        else{

            Write-host "NO"
            mainmenu
        }

    }
}
function Json-ReParse($InputFile,$OutputFile,$ScrtExpr)
{

    $Blank = ""; $BuildingScriptLine = "" ; $GenericSuscriptionID = '11111111-2222-3333-4444-555555555555'

    if(Test-Path $OutputFile) # Si el fichero de salida existe
    {
        New-Item -ItemType File -Force -Path $OutputFile | Out-Null
    }

    foreach($Line in Get-Content $InputFile)
    {
        if($Line -like "$($ScrtExpr)*")
        {
            $BuildingScriptLine = "$($Line.Replace($ScrtExpr,$Blank))"

            if($Outputfile -like "*.json")
            {
                if($BuildingScriptLine -like "*$($GenericSuscriptionID)*")
                {
                    $BuildingScriptLine = "$($BuildingScriptLine.Replace($GenericSuscriptionID,$NewSuscriptionDeploymentID))"
                    $BuildingScriptLine | Out-File -FilePath $OutputFile -Append -Encoding unicode -Force                    
                }
                else
                {
                    $BuildingScriptLine | Out-File -FilePath $OutputFile -Append -Encoding unicode -Force
                }
            }
            else
            {
                $BuildingScriptLine | Out-File -FilePath $OutputFile -Append -Encoding ascii -Force
            }
        }
    }
}
function Write-Log() 
{ 
        
            
        
            [CmdletBinding()]
             
            Param 
            ( 
                [Parameter(Mandatory=$true, 
                ValueFromPipelineByPropertyName=$true)] 
                [ValidateNotNullOrEmpty()] 
                [Alias("LogContent")] 
                [string]$Message,  
                 
                [Parameter(Mandatory=$false)] 
                [ValidateSet("Error","Warn","Info")] 
                [string]$Level="Info", 
                 
                [Parameter(Mandatory=$false)] 
                [switch]$NoClobber 
            ) 
         
            Begin 
            { 
                # Set VerbosePreference to Continue so that verbose messages are displayed. 
                $VerbosePreference = 'Continue' 
            } 
            Process 
            { 
                $date = Get-Date -Format "yyyy-MM-dd" 
        
                $Path = "$env:UserProfile\Desktop\Log_Azure_Reserve_Intance_$date.log"
                 
                # If the file already exists and NoClobber was specified, do not write to the log. 
                if ((Test-Path $Path) -AND $NoClobber) { 
                    Write-Error "Log file $Path already exists, and you specified NoClobber. Either delete the file or specify a different name." 
                    Return 
                    } 
         
                # If attempting to write to a log file in a folder/path that doesn't exist create the file including the path. 
                elseif (!(Test-Path $Path)) { 
                    Write-Verbose "Creating $Path." 
                    $NewLogFile = New-Item $Path -Force -ItemType File 
                    } 
         
                else { 
                    # Nothing to see here yet. 
                    } 
         
                # Format Date for our Log File 
                $FormattedDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss" 
         
                # Write message to error, warning, or verbose pipeline and specify $LevelText 
                switch ($Level) { 
                    'Error' { 
                        Write-Error $Message 
                        $LevelText = 'ERROR:' 
                        } 
                    'Warn' { 
                        Write-Warning $Message 
                        $LevelText = 'WARNING:' 
                        } 
                    'Info' { 
                        Write-Verbose $Message 
                        $LevelText = 'INFO:' 
                        } 
                    } 
                 
                # Write log entry to $Path 
                "$FormattedDate $LevelText $Message" | Out-File -FilePath $Path -Append 
            } 
            End 
            { 
            } 
}
function Adduser()
{
    
    Login 

    subscriptions

    Write-Log -Level Info -Message "Realizando Login en la Suscripcion $($cspsubscriptions.name)"


    Select-AzSubscription -SubscriptionName $cspsubscriptions.name | Out-Null

    $global:tenantid = $cspsubscriptions.TenantId

    $global:NewSuscriptionDeploymentID = $cspsubscriptions.Id

    ################Import CSV with data od Users with access to Azure################

    $users = Import-Csv -Path 'C:\temp\Roles CSP.csv' -Header @("Username","Email","Rol","ADGroup","RolAD") | Out-GridView -Title "Selecciona el/los usuarios necesarios a dar permisos en la subscripción $($azsubscription)" -OutputMode Multiple
    
    Write-Log -Level Info "Conectandose al AzureAD de la subscripción: $($cspsub.name)"

    $global:tenantdataadduser = Connect-AzureAD -Credential $credentials -TenantId $tenantid 

    foreach ($user in $users){
        
        Write-Log -Level Info "Enviando invitaci�n al dominio de Azure $($tenantdataadduser.TenantDomain)"

        New-AzureADMSInvitation -InvitedUserDisplayName $user.username -InvitedUserEmailAddress $user.email -SendInvitationMessage $true -InviteRedirectURL  https://myapps.azure.com -InvitedUserType Member | Out-Null
        

        #############################################################################################
        ######################################Assing Groups##########################################
        #############################################################################################
        
        ######Obatin Email Address ang Guest Name in Azure AD########

        Write-Log -Level Info "Obtaining Email Address for user $($user.username)"

        $email= $user.email

        $guest = $email.Replace("@","_")

        $guest = "$($guest)#EXT#@$($tenantdataadduser.TenantDomain)" 

        Write-Log -Level Info "Waiting 30 Segundos para la creaci�n del usuario $($email) en AzureAD"

        Start-Sleep -Seconds 30
       

        ######List All Azure AD Users######

        $AllAzUsers = (Get-AzureADUser -All:$true)

        ######Obain Azure AD User Object ID########

        
        foreach ($azuser in $AllAzUsers){

            if ($guest -eq $azuser.userprincipalname){

                $useridguest = $azuser.ObjectId

        }
    }

    #######Obtain Azure AD Group ID#######

    $ObjGroupid = (Get-AzureADGroup -SearchString "$($user.adgroup)").ObjectId

    #######Add User Guest to Azure AD Group######

    Write-Log -Level Info "Adding User $($user.username) to Azure AD Group $($user.adgroup)"
        
    Add-AzureADGroupMember -ObjectId $ObjGroupid -RefObjectId $useridguest

    ######Obatin Rol AD########

    $adrol = $user.RolAD

    if ($adrol -notlike $null)
    {
        Connect-MsolService -Credential $credentials | Out-Null
 
        Write-Log -Level Info "Adding Rol $($adrol) to user $($user.username) in Azure AD"
 
        Add-MsolRoleMember -RoleMemberEmailAddress $guest -RoleName "$($adrol)"
 
    } 
        

    }


}
function Removeuser()
{
    
    Login       

    ######Define EA Seidor ID to show only all subscriptions of CSP Tenant#####

    $seidorea = '654623d6-1504-4f22-a146-b7c72637766a'

    ######Obtain all Azure Subscriptions#####
        
    Write-Log -Level Info -Message "Obteniendo todas las subscripciones CSP a las que el usuario $($credentials.UserName) tiene acceso"
        
    $subs = Get-AzSubscription 
        
    ######Create empty Array to save Tenant/tenants to deploy Roles and Permissions#####
        
    $Tennants = @()
        
    foreach ($sub in $subs){
        
     if ($sub.TenantId -ne $seidorea){
        
         $Tennants += $sub
    
     }
    }

    $removeusers = Import-Csv -Path 'C:\temp\Roles CSP.csv' -Header @("Username","Email","Rol","ADGroup","RolAD") | Out-GridView -Title "Selecciona el/los usuarios necesarios a dar de baja en las subscripciones CSP de Azure $($azsubscription)" -OutputMode Multiple


    foreach ($tenant in $Tennants){
        
        Write-Log -Level Info -Message "Realizando Login en la Suscripcion $($tenant.name)"

        Select-AzSubscription -SubscriptionName $tenant.name | Out-Null

        $global:tenantid = $tenant.TenantId

        #$global:NewSuscriptionDeploymentID = $tenant.Id

        ################Connect Azure AD################

        $global:tenantdataadduser = Connect-AzureAD -Credential $credentials -TenantId $tenantid

        $azureadname = (Get-AzureADDomain).name

        ######List All Azure AD Users######

        $AllAzUsers = (Get-AzureADUser -All:$true)

        foreach ($user in $removeusers){

            ######Obain Azure AD User Object ID########

            $email= $user.email

            $guest = $email.Replace("@","_")

            $guest = "$($guest)#EXT#@$($tenantdataadduser.TenantDomain)"

        
            foreach ($azuser in $AllAzUsers){

                if ($guest -eq $azuser.userprincipalname){

                    $useridguest = $azuser.ObjectId

                }
            }

            try {
            
                Remove-AzureADUser -ObjectId $useridguest | Out-Null

                Write-Log -Level Info "Borrando el usuario $($user.Username) del Azure AD $($azureadname)"

            }
            catch{

                continue
            }


        }

    }

}

#####################################################################################################################################
#################################################### Ejecución Script ###############################################################
#####################################################################################################################################
mainmenu



Login
adduser
removeuser






# SECCION DE FICHEROS JSON PARSEABLES #

#<ROL>#AdministradorRD#{
#<ROL>#AdministradorRD#    "Name":  "Administrador RD",
#<ROL>#AdministradorRD#    "Id":  "dc075bf5-6ad1-41be-8f8c-92e7b8e7749a",
#<ROL>#AdministradorRD#    "IsCustom":  true,
#<ROL>#AdministradorRD#    "Description":  "Administrator Profile",
#<ROL>#AdministradorRD#    "Actions":  [
#<ROL>#AdministradorRD#                    "*"
#<ROL>#AdministradorRD#                ],
#<ROL>#AdministradorRD#    "NotActions":  [
#<ROL>#AdministradorRD#
#<ROL>#AdministradorRD#                   ],
#<ROL>#AdministradorRD#    "DataActions":  [
#<ROL>#AdministradorRD#
#<ROL>#AdministradorRD#                    ],
#<ROL>#AdministradorRD#    "NotDataActions":  [
#<ROL>#AdministradorRD#
#<ROL>#AdministradorRD#                       ],
#<ROL>#AdministradorRD#    "AssignableScopes":  [
#<ROL>#AdministradorRD#                             "/subscriptions/11111111-2222-3333-4444-555555555555"
#<ROL>#AdministradorRD#                         ]
#<ROL>#AdministradorRD#}

#<ROL>#NOCAvanzadoRD#{
#<ROL>#NOCAvanzadoRD#    "Name":  "NOC Avanzado RD",
#<ROL>#NOCAvanzadoRD#    "Id":  "1c76e197-4530-4276-90a6-23093a59e407",
#<ROL>#NOCAvanzadoRD#    "IsCustom":  true,
#<ROL>#NOCAvanzadoRD#    "Description":  "NOC Advanced Profile",
#<ROL>#NOCAvanzadoRD#    "Actions":  [
#<ROL>#NOCAvanzadoRD#                    "*/read",
#<ROL>#NOCAvanzadoRD#                    "Microsoft.AlertsManagement/alerts/*",
#<ROL>#NOCAvanzadoRD#                    "Microsoft.AlertsManagement/alertsSummary/*",
#<ROL>#NOCAvanzadoRD#                    "Microsoft.Insights/components/*",
#<ROL>#NOCAvanzadoRD#                    "Microsoft.Insights/DiagnosticSettings/*",
#<ROL>#NOCAvanzadoRD#                    "Microsoft.Insights/eventtypes/*",
#<ROL>#NOCAvanzadoRD#                    "Microsoft.Insights/LogDefinitions/*",
#<ROL>#NOCAvanzadoRD#                    "Microsoft.Insights/MetricDefinitions/*",
#<ROL>#NOCAvanzadoRD#                    "Microsoft.Insights/Metrics/*",
#<ROL>#NOCAvanzadoRD#                    "Microsoft.Insights/Register/Action",
#<ROL>#NOCAvanzadoRD#                    "Microsoft.Insights/webtests/*",
#<ROL>#NOCAvanzadoRD#                    "Microsoft.OperationalInsights/workspaces/intelligencepacks/*",
#<ROL>#NOCAvanzadoRD#                    "Microsoft.OperationalInsights/workspaces/savedSearches/*",
#<ROL>#NOCAvanzadoRD#                    "Microsoft.OperationalInsights/workspaces/search/action",
#<ROL>#NOCAvanzadoRD#                    "Microsoft.OperationalInsights/workspaces/sharedKeys/action",
#<ROL>#NOCAvanzadoRD#                    "Microsoft.OperationalInsights/workspaces/storageinsightconfigs/*",
#<ROL>#NOCAvanzadoRD#                    "Microsoft.Authorization/*/read",
#<ROL>#NOCAvanzadoRD#                    "Microsoft.Network/*",
#<ROL>#NOCAvanzadoRD#                    "Microsoft.Resources/deployments/*",
#<ROL>#NOCAvanzadoRD#                    "Microsoft.Support/*",
#<ROL>#NOCAvanzadoRD#                    "Microsoft.Authorization/*/read",
#<ROL>#NOCAvanzadoRD#                    "Microsoft.ClassicCompute/*/read",
#<ROL>#NOCAvanzadoRD#                    "Microsoft.ClassicCompute/virtualMachines/*/write",
#<ROL>#NOCAvanzadoRD#                    "Microsoft.ClassicNetwork/*/read",
#<ROL>#NOCAvanzadoRD#                    "Microsoft.Insights/alertRules/*",
#<ROL>#NOCAvanzadoRD#                    "Microsoft.ResourceHealth/availabilityStatuses/read",
#<ROL>#NOCAvanzadoRD#                    "Microsoft.Resources/subscriptions/resourceGroups/read",
#<ROL>#NOCAvanzadoRD#                    "Microsoft.Security/*"
#<ROL>#NOCAvanzadoRD#                ],
#<ROL>#NOCAvanzadoRD#    "NotActions":  [
#<ROL>#NOCAvanzadoRD#
#<ROL>#NOCAvanzadoRD#                   ],
#<ROL>#NOCAvanzadoRD#    "DataActions":  [
#<ROL>#NOCAvanzadoRD#
#<ROL>#NOCAvanzadoRD#                    ],
#<ROL>#NOCAvanzadoRD#    "NotDataActions":  [
#<ROL>#NOCAvanzadoRD#
#<ROL>#NOCAvanzadoRD#                       ],
#<ROL>#NOCAvanzadoRD#    "AssignableScopes":  [
#<ROL>#NOCAvanzadoRD#                             "/subscriptions/11111111-2222-3333-4444-555555555555"
#<ROL>#NOCAvanzadoRD#                         ]
#<ROL>#NOCAvanzadoRD#}

#<ROL>#NOCbasicoRD#{
#<ROL>#NOCbasicoRD#    "Name":  "NOC Basico RD",
#<ROL>#NOCbasicoRD#    "Id":  "611c6dd8-27c4-4100-a2a0-d8f61b50c0a3",
#<ROL>#NOCbasicoRD#    "IsCustom":  true,
#<ROL>#NOCbasicoRD#    "Description":  "NOC Basic Profile",
#<ROL>#NOCbasicoRD#    "Actions":  [
#<ROL>#NOCbasicoRD#                    "*/read",
#<ROL>#NOCbasicoRD#                    "Microsoft.OperationalInsights/workspaces/search/action",
#<ROL>#NOCbasicoRD#                    "Microsoft.Support/*"
#<ROL>#NOCbasicoRD#                ],
#<ROL>#NOCbasicoRD#    "NotActions":  [
#<ROL>#NOCbasicoRD#
#<ROL>#NOCbasicoRD#                   ],
#<ROL>#NOCbasicoRD#    "DataActions":  [
#<ROL>#NOCbasicoRD#
#<ROL>#NOCbasicoRD#                    ],
#<ROL>#NOCbasicoRD#    "NotDataActions":  [
#<ROL>#NOCbasicoRD#
#<ROL>#NOCbasicoRD#                       ],
#<ROL>#NOCbasicoRD#    "AssignableScopes":  [
#<ROL>#NOCbasicoRD#                             "/subscriptions/11111111-2222-3333-4444-555555555555"
#<ROL>#NOCbasicoRD#                         ]
#<ROL>#NOCbasicoRD#}

#<ROL>#OperadorAvanzadoRD#{
#<ROL>#OperadorAvanzadoRD#    "Name":  "Operador Avanzado RD",
#<ROL>#OperadorAvanzadoRD#    "Id":  "a3a5627c-ae9f-4c61-a264-8e5e23b9f0dd",
#<ROL>#OperadorAvanzadoRD#    "IsCustom":  true,
#<ROL>#OperadorAvanzadoRD#    "Description":  "Advanced Operator Profile",
#<ROL>#OperadorAvanzadoRD#    "Actions":  [
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.Authorization/*/read",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.Compute/availabilitySets/*",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.Compute/locations/*",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.Compute/virtualMachineScaleSets/*",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.Compute/virtualMachines/write",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.DevTestLab/schedules/*",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.Insights/alertRules/*",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.Network/applicationGateways/backendAddressPools/join/action",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.Network/loadBalancers/backendAddressPools/join/action",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.Network/loadBalancers/inboundNatPools/join/action",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.Network/loadBalancers/inboundNatRules/join/action",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.Network/loadBalancers/probes/join/action",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.Network/loadBalancers/read",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.Network/locations/*",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.Network/networkInterfaces/*",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.Network/networkSecurityGroups/join/action",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.Network/publicIPAddresses/join/action",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.Network/publicIPAddresses/read",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.Network/virtualNetworks/read",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.Network/virtualNetworks/subnets/join/action",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.RecoveryServices/locations/*",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.RecoveryServices/Vaults/backupFabrics/backupProtectionIntent/write",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.RecoveryServices/Vaults/write",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.ResourceHealth/availabilityStatuses/read",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.Resources/deployments/*",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.Resources/subscriptions/resourceGroups/read",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.Storage/storageAccounts/listKeys/action",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.Storage/storageAccounts/read",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.Network/virtualNetworks/read",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.RecoveryServices/Vaults/backupFabrics/operationResults/*",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.RecoveryServices/Vaults/backupFabrics/protectionContainers/*",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.RecoveryServices/Vaults/backupJobs/*",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.RecoveryServices/Vaults/backupJobsExport/action",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.RecoveryServices/Vaults/backupOperationResults/*",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.RecoveryServices/Vaults/backupPolicies/*",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.RecoveryServices/Vaults/backupProtectableItems/*",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.RecoveryServices/Vaults/backupProtectedItems/*",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.RecoveryServices/Vaults/backupProtectionContainers/*",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.RecoveryServices/Vaults/certificates/*",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.RecoveryServices/Vaults/extendedInformation/*",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.RecoveryServices/Vaults/registeredIdentities/*",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.RecoveryServices/Vaults/usages/*",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.RecoveryServices/Vaults/backupUsageSummaries/read",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.Resources/deployments/*",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.Resources/subscriptions/resourceGroups/read",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.Storage/storageAccounts/read",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.RecoveryServices/locations/allocatedStamp/read",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.RecoveryServices/Vaults/monitoringConfigurations/*",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.RecoveryServices/Vaults/monitoringAlerts/read",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.RecoveryServices/Vaults/backupSecurityPIN/*",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.Support/*",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.RecoveryServices/Vaults/backupFabrics/protectionContainers/protectedItems/recoveryPoints/restore/action",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.Network/publicIpAddresses/write",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.Network/networkSecurityGroups/write",
#<ROL>#OperadorAvanzadoRD#                    "*/read",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.Insights/AlertRules/*",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.Insights/components/*",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.Insights/DiagnosticSettings/*",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.Insights/eventtypes/*",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.Insights/LogDefinitions/*",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.Insights/MetricDefinitions/*",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.Insights/Metrics/*",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.Insights/Register/Action",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.Insights/webtests/*",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.OperationalInsights/workspaces/intelligencepacks/*",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.OperationalInsights/workspaces/savedSearches/*",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.OperationalInsights/workspaces/search/action",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.OperationalInsights/workspaces/sharedKeys/action",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.OperationalInsights/workspaces/storageinsightconfigs/*",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.Authorization/roleAssignments/write",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.Resources/subscriptions/resourcegroups/deployments/write",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.Resources/subscriptions/resourcegroups/deployments/read",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.Resources/subscriptions/resourceGroups/write",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.Resources/subscriptions/resourceGroups/read",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.Compute/virtualMachines/write",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.DevTestLab/labs/users/disks/Attach/action",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.DevTestLab/labs/users/disks/write",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.Storage/storageAccounts/write",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.Compute/snapshots/write",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.Compute/disks/write",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.Network/virtualNetworks/write",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.Network/virtualNetworks/virtualNetworkPeerings/write",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.Network/virtualNetworks/peer/action",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.Network/virtualNetworks/subnets/write",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.Network/localnetworkgateways/write",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.Network/connections/write",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.Network/routeTables/write",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.Network/routeTables/routes/write",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.Network/connections/write",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.Network/connections/sharedKey/write",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.Network/virtualNetworkGateways/write",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.network/virtualnetworkgateways/generatevpnclientpackage/action",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.Network/virtualNetworks/subnets/write",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.Network/routeTables/join/action",
#<ROL>#OperadorAvanzadoRD#                    "*/register/action",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.Compute/disks/delete",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.Compute/images/write",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.Network/networksecuritygroups/delete",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.Network/publicIPAddresses/delete",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.Compute/images/delete",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.Logic/workflows/write",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.Web/connections/Join/Action",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.RecoveryServices/Vaults/*",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.Automation/automationAccounts/runbooks/read",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.Automation/automationAccounts/jobs/write",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.Network/virtualNetworkGateways/*",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.Network/virtualNetworkGateways/*",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.Compute/virtualMachines/read",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.Compute/virtualMachines/start/action",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.Compute/virtualMachines/powerOff/action",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.Compute/virtualMachines/restart/action",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.Compute/virtualMachines/redeploy/action",
#<ROL>#OperadorAvanzadoRD#                    "Microsoft.Compute/virtualMachines/deallocate/action"
#<ROL>#OperadorAvanzadoRD#                ],
#<ROL>#OperadorAvanzadoRD#    "NotActions":  [
#<ROL>#OperadorAvanzadoRD#                       "Microsoft.RecoveryServices/Vaults/backupFabrics/protectionContainers/protectedItems/delete",
#<ROL>#OperadorAvanzadoRD#                       "Microsoft.RecoveryServices/Vaults/delete",
#<ROL>#OperadorAvanzadoRD#                       "Microsoft.Network/networkSecurityGroups/delete",
#<ROL>#OperadorAvanzadoRD#                       "Microsoft.Compute/virtualMachines/capture/*",
#<ROL>#OperadorAvanzadoRD#                       "Microsoft.Compute/virtualMachines/generalize/*"
#<ROL>#OperadorAvanzadoRD#                   ],
#<ROL>#OperadorAvanzadoRD#    "DataActions":  [
#<ROL>#OperadorAvanzadoRD#
#<ROL>#OperadorAvanzadoRD#                    ],
#<ROL>#OperadorAvanzadoRD#    "NotDataActions":  [
#<ROL>#OperadorAvanzadoRD#
#<ROL>#OperadorAvanzadoRD#                       ],
#<ROL>#OperadorAvanzadoRD#    "AssignableScopes":  [
#<ROL>#OperadorAvanzadoRD#                             "/subscriptions/11111111-2222-3333-4444-555555555555"
#<ROL>#OperadorAvanzadoRD#                         ]
#<ROL>#OperadorAvanzadoRD#}

#<ROL>#OperadorBasicoRD#{
#<ROL>#OperadorBasicoRD#    "Name":  "Operador Basico RD",
#<ROL>#OperadorBasicoRD#    "Id":  "3820250b-82e8-4dc1-91c0-314a431b973e",
#<ROL>#OperadorBasicoRD#    "IsCustom":  true,
#<ROL>#OperadorBasicoRD#    "Description":  "Profile Basic Operator",
#<ROL>#OperadorBasicoRD#    "Actions":  [
#<ROL>#OperadorBasicoRD#                    "Microsoft.Compute/snapshots/write",
#<ROL>#OperadorBasicoRD#                    "*/read",
#<ROL>#OperadorBasicoRD#                    "Microsoft.OperationalInsights/workspaces/search/action",
#<ROL>#OperadorBasicoRD#                    "Microsoft.Support/*",
#<ROL>#OperadorBasicoRD#                    "Microsoft.Authorization/*/read",
#<ROL>#OperadorBasicoRD#                    "Microsoft.Compute/availabilitySets/read",
#<ROL>#OperadorBasicoRD#                    "Microsoft.Compute/virtualMachines/*/read",
#<ROL>#OperadorBasicoRD#                    "Microsoft.Compute/virtualMachines/deallocate/action",
#<ROL>#OperadorBasicoRD#                    "Microsoft.Compute/virtualMachines/read",
#<ROL>#OperadorBasicoRD#                    "Microsoft.Compute/virtualMachines/restart/action",
#<ROL>#OperadorBasicoRD#                    "Microsoft.Compute/virtualMachines/start/action",
#<ROL>#OperadorBasicoRD#                    "Microsoft.DevTestLab/*/read",
#<ROL>#OperadorBasicoRD#                    "Microsoft.DevTestLab/labs/createEnvironment/action",
#<ROL>#OperadorBasicoRD#                    "Microsoft.DevTestLab/labs/claimAnyVm/action",
#<ROL>#OperadorBasicoRD#                    "Microsoft.DevTestLab/labs/formulas/delete",
#<ROL>#OperadorBasicoRD#                    "Microsoft.DevTestLab/labs/formulas/read",
#<ROL>#OperadorBasicoRD#                    "Microsoft.DevTestLab/labs/formulas/write",
#<ROL>#OperadorBasicoRD#                    "Microsoft.DevTestLab/labs/policySets/evaluatePolicies/action",
#<ROL>#OperadorBasicoRD#                    "Microsoft.DevTestLab/labs/virtualMachines/claim/action",
#<ROL>#OperadorBasicoRD#                    "Microsoft.Network/loadBalancers/backendAddressPools/join/action",
#<ROL>#OperadorBasicoRD#                    "Microsoft.Network/loadBalancers/inboundNatRules/join/action",
#<ROL>#OperadorBasicoRD#                    "Microsoft.Network/networkInterfaces/*/read",
#<ROL>#OperadorBasicoRD#                    "Microsoft.Network/networkInterfaces/join/action",
#<ROL>#OperadorBasicoRD#                    "Microsoft.Network/networkInterfaces/read",
#<ROL>#OperadorBasicoRD#                    "Microsoft.Network/networkInterfaces/write",
#<ROL>#OperadorBasicoRD#                    "Microsoft.Network/publicIPAddresses/*/read",
#<ROL>#OperadorBasicoRD#                    "Microsoft.Network/publicIPAddresses/join/action",
#<ROL>#OperadorBasicoRD#                    "Microsoft.Network/publicIPAddresses/read",
#<ROL>#OperadorBasicoRD#                    "Microsoft.Network/virtualNetworks/subnets/join/action",
#<ROL>#OperadorBasicoRD#                    "Microsoft.Resources/deployments/operations/read",
#<ROL>#OperadorBasicoRD#                    "Microsoft.Resources/deployments/read",
#<ROL>#OperadorBasicoRD#                    "Microsoft.Resources/subscriptions/resourceGroups/read",
#<ROL>#OperadorBasicoRD#                    "Microsoft.Storage/storageAccounts/listKeys/action",
#<ROL>#OperadorBasicoRD#                    "Microsoft.Authorization/*/read",
#<ROL>#OperadorBasicoRD#                    "Microsoft.Network/virtualNetworks/read",
#<ROL>#OperadorBasicoRD#                    "Microsoft.RecoveryServices/Vaults/backupFabrics/operationResults/read",
#<ROL>#OperadorBasicoRD#                    "Microsoft.RecoveryServices/Vaults/backupFabrics/protectionContainers/operationResults/read",
#<ROL>#OperadorBasicoRD#                    "Microsoft.RecoveryServices/Vaults/backupFabrics/protectionContainers/protectedItems/backup/action",
#<ROL>#OperadorBasicoRD#                    "Microsoft.RecoveryServices/Vaults/backupFabrics/protectionContainers/protectedItems/operationResults/read",
#<ROL>#OperadorBasicoRD#                    "Microsoft.RecoveryServices/Vaults/backupFabrics/protectionContainers/protectedItems/operationsStatus/read",
#<ROL>#OperadorBasicoRD#                    "Microsoft.RecoveryServices/Vaults/backupFabrics/protectionContainers/protectedItems/read",
#<ROL>#OperadorBasicoRD#                    "Microsoft.RecoveryServices/Vaults/backupFabrics/protectionContainers/protectedItems/recoveryPoints/read",
#<ROL>#OperadorBasicoRD#                    "Microsoft.RecoveryServices/Vaults/backupFabrics/protectionContainers/protectedItems/recoveryPoints/restore/action",
#<ROL>#OperadorBasicoRD#                    "Microsoft.RecoveryServices/Vaults/backupFabrics/protectionContainers/protectedItems/write",
#<ROL>#OperadorBasicoRD#                    "Microsoft.RecoveryServices/Vaults/backupFabrics/protectionContainers/read",
#<ROL>#OperadorBasicoRD#                    "Microsoft.RecoveryServices/Vaults/backupJobs/*",
#<ROL>#OperadorBasicoRD#                    "Microsoft.RecoveryServices/Vaults/backupJobs/cancel/action",
#<ROL>#OperadorBasicoRD#                    "Microsoft.RecoveryServices/Vaults/backupJobs/operationResults/read",
#<ROL>#OperadorBasicoRD#                    "Microsoft.RecoveryServices/Vaults/backupJobs/read",
#<ROL>#OperadorBasicoRD#                    "Microsoft.RecoveryServices/Vaults/backupJobsExport/action",
#<ROL>#OperadorBasicoRD#                    "Microsoft.RecoveryServices/Vaults/backupOperationResults/*",
#<ROL>#OperadorBasicoRD#                    "Microsoft.RecoveryServices/Vaults/backupPolicies/operationResults/read",
#<ROL>#OperadorBasicoRD#                    "Microsoft.RecoveryServices/Vaults/backupPolicies/read",
#<ROL>#OperadorBasicoRD#                    "Microsoft.RecoveryServices/Vaults/backupProtectableItems/*",
#<ROL>#OperadorBasicoRD#                    "Microsoft.RecoveryServices/Vaults/backupProtectableItems/read",
#<ROL>#OperadorBasicoRD#                    "Microsoft.RecoveryServices/Vaults/backupProtectedItems/read",
#<ROL>#OperadorBasicoRD#                    "Microsoft.RecoveryServices/Vaults/backupProtectionContainers/read",
#<ROL>#OperadorBasicoRD#                    "Microsoft.RecoveryServices/Vaults/backupUsageSummaries/read",
#<ROL>#OperadorBasicoRD#                    "Microsoft.RecoveryServices/Vaults/extendedInformation/read",
#<ROL>#OperadorBasicoRD#                    "Microsoft.RecoveryServices/Vaults/extendedInformation/write",
#<ROL>#OperadorBasicoRD#                    "Microsoft.RecoveryServices/Vaults/read",
#<ROL>#OperadorBasicoRD#                    "Microsoft.RecoveryServices/Vaults/registeredIdentities/operationResults/read",
#<ROL>#OperadorBasicoRD#                    "Microsoft.RecoveryServices/Vaults/registeredIdentities/read",
#<ROL>#OperadorBasicoRD#                    "Microsoft.RecoveryServices/Vaults/registeredIdentities/write",
#<ROL>#OperadorBasicoRD#                    "Microsoft.RecoveryServices/Vaults/usages/read",
#<ROL>#OperadorBasicoRD#                    "Microsoft.Resources/deployments/*",
#<ROL>#OperadorBasicoRD#                    "Microsoft.Resources/subscriptions/resourceGroups/read",
#<ROL>#OperadorBasicoRD#                    "Microsoft.Storage/storageAccounts/read",
#<ROL>#OperadorBasicoRD#                    "Microsoft.RecoveryServices/Vaults/backupFabrics/protectionContainers/protectedItems/recoveryPoints/provisionInstantItemRecovery/action",
#<ROL>#OperadorBasicoRD#                    "Microsoft.RecoveryServices/Vaults/backupFabrics/protectionContainers/protectedItems/recoveryPoints/revokeInstantItemRecovery/action",
#<ROL>#OperadorBasicoRD#                    "Microsoft.RecoveryServices/locations/allocatedStamp/read",
#<ROL>#OperadorBasicoRD#                    "Microsoft.RecoveryServices/Vaults/monitoringConfigurations/*",
#<ROL>#OperadorBasicoRD#                    "Microsoft.RecoveryServices/Vaults/monitoringAlerts/read",
#<ROL>#OperadorBasicoRD#                    "Microsoft.RecoveryServices/Vaults/certificates/write",
#<ROL>#OperadorBasicoRD#                    "Microsoft.Support/*",
#<ROL>#OperadorBasicoRD#                    "Microsoft.Compute/virtualMachines/write"
#<ROL>#OperadorBasicoRD#                ],
#<ROL>#OperadorBasicoRD#    "NotActions":  [
#<ROL>#OperadorBasicoRD#
#<ROL>#OperadorBasicoRD#                   ],
#<ROL>#OperadorBasicoRD#    "DataActions":  [
#<ROL>#OperadorBasicoRD#
#<ROL>#OperadorBasicoRD#                    ],
#<ROL>#OperadorBasicoRD#    "NotDataActions":  [
#<ROL>#OperadorBasicoRD#
#<ROL>#OperadorBasicoRD#                       ],
#<ROL>#OperadorBasicoRD#    "AssignableScopes":  [
#<ROL>#OperadorBasicoRD#                             "/subscriptions/11111111-2222-3333-4444-555555555555"
#<ROL>#OperadorBasicoRD#                         ]
#<ROL>#OperadorBasicoRD#}

#<ROL>#Tecniconivel2RD#{
#<ROL>#Tecniconivel2RD#    "Name":  "Tecnico Nivel2 RD",
#<ROL>#Tecniconivel2RD#    "Id":  "80fc043d-9bd0-45fe-a215-8ba772c8438c",
#<ROL>#Tecniconivel2RD#    "IsCustom":  true,
#<ROL>#Tecniconivel2RD#    "Description":  "Profile Level 2",
#<ROL>#Tecniconivel2RD#    "Actions":  [
#<ROL>#Tecniconivel2RD#                    "*"
#<ROL>#Tecniconivel2RD#                ],
#<ROL>#Tecniconivel2RD#    "NotActions":  [
#<ROL>#Tecniconivel2RD#                       "Microsoft.Resources/subscriptions/resourceGroups/delete",
#<ROL>#Tecniconivel2RD#                       "Microsoft.Authorization/*/Delete",
#<ROL>#Tecniconivel2RD#                       "Microsoft.Authorization/*/Write",
#<ROL>#Tecniconivel2RD#                       "Microsoft.Authorization/elevateAccess/Action"
#<ROL>#Tecniconivel2RD#                   ],
#<ROL>#Tecniconivel2RD#    "DataActions":  [
#<ROL>#Tecniconivel2RD#
#<ROL>#Tecniconivel2RD#                    ],
#<ROL>#Tecniconivel2RD#    "NotDataActions":  [
#<ROL>#Tecniconivel2RD#
#<ROL>#Tecniconivel2RD#                       ],
#<ROL>#Tecniconivel2RD#    "AssignableScopes":  [
#<ROL>#Tecniconivel2RD#                             "/subscriptions/11111111-2222-3333-4444-555555555555"
#<ROL>#Tecniconivel2RD#                         ]
#<ROL>#Tecniconivel2RD#}

#<ROL>#ReportsAzureRD#{
#<ROL>#ReportsAzureRD#    "Name":  "Reports Azure RD",
#<ROL>#ReportsAzureRD#    "Id":  "8909abe1-7f61-4f90-a2ef-4e4c081cef27",
#<ROL>#ReportsAzureRD#    "IsCustom":  true,
#<ROL>#ReportsAzureRD#    "Description":  "Report Backups Profile",
#<ROL>#ReportsAzureRD#    "Actions":  [
#<ROL>#ReportsAzureRD#                    "*/read",
#<ROL>#ReportsAzureRD#                    "Microsoft.Storage/storageAccounts/listKeys/action"
#<ROL>#ReportsAzureRD#                ],
#<ROL>#ReportsAzureRD#    "NotActions":  [
#<ROL>#ReportsAzureRD#
#<ROL>#ReportsAzureRD#                   ],
#<ROL>#ReportsAzureRD#    "DataActions":  [
#<ROL>#ReportsAzureRD#
#<ROL>#ReportsAzureRD#                    ],
#<ROL>#ReportsAzureRD#    "NotDataActions":  [
#<ROL>#ReportsAzureRD#
#<ROL>#ReportsAzureRD#                       ],
#<ROL>#ReportsAzureRD#    "AssignableScopes":  [
#<ROL>#ReportsAzureRD#                             "/subscriptions/11111111-2222-3333-4444-555555555555"
#<ROL>#ReportsAzureRD#                         ]
#<ROL>#ReportsAzureRD#}
