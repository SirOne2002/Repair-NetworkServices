#Requires -RunAsAdministrator
#Requires -Version 5.1
<#
.SYNOPSIS
    Diagnostica (y opcionalmente repara) los servicios de red de Windows 10 y 11 que
    provocan el error 1068: "No se pudo iniciar el servicio o grupo de dependencia".

.DESCRIPTION
    1. Revisa un catálogo de servicios y drivers que Windows 10/11 necesita para la red
       (tipo de inicio esperado vs. actual, estado, binario existente).
    2. Recorre el árbol de dependencias (DependOnService / DependOnGroup) de los
       servicios de red clave y localiza la CAUSA RAÍZ del 1068: la dependencia más
       profunda que está deshabilitada, ausente o detenida.
    3. Busca en TODOS los servicios dependencias deshabilitadas, detecta el uso de
       "optimizadores" (muchos servicios de Windows deshabilitados) y directivas que
       fuercen tipos de inicio (y que revertirían la reparación).
    4. Revisa el Firewall (claves de directiva ausentes), el registro de eventos
       (Service Control Manager), los adaptadores, los filtros de clase de red
       huérfanos y prueba la conectividad (IP/DHCP, puerta de enlace, DNS, HTTP, reloj).
    5. Con -Fix: respalda HKLM\...\Services, restablece los tipos de inicio por defecto,
       arranca los servicios en orden de dependencias (primero las hojas), verifica
       que siguen en ejecución y vuelve a diagnosticar para mostrar lo que queda pendiente.
    6. Con -ResetStack: además ejecuta netsh winsock reset / netsh int ip reset.

    Sin parámetros solo DIAGNOSTICA, no modifica nada.

.PARAMETER Fix
    Aplica las correcciones (tipos de inicio + arranque ordenado de servicios).

.PARAMETER ResetStack
    Restablece Winsock y la pila TCP/IP (requiere reinicio). Se puede combinar con -Fix.

.PARAMETER LogDir
    Carpeta donde se crea la subcarpeta NetDiag_<fecha> con transcripción, CSV y respaldo.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Repair-NetworkServices.ps1
    Solo diagnóstico.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Repair-NetworkServices.ps1 -Fix
    Diagnóstico + reparación.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Repair-NetworkServices.ps1 -Fix -ResetStack
    Diagnóstico + reparación + reinicio de la pila de red.
#>
[CmdletBinding()]
param(
    [switch]$Fix,
    [switch]$ResetStack,
    [string]$LogDir = $(if ($PSScriptRoot) { $PSScriptRoot } else { $PWD.Path })
)

$ErrorActionPreference = 'Continue'
$script:RebootRequired = $false
$script:Findings       = New-Object System.Collections.Generic.List[string]
$script:StartFailures  = New-Object System.Collections.Generic.List[object]
$script:Persistent     = New-Object System.Collections.Generic.List[string]   # avisos que siguen vigentes tras -Fix
$script:Started        = New-Object System.Collections.Generic.List[string]
$script:AfterRepair    = $false
$script:WmiOk          = $false

$ts     = Get-Date -Format 'yyyyMMdd_HHmmss'
$LogDir = Join-Path $LogDir "NetDiag_$ts"
New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
try { Start-Transcript -Path (Join-Path $LogDir 'transcript.txt') -ErrorAction Stop | Out-Null } catch { }

$SvcRoot = 'HKLM:\SYSTEM\CurrentControlSet\Services'

#region Catálogo ---------------------------------------------------------------------------
# Valores por defecto de Windows 10 (1607-22H2) y Windows 11; las diferencias por build van en $BuildOverrides.
# Default: Boot | System | Auto | AutoDelayed | Manual | Disabled
# Critical: imprescindible para tener conectividad IP básica.
$Catalog = @(
    # --- Núcleo del sistema del que depende todo lo demás
    @{ Name='RpcEptMapper';         Default='Auto';   Critical=$true;  Desc='Asignador de extremos RPC' }
    @{ Name='DcomLaunch';           Default='Auto';   Critical=$true;  Desc='Iniciador de procesos DCOM' }
    @{ Name='RpcSs';                Default='Auto';   Critical=$true;  Desc='Llamada a procedimiento remoto (RPC)' }
    @{ Name='EventLog';             Default='Auto';   Critical=$true;  Desc='Registro de eventos de Windows' }
    @{ Name='PlugPlay';             Default='Manual'; Critical=$true;  Desc='Plug and Play' }
    @{ Name='Power';                Default='Auto';   Critical=$false; Desc='Energía' }
    @{ Name='BrokerInfrastructure'; Default='Auto';   Critical=$false; Desc='Infraestructura de tareas en segundo plano' }
    @{ Name='SamSs';                Default='Auto';   Critical=$false; Desc='Administrador de cuentas de seguridad' }
    @{ Name='CryptSvc';             Default='Auto';   Critical=$false; Desc='Servicios de cifrado' }
    @{ Name='Winmgmt';              Default='Auto';   Critical=$false; Desc='Instrumental de administración de Windows' }

    # --- Drivers de la pila de red (kernel)
    @{ Name='NDIS';                 Default='Boot';   Critical=$true;  Desc='Driver NDIS' }
    @{ Name='Tcpip';                Default='Boot';   Critical=$true;  Desc='Driver de protocolo TCP/IP' }
    @{ Name='tdx';                  Default='System'; Critical=$true;  Desc='Driver heredado TDI (tdx)' }
    @{ Name='Afd';                  Default='System'; Critical=$true;  Desc='Driver de funciones auxiliares de Winsock (AFD)' }
    @{ Name='nsiproxy';             Default='System'; Critical=$true;  Desc='Proxy NSI (kernel)' }
    @{ Name='NetBT';                Default='System'; Critical=$false; Desc='NetBIOS sobre TCP/IP' }
    @{ Name='NetBIOS';              Default='System'; Critical=$false; Desc='Driver de interfaz NetBIOS' }
    @{ Name='tcpipreg';             Default='Auto';   Critical=$false; Desc='Compatibilidad de registro TCP/IP' }
    @{ Name='WfpLwfs';              Default='Boot';   Critical=$false; Desc='Filtros ligeros de WFP' }
    @{ Name='mpsdrv';               Default='Manual'; Critical=$false; Desc='Driver del Firewall de Windows' }
    @{ Name='rdbss';                Default='System'; Critical=$false; Desc='Redirected Buffering Sub System' }
    @{ Name='bowser';               Default='Manual'; Critical=$false; Desc='Explorador de red (driver)' }
    @{ Name='mrxsmb';               Default='Manual'; Critical=$false; Desc='Minirredirector SMB' }
    @{ Name='mrxsmb20';             Default='Manual'; Critical=$false; Desc='Minirredirector SMB 2.0' }
    @{ Name='srv2';                 Default='Manual'; Critical=$false; Desc='Servidor SMB 2.0 (driver)' }
    @{ Name='srvnet';               Default='Manual'; Critical=$false; Desc='Servidor SMB (driver de red)' }
    @{ Name='Ndisuio';              Default='Manual'; Critical=$false; Desc='NDIS Usermode I/O' }
    @{ Name='nativewifip';          Default='Manual'; Critical=$false; Desc='Filtro WiFi nativo' }

    # --- Servicios de red (modo usuario)
    @{ Name='BFE';                  Default='Auto';   Critical=$true;  Desc='Motor de filtrado de base' }
    @{ Name='MpsSvc';               Default='Auto';   Critical=$true;  Desc='Firewall de Windows Defender' }
    @{ Name='nsi';                  Default='Auto';   Critical=$true;  Desc='Servicio Interfaz de almacenamiento en red' }
    @{ Name='Dhcp';                 Default='Auto';   Critical=$true;  Desc='Cliente DHCP' }
    @{ Name='Dnscache';             Default='Auto';   Critical=$true;  Desc='Cliente DNS' }
    @{ Name='NlaSvc';               Default='Auto';   Critical=$true;  Desc='Reconocimiento de ubicación de red' }
    @{ Name='netprofm';             Default='Manual'; Critical=$true;  Desc='Servicio de lista de redes' }
    @{ Name='Wcmsvc';               Default='Auto';   Critical=$true;  Desc='Administrador de conexiones de Windows' }
    @{ Name='WinHttpAutoProxySvc';  Default='Manual'; Critical=$false; Desc='Detección automática de proxy web WinHTTP' }
    @{ Name='iphlpsvc';             Default='Auto';   Critical=$false; Desc='Aplicación auxiliar IP' }
    @{ Name='Netman';               Default='Manual'; Critical=$false; Desc='Conexiones de red' }
    @{ Name='NcbService';           Default='Manual'; Critical=$false; Desc='Agente de conexión de red' }
    @{ Name='NetSetupSvc';          Default='Manual'; Critical=$false; Desc='Servicio de instalación de red' }
    @{ Name='LanmanWorkstation';    Default='Auto';   Critical=$false; Desc='Estación de trabajo (cliente SMB)' }
    @{ Name='LanmanServer';         Default='Auto';   Critical=$false; Desc='Servidor (SMB)' }
    @{ Name='lmhosts';              Default='Manual'; Critical=$false; Desc='Aplicación auxiliar de NetBIOS sobre TCP/IP' }
    @{ Name='WlanSvc';              Default='Auto';   Critical=$false; Desc='Configuración automática de WLAN (WiFi)' }
    @{ Name='Dot3svc';              Default='Manual'; Critical=$false; Desc='Configuración automática de redes cableadas (802.1X)' }
    @{ Name='EapHost';              Default='Manual'; Critical=$false; Desc='Protocolo de autenticación extensible' }
    @{ Name='RasMan';               Default='Manual'; Critical=$false; Desc='Administrador de conexiones de acceso remoto' }
    @{ Name='KeyIso';               Default='Manual'; Critical=$false; Desc='Aislamiento de claves CNG' }
    @{ Name='SstpSvc';              Default='Manual'; Critical=$false; Desc='Protocolo de túnel de sockets seguros (RasMan depende)' }
    @{ Name='IKEEXT';               Default='Manual'; Critical=$false; Desc='Módulos de creación de claves IKE y AuthIP (VPN)' }
    @{ Name='PolicyAgent';          Default='Manual'; Critical=$false; Desc='Agente de directiva IPsec' }
    @{ Name='NcaSvc';               Default='Manual'; Critical=$false; Desc='Asistente para la conectividad de red' }
    @{ Name='lltdsvc';              Default='Manual'; Critical=$false; Desc='Asignador de detección de topologías de nivel de vínculo' }
    @{ Name='fdPHost';              Default='Manual'; Critical=$false; Desc='Host de proveedor de detección de función' }
    @{ Name='FDResPub';             Default='Manual'; Critical=$false; Desc='Publicación de recurso de detección de función' }
    @{ Name='SSDPSRV';              Default='Manual'; Critical=$false; Desc='Detección SSDP' }

    # --- Soporte del sistema que afecta a la red o a su reparación
    @{ Name='EventSystem';          Default='Auto';   Critical=$false; Desc='Sistema de eventos COM+ (SENS depende)' }
    @{ Name='SENS';                 Default='Auto';   Critical=$false; Desc='Notificación de eventos del sistema (avisa a las apps de cambios de conectividad)' }
    @{ Name='W32Time';              Default='Manual'; Critical=$false; Desc='Hora de Windows (un reloj desfasado rompe HTTPS)' }
    @{ Name='TrustedInstaller';     Default='Manual'; Critical=$false; Desc='Instalador de módulos (necesario para sfc /scannow y DISM)' }
    @{ Name='DeviceInstall';        Default='Manual'; Critical=$false; Desc='Instalación de dispositivos (drivers de adaptadores nuevos)' }
    @{ Name='DsmSvc';               Default='Manual'; Critical=$false; Desc='Administrador de configuración de dispositivos' }
    @{ Name='DPS';                  Default='Auto';   Critical=$false; Desc='Directivas de diagnóstico (solucionador de problemas de red)' }
    @{ Name='WdiServiceHost';       Default='Manual'; Critical=$false; Desc='Host del servicio de diagnóstico' }
    @{ Name='WdiSystemHost';        Default='Manual'; Critical=$false; Desc='Host del sistema de diagnóstico' }
    @{ Name='VaultSvc';             Default='Manual'; Critical=$false; Desc='Administrador de credenciales' }

    # --- Solo informativos: pueden estar deshabilitados a propósito (-Fix no los toca)
    @{ Name='wuauserv';             Default='Manual'; Critical=$false; NoFix=$true; Desc='Windows Update' }
    @{ Name='BITS';                 Default='Manual'; Critical=$false; NoFix=$true; Desc='Transferencia inteligente en segundo plano' }
    @{ Name='UsoSvc';               Default='Manual'; Critical=$false; NoFix=$true; Desc='Orquestador de actualizaciones' }
) | ForEach-Object { if (-not $_.ContainsKey('NoFix')) { $_.NoFix = $false }; [pscustomobject]$_ }

# Valores por defecto que cambiaron en versiones posteriores: servicio -> @{ build mínima = tipo de inicio }
# Windows 11 24H2 (26100) pasó NlaSvc a inicio manual y netprofm dejó de depender de él.
$BuildOverrides = @{
    NlaSvc = @{ 26100 = 'Manual' }
}
$OsInfo  = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$OsBuild = [int]$OsInfo.CurrentBuild
foreach ($c in $Catalog) {
    if (-not $BuildOverrides.ContainsKey($c.Name)) { continue }
    $o = $BuildOverrides[$c.Name]
    $b = $o.Keys | Where-Object { $_ -le $OsBuild } | Sort-Object -Descending | Select-Object -First 1
    if ($b) { $c.Default = $o[$b] }
}

# Si hay más servicios de Windows deshabilitados que este umbral, casi seguro se usó un "optimizador"
$OptimizerThreshold = 30

# Servicios cuyo árbol de dependencias se analiza en busca de la causa raíz del 1068
$Targets = 'Dhcp','Dnscache','NlaSvc','netprofm','nsi','Wcmsvc','BFE','MpsSvc','iphlpsvc','LanmanWorkstation','WlanSvc'
#endregion

#region Utilidades de salida ---------------------------------------------------------------
function Write-Section([string]$Title) {
    Write-Host ''
    Write-Host ('=' * 90) -ForegroundColor Cyan
    Write-Host " $Title" -ForegroundColor Cyan
    Write-Host ('=' * 90) -ForegroundColor Cyan
}
function Write-Status([string]$Level, [string]$Text) {
    $color = switch ($Level) { 'OK' {'Green'} 'INFO' {'Gray'} 'WARN' {'Yellow'} 'ERROR' {'Red'} 'FIX' {'Magenta'} default {'White'} }
    Write-Host ("[{0,-5}] {1}" -f $Level, $Text) -ForegroundColor $color
}
function Get-Win32Message([int]$Code) {
    (New-Object System.ComponentModel.Win32Exception($Code)).Message
}
#endregion

#region Caché de registro / estado ---------------------------------------------------------
$script:RegCache   = @{}
$script:StateCache = @{}
$script:GroupMap   = @{}

function Initialize-Cache {
    $script:RegCache   = @{}
    $script:StateCache = @{}
    $script:GroupMap   = @{}

    # Estado de servicios y drivers. Si WMI está deshabilitado o roto se recurre a Get-Service.
    $script:WmiOk = $false
    if (Test-Disabled 'Winmgmt') {
        Write-Status 'WARN' 'WMI (Winmgmt) está deshabilitado; se usa Get-Service/sc.exe.'
    } else {
        try {
            Get-CimInstance Win32_Service -ErrorAction Stop |
                ForEach-Object { $script:StateCache[$_.Name.ToLower()] = $_.State }
            Get-CimInstance Win32_SystemDriver -ErrorAction Stop |
                ForEach-Object { if (-not $script:StateCache.ContainsKey($_.Name.ToLower())) { $script:StateCache[$_.Name.ToLower()] = $_.State } }
            $script:WmiOk = $true
        } catch {
            Write-Status 'WARN' "WMI no responde ($($_.Exception.Message)); se usa Get-Service/sc.exe."
        }
    }
    if (-not $script:WmiOk) {
        Get-Service -ErrorAction SilentlyContinue |
            ForEach-Object { $script:StateCache[$_.Name.ToLower()] = [string]$_.Status }
    }

    # Mapa de grupos de carga (para DependOnGroup)
    Get-ChildItem -LiteralPath $SvcRoot -ErrorAction SilentlyContinue | ForEach-Object {
        $g = $_.GetValue('Group')
        if ($g) {
            $k = $g.ToLower()
            if (-not $script:GroupMap.ContainsKey($k)) { $script:GroupMap[$k] = New-Object System.Collections.Generic.List[string] }
            $script:GroupMap[$k].Add($_.PSChildName)
        }
    }
}

function Update-State([string]$Name) {
    # sc.exe query es independiente de WMI y del idioma (los estados se muestran en inglés)
    $q = & sc.exe query $Name 2>$null | Out-String
    $state = 'Unknown'
    if ($q -match '\b[1-7]\s+(STOPPED|START_PENDING|STOP_PENDING|RUNNING|CONTINUE_PENDING|PAUSE_PENDING|PAUSED)\b') {
        $state = switch ($Matches[1]) { 'RUNNING' {'Running'} 'STOPPED' {'Stopped'} default { $Matches[1] } }
    }
    $script:StateCache[$Name.ToLower()] = $state
    $state
}

function Get-ExitInfo([string]$Name) {
    # Código con el que terminó el servicio. 1066 = error específico del servicio (ver SERVICE_EXIT_CODE)
    $q = & sc.exe query $Name 2>$null | Out-String
    $w32 = 0; $svc = 0
    if ($q -match 'WIN32_EXIT_CODE\s*:\s*(\d+)')   { $w32 = [int]$Matches[1] }
    if ($q -match 'SERVICE_EXIT_CODE\s*:\s*(\d+)') { $svc = [int]$Matches[1] }
    $code = if ($w32 -eq 1066 -and $svc) { $svc } else { $w32 }
    $text = if ($code) { Get-Win32Message $code } else { 'sin código de error' }
    if ($w32 -eq 1066) { $text = "error específico del servicio $code - $text" }
    [pscustomobject]@{ Code = $code; Win32 = $w32; Message = $text }
}

function Test-Disabled([string]$Name) {
    $i = Get-Info $Name
    $i -and $i.Start -eq 4
}

function Get-State([string]$Name) {
    $k = $Name.ToLower()
    if ($script:StateCache.ContainsKey($k)) { return $script:StateCache[$k] }
    Update-State $Name
}

function Get-Info([string]$Name) {
    $k = $Name.ToLower()
    if ($script:RegCache.ContainsKey($k)) { return $script:RegCache[$k] }

    # API .NET en lugar del proveedor HKLM: de PowerShell: ~50 veces más rápida al recorrer todos los servicios
    $info = $null
    $key  = $null
    try { $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("SYSTEM\CurrentControlSet\Services\$Name") } catch { }
    if ($key) {
        try {
            $dll = $null
            try { $pk = $key.OpenSubKey('Parameters'); if ($pk) { $dll = $pk.GetValue('ServiceDll'); $pk.Close() } } catch { }
            $type = [int]$key.GetValue('Type', 0)
            $info = [pscustomobject]@{
                Name            = Split-Path $key.Name -Leaf    # nombre con las mayúsculas reales
                Start           = $key.GetValue('Start')
                Delayed         = [int]$key.GetValue('DelayedAutostart', 0)
                Type            = $type
                IsDriver        = ($type -band 0x3) -ne 0     # 1 = kernel driver, 2 = FS driver
                ImagePath       = $key.GetValue('ImagePath')
                ServiceDll      = $dll
                DependOnService = @($key.GetValue('DependOnService') | Where-Object { $_ })
                DependOnGroup   = @($key.GetValue('DependOnGroup')   | Where-Object { $_ })
            }
        } finally { $key.Close() }
    }
    $script:RegCache[$k] = $info
    $info
}

function ConvertTo-StartText($Info) {
    if (-not $Info) { return '-' }
    switch ($Info.Start) {
        0 { 'Boot' } 1 { 'System' } 3 { 'Manual' } 4 { 'Disabled' }
        2 { if ($Info.Delayed -eq 1) { 'AutoDelayed' } else { 'Auto' } }
        default { "?($($Info.Start))" }
    }
}

function Resolve-BinaryPath([string]$Path) {
    if (-not $Path) { return $null }
    $p = [Environment]::ExpandEnvironmentVariables($Path.Trim())
    if ($p.StartsWith('"')) { $p = $p.Substring(1, $p.IndexOf('"', 1) - 1) }
    elseif ($p -match '^(.+?\.(exe|sys|dll))\b') { $p = $Matches[1] }
    $p = $p -replace '^\\\?\?\\', ''
    $p = $p -replace '^(?i)\\SystemRoot\\', ($env:SystemRoot + '\')
    if ($p -match '^(?i)system32\\') { $p = Join-Path $env:SystemRoot $p }
    $p
}

function Get-MissingBinary($Info) {
    # Devuelve la ruta del binario si NO existe; $null si está bien o no se puede determinar
    if ($Info.ServiceDll) { $file = Resolve-BinaryPath $Info.ServiceDll }
    elseif ($Info.ImagePath) { $file = Resolve-BinaryPath $Info.ImagePath }
    elseif ($Info.IsDriver) { $file = Join-Path $env:SystemRoot "System32\drivers\$($Info.Name).sys" }
    else { return $null }
    if ($file -and -not (Test-Path -LiteralPath $file)) { return $file }
    $null
}
#endregion

#region Dependencias -----------------------------------------------------------------------
# Los grupos se representan como nodos '@NombreGrupo' cuyos hijos son sus miembros.
function Get-Deps([string]$Node) {
    if ($Node.StartsWith('@')) {
        $k = $Node.Substring(1).ToLower()
        if ($script:GroupMap.ContainsKey($k)) { return @($script:GroupMap[$k]) }
        return @()
    }
    $i = Get-Info $Node
    if (-not $i) { return @() }
    @($i.DependOnService) + @($i.DependOnGroup | ForEach-Object { "@$_" })
}

function Get-NodeIssue([string]$Node) {
    if ($Node.StartsWith('@')) {
        $members = Get-Deps $Node
        if ($members.Count -eq 0) { return 'GRUPO SIN MIEMBROS' }
        if ($members | Where-Object { (Get-State $_) -eq 'Running' }) { return $null }
        return 'NINGÚN MIEMBRO DEL GRUPO EN EJECUCIÓN'
    }
    $i = Get-Info $Node
    if (-not $i) { return 'NO EXISTE en el registro' }
    if ($i.Start -eq 4) { return 'DESHABILITADO' }
    $miss = Get-MissingBinary $i
    if ($miss) { return "FALTA EL ARCHIVO $miss" }
    # Un servicio/driver Manual detenido no es un problema: el SCM lo arranca al iniciar su dependiente
    $st = Get-State $Node
    if ($st -ne 'Running' -and $i.Start -ne 3) { return "DETENIDO ($st)" }
    $null
}

function Show-Tree([string]$Node, [int]$Depth, $Path) {
    $issue = Get-NodeIssue $Node
    if ($Node.StartsWith('@')) { $label = "[grupo] $($Node.Substring(1))" }
    else { $label = "$Node  <$(ConvertTo-StartText (Get-Info $Node))>" }
    if ($issue) { $label += "  -> $issue" }
    $prefix = if ($Depth -eq 0) { '' } else { ('   ' * ($Depth - 1)) + '|-- ' }
    Write-Host ("    $prefix$label") -ForegroundColor $(if ($issue) { 'Red' } else { 'Green' })

    $k = $Node.ToLower()
    if ($Path.Contains($k)) { Write-Host "    $('   ' * $Depth)(dependencia circular)" -ForegroundColor Yellow; return }
    if ($Depth -ge 12) { return }
    [void]$Path.Add($k)
    foreach ($d in Get-Deps $Node) { Show-Tree $d ($Depth + 1) $Path }
    [void]$Path.Remove($k)
}

# Recorrido post-orden (dependencias antes que dependientes), sin repetir nodos
function Add-PostOrder([string]$Node, $Visited, $Order) {
    if (-not $Visited.Add($Node)) { return }
    foreach ($d in Get-Deps $Node) { Add-PostOrder $d $Visited $Order }
    $Order.Add($Node)
}

function Get-PostOrder([string[]]$Roots) {
    $visited = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $order   = New-Object System.Collections.Generic.List[string]
    foreach ($r in $Roots) { Add-PostOrder $r $visited $order }
    $order
}

function Test-WindowsBinary($Info) {
    $file = if ($Info.ServiceDll) { Resolve-BinaryPath $Info.ServiceDll } else { Resolve-BinaryPath $Info.ImagePath }
    $file -and $file.StartsWith($env:SystemRoot, [StringComparison]::OrdinalIgnoreCase)
}

function Get-AllServiceInfo {
    $root = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SYSTEM\CurrentControlSet\Services')
    $names = $root.GetSubKeyNames(); $root.Close()
    $names | ForEach-Object { Get-Info $_ } |
        Where-Object { $_ -and $null -ne $_.Start -and ($_.Type -band 0x3B) }   # servicios y drivers reales
}

function Get-DisabledDependencies {
    # Pares (servicio no deshabilitado -> dependencia deshabilitada) en TODO el registro:
    # cada uno es un error 1068 en cuanto el dependiente intente arrancar.
    foreach ($i in Get-AllServiceInfo) {
        if ($i.Start -eq 4) { continue }
        foreach ($d in $i.DependOnService) {
            $di = Get-Info $d
            if ($di -and $di.Start -eq 4) {
                [pscustomobject]@{
                    Dependent      = $i.Name
                    DependentStart = ConvertTo-StartText $i
                    Dependency     = $di.Name
                    IsWindows      = Test-WindowsBinary $di
                }
            }
        }
    }
}

function Get-RootCauses([string[]]$Roots) {
    # Causa raíz = nodo con problema cuyas dependencias directas están todas sanas
    foreach ($n in Get-PostOrder $Roots) {
        $issue = Get-NodeIssue $n
        if (-not $issue) { continue }
        $badChild = Get-Deps $n | Where-Object { Get-NodeIssue $_ } | Select-Object -First 1
        if (-not $badChild) { [pscustomobject]@{ Node = $n; Issue = $issue } }
    }
}
#endregion

#region Diagnóstico ------------------------------------------------------------------------
function Invoke-CatalogScan {
    $results = foreach ($c in $Catalog) {
        $i        = Get-Info $c.Name
        $actual   = ConvertTo-StartText $i
        $state    = if ($i) { Get-State $c.Name } else { '-' }
        $problems = New-Object System.Collections.Generic.List[string]
        $levels   = New-Object System.Collections.Generic.List[int]   # 0 OK, 1 INFO, 2 WARN, 3 ERROR
        $hi       = if ($c.Critical) { 3 } elseif ($c.NoFix) { 1 } else { 2 }   # gravedad si falla algo importante
        $lo       = if ($c.Critical) { 2 } else { 1 }                           # gravedad de una discrepancia menor

        if (-not $i) {
            $problems.Add('No existe en el registro')
            $levels.Add($(if ($c.Critical) { 3 } else { 1 }))
        } else {
            $miss = Get-MissingBinary $i
            if ($miss) { $problems.Add("Falta binario: $miss"); $levels.Add(3) }

            $normActual   = $actual    -replace '^AutoDelayed$', 'Auto'
            $normExpected = $c.Default -replace '^AutoDelayed$', 'Auto'
            if ($actual -eq 'Disabled' -and $c.Default -ne 'Disabled') {
                $problems.Add("Deshabilitado (debería ser $($c.Default))"); $levels.Add($hi)
            } elseif ($normActual -ne $normExpected -and -not $c.NoFix) {
                $problems.Add("Inicio $actual (por defecto $($c.Default))"); $levels.Add($lo)
            }

            if ($c.Default -in 'Auto','AutoDelayed','Boot','System' -and $actual -ne 'Disabled' -and $state -ne 'Running') {
                $problems.Add("Debería estar en ejecución (estado: $state)"); $levels.Add($hi)
            }
        }
        $max = (@($levels) + 0 | Measure-Object -Maximum).Maximum
        $sev = @('OK','INFO','WARN','ERROR')[[int]$max]

        [pscustomobject]@{
            Severity = $sev
            Name     = $c.Name
            Critical = $c.Critical
            Expected = $c.Default
            Actual   = $actual
            State    = $state
            Problems = ($problems -join '; ')
            Desc     = $c.Desc
        }
    }
    $results
}

function Show-CatalogScan($Results) {
    Write-Host ("{0,-6} {1,-21} {2,-4} {3,-11} {4,-11} {5,-9} {6}" -f 'NIVEL','SERVICIO','CRIT','ESPERADO','ACTUAL','ESTADO','OBSERVACIONES') -ForegroundColor White
    foreach ($r in $Results) {
        $color = switch ($r.Severity) { 'OK' {'Green'} 'INFO' {'Gray'} 'WARN' {'Yellow'} 'ERROR' {'Red'} }
        $obs   = if ($r.Problems) { $r.Problems } else { $r.Desc }
        Write-Host ("{0,-6} {1,-21} {2,-4} {3,-11} {4,-11} {5,-9} {6}" -f $r.Severity, $r.Name, $(if ($r.Critical) {'Sí'} else {''}), $r.Expected, $r.Actual, $r.State, $obs) -ForegroundColor $color
    }
}

function Show-ScmEvents([datetime]$Since = (Get-Date).AddHours(-48), [string]$CsvName = 'eventos_scm.csv') {
    $title = if (((Get-Date) - $Since).TotalHours -lt 1) { "desde las $($Since.ToString('HH:mm:ss'))" } else { 'últimas 48 h' }
    Write-Section "Eventos del Administrador de control de servicios ($title)"
    if ((Get-State 'EventLog') -ne 'Running') {
        Write-Status 'WARN' 'El servicio EventLog no está en ejecución: no hay eventos que leer (se podrán ver tras -Fix).'
        return
    }
    # 7000 no se inició, 7001 dependencia falló (1068), 7003 dependencia inexistente (1075),
    # 7023/7024 terminó con error, 7026 driver de arranque no cargó, 7031/7034 terminó inesperadamente
    try {
        $ev = @(Get-WinEvent -FilterHashtable @{
            LogName = 'System'; ProviderName = 'Service Control Manager'
            Id = 7000,7001,7003,7023,7024,7026,7031,7034; StartTime = $Since
        } -MaxEvents 200 -ErrorAction Stop)
        # Los mismos fallos se repiten en cada arranque: se agrupan por mensaje
        $ev | Group-Object Id, Message | Sort-Object { $_.Group[0].TimeCreated } -Descending | Select-Object -First 25 | ForEach-Object {
            $e   = $_.Group[0]
            $msg = ($e.Message -replace '\s+', ' ')
            if ($msg.Length -gt 200) { $msg = $msg.Substring(0, 200) + '...' }
            $rep = if ($_.Count -gt 1) { " (x$($_.Count))" } else { '' }
            Write-Status 'WARN' ("{0:yyyy-MM-dd HH:mm} [{1}]{2} {3}" -f $e.TimeCreated, $e.Id, $rep, $msg)
        }
        $ev | Select-Object TimeCreated, Id, Message | Export-Csv (Join-Path $LogDir $CsvName) -NoTypeInformation -Encoding UTF8
    } catch {
        if ($_.Exception.Message -match 'No events|No se encontraron') { Write-Status 'OK' 'Sin eventos de error de servicios.' }
        else { Write-Status 'WARN' "No se pudo leer el registro de eventos: $($_.Exception.Message)" }
    }
}

function Show-Adapters {
    Write-Section 'Adaptadores de red'
    if (-not $script:WmiOk) {
        # Sin WMI no hay Win32_PnPEntity ni Get-NetAdapter; .NET lee las interfaces directamente
        Write-Status 'WARN' 'WMI no disponible: no se puede ver el estado PnP de los adaptadores (código de error del Administrador de dispositivos).'
        try {
            [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces() |
                Where-Object { $_.NetworkInterfaceType -notin 'Loopback','Tunnel' } | ForEach-Object {
                    $lvl = if ($_.OperationalStatus -eq 'Up') { 'OK' } else { 'WARN' }
                    Write-Status $lvl ("{0} [{1}] estado={2}" -f $_.Name, $_.Description, $_.OperationalStatus)
                }
        } catch { Write-Status 'WARN' "No se pudieron enumerar las interfaces: $($_.Exception.Message)" }
        return
    }
    try {
        $devs = Get-CimInstance Win32_PnPEntity -Filter "PNPClass='Net'" -ErrorAction Stop
        if (-not $devs) { Write-Status 'ERROR' 'No se detecta ningún dispositivo de clase Red.'; $script:Findings.Add('No hay adaptadores de red detectados: revisar hardware/BIOS o instalar el driver del adaptador.') }
        foreach ($d in $devs) {
            $code = [int]$d.ConfigManagerErrorCode
            if ($code -eq 0)      { Write-Status 'OK'    "$($d.Name)" }
            elseif ($code -eq 22) { Write-Status 'WARN'  "$($d.Name) -> DESHABILITADO (código 22)"; $script:Findings.Add("Adaptador deshabilitado: '$($d.Name)'. Habilitar con: Enable-PnpDevice -InstanceId '$($d.PNPDeviceID)' -Confirm:`$false") }
            else                  { Write-Status 'ERROR' "$($d.Name) -> código de error $code"; $script:Findings.Add("Adaptador '$($d.Name)' con código $code en el Administrador de dispositivos: reinstalar su driver.") }
        }
    } catch { Write-Status 'WARN' "No se pudo consultar dispositivos PnP: $($_.Exception.Message)" }

    try {
        Get-NetAdapter -ErrorAction Stop | ForEach-Object {
            $lvl = if ($_.Status -eq 'Up') { 'OK' } else { 'WARN' }
            Write-Status $lvl ("{0} [{1}] estado={2} enlace={3} MAC={4}" -f $_.Name, $_.InterfaceDescription, $_.Status, $_.LinkSpeed, $_.MacAddress)
        }
    } catch {
        Write-Status 'WARN' "Get-NetAdapter falló (normal si nsi/Tcpip no están en marcha): $($_.Exception.Message)"
    }
}

function Show-ClassFilters {
    Write-Section 'Filtros de la clase Red (UpperFilters / LowerFilters)'
    $classKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}'
    $p = Get-ItemProperty -LiteralPath $classKey -ErrorAction SilentlyContinue
    $any = $false
    foreach ($kind in 'UpperFilters','LowerFilters') {
        foreach ($f in @($p.$kind | Where-Object { $_ })) {
            $any = $true
            if (Get-Info $f) { Write-Status 'INFO' "$kind : $f (existe)" }
            else {
                Write-Status 'ERROR' "$kind : $f -> el servicio NO existe (filtro huérfano, típico tras desinstalar antivirus/VPN)"
                $script:Findings.Add("Filtro huérfano '$f' en $kind de la clase Red. Quitarlo de $classKey (tras respaldar) y reiniciar.")
            }
        }
    }
    if (-not $any) { Write-Status 'OK' 'Sin filtros de clase (configuración por defecto).' }
}

function Show-DependencyAnalysis {
    Write-Section '2) Árboles de dependencias de los servicios de red clave'
    $sick = @($Targets | Where-Object { (Get-Info $_) -and (Get-NodeIssue $_) })
    foreach ($t in $Targets) {
        if (-not (Get-Info $t)) { Write-Status 'INFO' "$t no está instalado, se omite."; continue }
        if ($sick -notcontains $t) { Write-Status 'OK' "$t sin dependencias rotas ($(Get-State $t))"; continue }
        Write-Host ''
        Show-Tree $t 0 (New-Object 'System.Collections.Generic.HashSet[string]')
    }

    Write-Section '3) Causa raíz probable del error 1068'
    $roots = @(Get-RootCauses $sick)
    if ($roots.Count -eq 0) {
        Write-Status 'OK' 'No se encontró ninguna dependencia rota en los servicios de red clave.'
        return
    }
    foreach ($r in $roots) {
        Write-Status 'ERROR' "$($r.Node): $($r.Issue)"
        switch -Wildcard ($r.Issue) {
            'NO EXISTE*'      { $script:Findings.Add("'$($r.Node)' es dependencia pero no existe (error 1075 -> 1068). Revisar DependOnService del servicio padre o restaurar la clave desde otro equipo con la misma versión de Windows; luego sfc /scannow.") }
            'DESHABILITADO'   { $script:Findings.Add("'$($r.Node)' está deshabilitado (error 1058 -> 1068). Se corrige con -Fix.") }
            'FALTA EL ARCHIVO*' { $script:Findings.Add("Binario de '$($r.Node)' ausente: ejecutar sfc /scannow y DISM con origen local (ver recomendaciones).") }
            'DETENIDO*'       {
                if ($script:AfterRepair) { $script:Findings.Add("'$($r.Node)' sigue detenido tras la reparación: ver su código de error en 'Estado tras la reparación'.") }
                else { $script:Findings.Add("'$($r.Node)' está detenido; -Fix intentará iniciarlo y mostrará el código de error real.") }
            }
            '*GRUPO*'         { $script:Findings.Add("Grupo de dependencia '$($r.Node.TrimStart('@'))' sin miembros activos: revisar los drivers de ese grupo.") }
        }
    }
}

function Show-DisabledDependencies {
    Write-Section '4) Dependencias deshabilitadas en el resto de servicios'
    # Las dependencias del catálogo ya se tratan en las secciones 1-3
    $pairs = @(Get-DisabledDependencies | Where-Object { -not ($Catalog | Where-Object Name -eq $_.Dependency) })
    if ($pairs.Count -eq 0) { Write-Status 'OK' 'Ningún servicio depende de otro deshabilitado.'; return }
    foreach ($p in $pairs) {
        $auto = $p.DependentStart -in 'Auto','AutoDelayed','Boot','System'
        $who  = if ($p.IsWindows) { '' } else { '  [no es de Windows: revisar a mano]' }
        Write-Status $(if ($auto) { 'WARN' } else { 'INFO' }) ("{0} <{1}> depende de {2} (DESHABILITADO){3}" -f $p.Dependent, $p.DependentStart, $p.Dependency, $who)
        if ($auto -and $p.IsWindows) {
            $script:Findings.Add("'$($p.Dependent)' ($($p.DependentStart)) falla con 1068 porque '$($p.Dependency)' está deshabilitado. -Fix lo pone en Manual.")
        }
    }
}

function Show-OptimizerCheck {
    Write-Section '5) Servicios de Windows deshabilitados y directivas'
    $dis = @(Get-AllServiceInfo | Where-Object { $_.Start -eq 4 -and (Test-WindowsBinary $_) } | Sort-Object Name)
    $dis | Select-Object Name, ImagePath | Export-Csv (Join-Path $LogDir 'servicios_windows_deshabilitados.csv') -NoTypeInformation -Encoding UTF8
    if ($dis.Count -ge $OptimizerThreshold) {
        Write-Status 'WARN' "$($dis.Count) servicios de Windows deshabilitados (una instalación limpia tiene ~10-20). Patrón típico de un 'optimizador' o script de debloat:"
        Write-Host ('        ' + (($dis | ForEach-Object Name) -join ', '))
        $script:Persistent.Add("Hay $($dis.Count) servicios de Windows deshabilitados: se usó un 'optimizador'/debloat. Desinstálelo o no lo vuelva a ejecutar (y revise sus tareas programadas), o volverá a romper la red. Lista completa en servicios_windows_deshabilitados.csv.")
    } else {
        Write-Status 'OK' "$($dis.Count) servicios de Windows deshabilitados (dentro de lo normal)."
    }

    # Una directiva (local o GPO) que fuerce el tipo de inicio revierte los cambios en cada actualización de directivas
    $cfg = Join-Path $LogDir 'directiva_servicios.inf'
    & secedit.exe /export /mergedpolicy /areas SERVICES /cfg $cfg /quiet 2>&1 | Out-Null
    if (-not (Test-Path -LiteralPath $cfg)) { Write-Status 'INFO' 'No se pudo exportar la directiva de seguridad (secedit).'; return }
    $inSection = $false; $forced = @()
    foreach ($line in Get-Content -LiteralPath $cfg) {
        if ($line -match '^\[(.+)\]') { $inSection = $Matches[1] -eq 'Service General Setting'; continue }
        if ($inSection -and $line -match '^"?([^",]+)"?\s*,\s*(\d)') { $forced += [pscustomobject]@{ Name = $Matches[1]; Start = [int]$Matches[2] } }
    }
    if ($forced.Count -eq 0) { Write-Status 'OK' 'Ninguna directiva fuerza el tipo de inicio de servicios.'; return }
    foreach ($f in $forced) {
        $txt = @{ 2 = 'Auto'; 3 = 'Manual'; 4 = 'Disabled' }[$f.Start]
        Write-Status $(if ($f.Start -eq 4) { 'WARN' } else { 'INFO' }) "Directiva fuerza $($f.Name) -> $txt"
        if ($f.Start -eq 4 -and (($Catalog | Where-Object Name -eq $f.Name) -or $Targets -contains $f.Name)) {
            $script:Persistent.Add("Una directiva (secpol.msc o GPO > Configuración de seguridad > Servicios del sistema) fuerza '$($f.Name)' a Deshabilitado: revertirá la reparación. Cambiarla en la directiva.")
        }
    }
}

$FirewallKeys = 'Parameters\FirewallPolicy',
                'Parameters\FirewallPolicy\FirewallRules',
                'Parameters\FirewallPolicy\RestrictedServices\AppIso\FirewallRules',
                'Parameters\FirewallPolicy\RestrictedServices\Configurable\System',
                'Parameters\FirewallPolicy\RestrictedServices\Static\System',
                'Defaults\FirewallPolicy'

function Get-FirewallMissingKeys {
    $base = Join-Path $SvcRoot 'SharedAccess'
    $FirewallKeys | ForEach-Object { Join-Path $base $_ } | Where-Object { -not (Test-Path -LiteralPath $_) }
}

function Show-FirewallCheck {
    # Si está deshabilitado lo trata el catálogo; aquí se investiga por qué no arranca estando habilitado
    if ((Get-State 'MpsSvc') -eq 'Running' -or (Test-Disabled 'MpsSvc') -or -not (Get-Info 'MpsSvc')) { return }
    Write-Section 'Firewall de Windows (MpsSvc) habilitado pero detenido'
    $x = Get-ExitInfo 'MpsSvc'
    Write-Status 'ERROR' "Último código de salida de MpsSvc: $($x.Message)"
    $missing = @(Get-FirewallMissingKeys)
    foreach ($m in $missing) { Write-Status 'ERROR' "Falta la clave $m" }
    try {
        $acl = Get-Acl -LiteralPath (Join-Path $SvcRoot 'SharedAccess\Parameters\FirewallPolicy') -ErrorAction Stop
        if (-not ($acl.Access | Where-Object { $_.IdentityReference -match 'MpsSvc' })) {
            Write-Status 'WARN' 'La clave FirewallPolicy no concede permisos a NT SERVICE\MpsSvc (por defecto sí los tiene).'
            $script:Findings.Add('Revisar permisos de HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy: conceder Control total a "NT SERVICE\MpsSvc".')
        }
    } catch { }
    if ($missing) {
        $script:Findings.Add('Faltan claves de la directiva del Firewall (típico tras eliminar apps UWP con un optimizador). -Fix las recrea vacías y reintenta MpsSvc.')
    } else {
        $script:Findings.Add("MpsSvc no arranca ($($x.Message)). Probar 'netsh advfirewall reset' (restaura las reglas por defecto) y reiniciar.")
    }
}

function Show-Connectivity {
    Write-Section 'Prueba de conectividad'
    try {
        $ifs = @([System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces() |
            Where-Object { $_.OperationalStatus -eq 'Up' -and $_.NetworkInterfaceType -notin 'Loopback','Tunnel' })
    } catch { Write-Status 'WARN' "No se pudieron leer las interfaces: $($_.Exception.Message)"; return }
    if ($ifs.Count -eq 0) {
        Write-Status 'ERROR' 'Ninguna interfaz de red conectada (revisar cable / WiFi).'
        $script:Findings.Add('No hay ninguna interfaz conectada: revisar cable, WiFi o el driver del adaptador.')
        return
    }
    $gateways = @()
    foreach ($if in $ifs) {
        $p   = $if.GetIPProperties()
        $ip  = @($p.UnicastAddresses | Where-Object { $_.Address.AddressFamily -eq 'InterNetwork' } | ForEach-Object { $_.Address.ToString() })
        $gw  = @($p.GatewayAddresses | Where-Object { $_.Address.AddressFamily -eq 'InterNetwork' } | ForEach-Object { $_.Address.ToString() })
        $dns = @($p.DnsAddresses | Where-Object { $_.AddressFamily -eq 'InterNetwork' } | ForEach-Object { $_.ToString() })
        $gateways += $gw
        Write-Status 'INFO' ("{0}: IP={1} puerta de enlace={2} DNS={3}" -f $if.Name, ($ip -join ','), ($gw -join ','), ($dns -join ','))
        if ($ip | Where-Object { $_ -like '169.254.*' }) {
            Write-Status 'ERROR' "$($if.Name) tiene IP automática 169.254.x.x: el servidor DHCP (router) no respondió."
            $script:Findings.Add("'$($if.Name)' no obtiene IP por DHCP (169.254.x.x): revisar router/cable y el servicio Dhcp.")
        }
    }

    $ping = New-Object System.Net.NetworkInformation.Ping
    foreach ($g in ($gateways | Select-Object -Unique)) {
        try   { $ok = $ping.Send($g, 2000).Status -eq 'Success' } catch { $ok = $false }
        if ($ok) { Write-Status 'OK' "Ping a la puerta de enlace $g" } else { Write-Status 'WARN' "La puerta de enlace $g no responde al ping" }
    }

    $hostName = 'www.msftconnecttest.com'
    try   { $addr = [System.Net.Dns]::GetHostAddresses($hostName); Write-Status 'OK' "DNS resuelve $hostName -> $($addr[0])" }
    catch { Write-Status 'ERROR' "DNS no resuelve $hostName"; $script:Findings.Add('La resolución DNS falla: revisar el servicio Dnscache y los DNS configurados.'); return }

    try {
        $r = Invoke-WebRequest "http://$hostName/connecttest.txt" -UseBasicParsing -TimeoutSec 10 -ErrorAction Stop
        if ($r.Content -match 'Microsoft Connect Test') { Write-Status 'OK' 'Acceso a Internet por HTTP correcto.' }
        else { Write-Status 'WARN' 'HTTP responde con contenido inesperado (¿portal cautivo o proxy?).' }
    } catch {
        Write-Status 'WARN' "Sin acceso HTTP a Internet: $($_.Exception.Message)"
        return
    }
    # Un reloj desfasado hace fallar HTTPS aunque haya conexión
    try {
        $remote = [datetime]::Parse($r.Headers['Date'], [Globalization.CultureInfo]::InvariantCulture).ToUniversalTime()
        $drift  = [math]::Abs(((Get-Date).ToUniversalTime() - $remote).TotalMinutes)
        if ($drift -gt 5) {
            Write-Status 'WARN' ("El reloj del equipo difiere {0:N0} min de la hora real: HTTPS fallará." -f $drift)
            $script:Findings.Add('Reloj desfasado: corregir fecha/hora (W32Time en Manual y "Sincronizar ahora") o los sitios HTTPS fallarán.')
        }
    } catch { }
}
#endregion

#region Reparación -------------------------------------------------------------------------
function Set-StartType([string]$Name, [string]$Type) {
    $scMap  = @{ Boot='boot'; System='system'; Auto='auto'; AutoDelayed='delayed-auto'; Manual='demand'; Disabled='disabled' }
    $regMap = @{ Boot=0; System=1; Auto=2; AutoDelayed=2; Manual=3; Disabled=4 }

    $out = & sc.exe config $Name start= $scMap[$Type] 2>&1 | Out-String
    if ($LASTEXITCODE -eq 0) { Write-Status 'FIX' "$Name -> inicio $Type"; return $true }

    # Plan B: escribir directamente en el registro (se aplica tras reiniciar)
    try {
        $path = Join-Path $SvcRoot $Name
        Set-ItemProperty -LiteralPath $path -Name Start -Value $regMap[$Type] -Type DWord -ErrorAction Stop
        if ($Type -eq 'AutoDelayed') { Set-ItemProperty -LiteralPath $path -Name DelayedAutostart -Value 1 -Type DWord -ErrorAction Stop }
        Write-Status 'FIX' "$Name -> inicio $Type (vía registro, requiere reinicio)"
        $script:RebootRequired = $true
        return $true
    } catch {
        Write-Status 'ERROR' "$Name : no se pudo cambiar el inicio. sc.exe: $($out.Trim()) | Registro: $($_.Exception.Message)"
        $script:Findings.Add("No se pudo cambiar el tipo de inicio de '$Name' (clave protegida). Ejecutar como SYSTEM, p.ej.: psexec -s sc.exe config $Name start= $($scMap[$Type])")
        return $false
    }
}

function Start-Node([string]$Name) {
    $i = Get-Info $Name
    if (-not $i) { return }
    if ((Update-State $Name) -eq 'Running') { return }
    if ($i.Start -eq 4) { Write-Status 'WARN' "$Name omitido: sigue deshabilitado"; return }

    & sc.exe start $Name 2>&1 | Out-Null
    $code = $LASTEXITCODE
    if ($code -eq 0 -or $code -eq 1056) {
        for ($n = 0; $n -lt 40; $n++) {
            if ((Update-State $Name) -eq 'Running') { break }
            Start-Sleep -Milliseconds 500
        }
        $st = Get-State $Name
        if ($st -eq 'Running') {
            Write-Status 'OK' "Iniciando $Name ... OK"
            if (-not $script:Started.Contains($Name)) { $script:Started.Add($Name) }
            return
        }
        $x = Get-ExitInfo $Name
        $code = $x.Code; $msg = "estado=$st, $($x.Message)"
    } else {
        $msg = Get-Win32Message $code
    }
    Write-Status 'ERROR' "Iniciando $Name ... FALLO ($code): $msg"
    $script:StartFailures.Add([pscustomobject]@{ Name = $Name; Code = $code; Message = $msg; IsDriver = $i.IsDriver; Start = ConvertTo-StartText $i })
}

function Confirm-Started([int]$WaitSeconds = 5) {
    # Algunos servicios arrancan y se cierran segundos después (p. ej. MpsSvc con error 87):
    # sc.exe devuelve éxito y sin esta comprobación se darían por buenos.
    if ($script:Started.Count -eq 0) { return }
    Write-Status 'INFO' "Comprobando en $WaitSeconds s que los servicios iniciados siguen en ejecución..."
    Start-Sleep -Seconds $WaitSeconds
    foreach ($n in @($script:Started)) {
        if ((Update-State $n) -eq 'Running') { continue }
        $x = Get-ExitInfo $n
        $i = Get-Info $n
        Write-Status 'ERROR' "$n arrancó pero se detuvo después: $($x.Message)"
        $script:StartFailures.Add([pscustomobject]@{ Name = $n; Code = $x.Code; Message = "arrancó y se detuvo: $($x.Message)"; IsDriver = $i.IsDriver; Start = ConvertTo-StartText $i })
        [void]$script:Started.Remove($n)
    }
}

function Repair-Firewall {
    if ((Update-State 'MpsSvc') -eq 'Running' -or (Test-Disabled 'MpsSvc') -or -not (Get-Info 'MpsSvc')) { return }
    $missing = @(Get-FirewallMissingKeys)
    if ($missing.Count -eq 0) { return }
    Write-Host ''
    Write-Status 'INFO' 'Paso 3: recrear claves ausentes de la directiva del Firewall y reintentar MpsSvc'
    foreach ($k in $missing) {
        try   { New-Item -Path $k -Force -ErrorAction Stop | Out-Null; Write-Status 'FIX' "Creada $k" }
        catch { Write-Status 'ERROR' "No se pudo crear $k : $($_.Exception.Message)" }
    }
    [void]$script:StartFailures.RemoveAll([Predicate[object]]{ param($f) $f.Name -eq 'MpsSvc' })
    Start-Node 'MpsSvc'
    Confirm-Started
}

function Invoke-Repair($ScanResults) {
    Write-Section 'REPARACIÓN'

    $backup = Join-Path $LogDir 'Services_backup.reg'
    & reg.exe export 'HKLM\SYSTEM\CurrentControlSet\Services' $backup /y | Out-Null
    if ($LASTEXITCODE -eq 0) { Write-Status 'OK' "Respaldo del registro de servicios: $backup" }
    else {
        Write-Status 'ERROR' 'No se pudo respaldar HKLM\...\Services. Se cancela la reparación por seguridad.'
        return
    }

    Write-Host ''
    Write-Status 'INFO' 'Paso 1: restablecer tipos de inicio'
    $changed = $false
    foreach ($r in $ScanResults) {
        if ($r.Actual -eq '-') { continue }
        $c = $Catalog | Where-Object Name -eq $r.Name
        if ($c.NoFix) { continue }
        $disabledWrong = $r.Actual -eq 'Disabled' -and $c.Default -ne 'Disabled'
        $criticalDiff  = $c.Critical -and ($r.Problems -match '^Inicio |; Inicio ')
        if ($disabledWrong -or $criticalDiff) { if (Set-StartType $r.Name $c.Default) { $changed = $true } }
    }
    Initialize-Cache   # releer el registro: los servicios recién habilitados también cuentan como dependientes

    # Dependencias deshabilitadas que no están en el catálogo -> Manual (el SCM las arrancará cuando haga falta):
    # las del árbol de los servicios clave y las de cualquier servicio automático de Windows
    $toManual = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($n in Get-PostOrder $Targets) {
        if (-not $n.StartsWith('@') -and (Test-Disabled $n)) { [void]$toManual.Add((Get-Info $n).Name) }
    }
    foreach ($p in Get-DisabledDependencies) {
        if ($p.IsWindows -and $p.DependentStart -in 'Auto','AutoDelayed','Boot','System') { [void]$toManual.Add($p.Dependency) }
    }
    foreach ($n in $toManual) {
        if ($Catalog | Where-Object Name -eq $n) { continue }
        if (Set-StartType $n 'Manual') { $changed = $true }
    }
    if (-not $changed) { Write-Status 'OK' 'No hacía falta cambiar ningún tipo de inicio.' }

    Initialize-Cache   # releer el registro tras los cambios

    Write-Host ''
    Write-Status 'INFO' 'Paso 2: iniciar servicios en orden de dependencias'
    $autoTargets = $Catalog | Where-Object { $_.Default -in 'Auto','AutoDelayed','Boot','System' -and -not $_.NoFix } | ForEach-Object Name
    foreach ($n in Get-PostOrder $autoTargets) {
        if ($n.StartsWith('@')) { continue }
        Start-Node $n
    }
    Confirm-Started

    Repair-Firewall

    if ($ResetStack) {
        Write-Host ''
        Write-Status 'INFO' 'Paso 4: restablecer Winsock y TCP/IP'
        & netsh.exe winsock reset | Out-Host
        & netsh.exe int ip reset (Join-Path $LogDir 'netsh_ip_reset.log') | Out-Host
        & ipconfig.exe /flushdns | Out-Host
        $script:RebootRequired = $true
    }
}
#endregion

#region Ejecución principal ----------------------------------------------------------------
# En Windows 11 ProductName sigue diciendo "Windows 10": se corrige según la build
$osName = if ($OsBuild -ge 22000) { $OsInfo.ProductName -replace 'Windows 10', 'Windows 11' } else { $OsInfo.ProductName }
Write-Section "Diagnóstico de servicios de red - $osName $($OsInfo.DisplayVersion) (build $OsBuild)"
Write-Status 'INFO' "Equipo: $env:COMPUTERNAME | Modo: $(if ($Fix) {'REPARACIÓN'} else {'SOLO DIAGNÓSTICO'})$(if ($ResetStack) {' + RESET PILA'}) | Logs: $LogDir"
if ($OsBuild -lt 10240) { Write-Status 'WARN' 'Este script está pensado para Windows 10/11; en versiones anteriores los valores por defecto difieren.' }

Initialize-Cache

Write-Section '1) Servicios y drivers de Windows necesarios para la red'
$scan = Invoke-CatalogScan
Show-CatalogScan $scan
$scan | Export-Csv (Join-Path $LogDir 'servicios_antes.csv') -NoTypeInformation -Encoding UTF8

Show-DependencyAnalysis
Show-DisabledDependencies
Show-OptimizerCheck
Show-FirewallCheck
Show-ScmEvents
Show-Adapters
Show-ClassFilters

if ($Fix -or $ResetStack) {
    $repairStart = Get-Date
    if ($Fix) { Invoke-Repair $scan }
    elseif ($ResetStack) {
        Write-Section 'Restablecer Winsock y TCP/IP'
        & netsh.exe winsock reset | Out-Host
        & netsh.exe int ip reset (Join-Path $LogDir 'netsh_ip_reset.log') | Out-Host
        & ipconfig.exe /flushdns | Out-Host
        $script:RebootRequired = $true
    }

    # Las recomendaciones del diagnóstico inicial ya no aplican: se vuelve a diagnosticar
    $script:Findings.Clear()
    $script:AfterRepair = $true

    Write-Section 'Estado tras la reparación'
    Initialize-Cache
    $after = Invoke-CatalogScan
    Show-CatalogScan ($after | Where-Object { $_.Severity -ne 'OK' })
    if (-not ($after | Where-Object { $_.Severity -in 'WARN','ERROR' })) { Write-Status 'OK' 'Todos los servicios del catálogo están correctos.' }
    $after | Export-Csv (Join-Path $LogDir 'servicios_despues.csv') -NoTypeInformation -Encoding UTF8

    Show-DependencyAnalysis
    Show-FirewallCheck
    Show-ScmEvents -Since $repairStart -CsvName 'eventos_scm_despues.csv'
    Show-Adapters

    foreach ($f in $script:StartFailures) {
        if ($f.IsDriver -and $f.Start -in 'Boot','System') {
            $script:Findings.Add("El driver '$($f.Name)' (inicio $($f.Start)) no arrancó [$($f.Code)]: los drivers de arranque solo se cargan al iniciar Windows -> REINICIAR. Si persiste, sfc /scannow.")
            $script:RebootRequired = $true
        } else {
            $script:Findings.Add("'$($f.Name)' falló al iniciar con $($f.Code): $($f.Message)")
        }
    }
}

Show-Connectivity

Write-Section 'RECOMENDACIONES'
$all = @($script:Persistent) + @($script:Findings) | Select-Object -Unique
if ($all.Count -eq 0) {
    if ($Fix) { Write-Status 'OK' 'No quedan problemas pendientes detectados.' }
    else { Write-Status 'INFO' 'No se detectaron fallos evidentes en servicios. Si sigue sin red, pruebe con -ResetStack y revise el driver del adaptador.' }
}
$all | ForEach-Object { Write-Status 'WARN' $_ }

Write-Host ''
if ($Fix) {
    Write-Status 'INFO' 'Reinicie y vuelva a ejecutar el script SIN parámetros para confirmar que los cambios persisten'
    Write-Host  '        (si vuelven a aparecer servicios deshabilitados, algo los revierte: optimizador, tarea programada o directiva).'
    Write-Host ''
}
Write-Status 'INFO' 'Si los problemas persisten después de reiniciar:'
if (Test-Disabled 'TrustedInstaller') {
    Write-Host  '        0. TrustedInstaller está DESHABILITADO: sfc y DISM no funcionarán hasta ejecutar este script con -Fix.'
}
Write-Host  '        1. sfc /scannow'
Write-Host  '        2. Sin Internet, DISM necesita un origen local (ISO/USB de la misma versión de Windows):'
Write-Host  '           DISM /Online /Cleanup-Image /RestoreHealth /Source:WIM:D:\sources\install.wim:1 /LimitAccess'
Write-Host  '           (use install.esd con ESD: en lugar de WIM: si su medio trae .esd)'
Write-Host  '        3. Ejecute este script con -ResetStack (netsh winsock reset / netsh int ip reset) y reinicie.'
Write-Host  '        4. Desinstale el adaptador en el Administrador de dispositivos (marcando eliminar driver) y reinicie.'
Write-Host  '        5. Desinstale antivirus/VPN/firewalls de terceros: suelen dejar filtros NDIS/WFP rotos.'
if (Test-Path -LiteralPath (Join-Path $LogDir 'Services_backup.reg')) {
    Write-Host  "        6. Para deshacer cambios del registro: reg import `"$LogDir\Services_backup.reg`" y reiniciar."
}

if ($script:RebootRequired) {
    Write-Host ''
    Write-Status 'WARN' 'SE REQUIERE REINICIAR EL EQUIPO para aplicar todos los cambios.'
}
Write-Host ''
Write-Status 'INFO' "Informe completo en: $LogDir"
try { Stop-Transcript | Out-Null } catch { }
#endregion
