# Repair-NetworkServices

Script de PowerShell que **diagnostica y repara el error 1068** ("No se pudo iniciar el servicio o grupo de dependencia") en los servicios de red de **Windows 10 y Windows 11**, típico de equipos que se quedan **sin red tras usar un "optimizador", un script de debloat o desinstalar un antivirus/VPN**.

> *English summary below.*

## Síntomas

- El equipo no tiene red (ni cable ni WiFi), o el icono de red muestra "Sin Internet" aunque el router funciona.
- Al iniciar servicios como **Cliente DHCP**, **Cliente DNS**, **Reconocimiento de ubicación de red** o **Servicio de lista de redes** aparece:
  - `Error 1068: No se pudo iniciar el servicio o grupo de dependencia.`
  - `Error 1058: No se puede iniciar el servicio, porque está deshabilitado...`
- En el Visor de eventos hay muchos eventos **7001** del *Service Control Manager*.
- Puede que tampoco funcionen el Firewall, `sfc /scannow`, el solucionador de problemas de red o WMI.

## Qué hace

**Sin parámetros solo diagnostica: no modifica nada.**

| Paso | Descripción |
|------|-------------|
| 1 | Compara unos 70 servicios y drivers de red con sus **valores por defecto de Windows** (tipo de inicio, estado y existencia del binario). |
| 2–3 | Recorre el **árbol de dependencias** de los servicios de red clave y señala la **causa raíz** del 1068: la dependencia más profunda que está deshabilitada, falta o no arranca. |
| 4 | Busca en **todos** los servicios del sistema aquellos que dependen de otro servicio deshabilitado. |
| 5 | Detecta si se usó un **"optimizador"** (demasiados servicios de Windows deshabilitados) y si una **directiva local o GPO** fuerza tipos de inicio, lo que desharía la reparación. |
| — | Revisa el **Firewall** (claves de directiva ausentes), los **eventos** del sistema, los **adaptadores**, los **filtros NDIS huérfanos** y prueba la **conectividad**: IP/DHCP, puerta de enlace, DNS, HTTP y desfase del reloj. |

Con **`-Fix`**:

1. Guarda una **copia de seguridad** de `HKLM\SYSTEM\CurrentControlSet\Services` (`Services_backup.reg`).
2. Restablece los tipos de inicio por defecto de los servicios del catálogo. Las dependencias deshabilitadas de Windows pasan a *Manual*.
3. Arranca los servicios **en orden de dependencias** y comprueba que siguen en ejecución unos segundos después.
4. Si el Firewall no arranca porque faltan claves de su directiva, las recrea.
5. **Vuelve a diagnosticar** y muestra solo lo que queda pendiente.

Con **`-ResetStack`** además ejecuta `netsh winsock reset`, `netsh int ip reset` e `ipconfig /flushdns` (requiere reiniciar).

## Compatibilidad

| Sistema | Estado |
|---------|--------|
| Windows 10 (1607 LTSB/LTSC – 22H2) | ✅ Probado en un caso real (1607 LTSB, error 1068 por un optimizador) |
| Windows 11 (21H2 – 24H2 y posteriores) | ✅ Diagnóstico verificado. Los valores que cambian por versión se ajustan automáticamente según la build (p. ej. `NlaSvc` es *Manual* desde 24H2) |
| Windows 7 / 8.1 | ❌ No soportado (los valores por defecto son distintos) |

Requisitos: **PowerShell 5.1** (incluido en Windows 10/11) y ejecutar **como administrador**. No necesita Internet ni instalar nada.

## Uso

Como el equipo afectado normalmente **no tiene red**, descarga el script en otro equipo y cópialo con una **memoria USB**.

1. Copia `Repair-NetworkServices.ps1` a la USB (por ejemplo, `E:\`).
2. En el equipo afectado abre **PowerShell como administrador** (clic derecho en Inicio → *Windows PowerShell (administrador)* o *Terminal (administrador)*).
3. Ve a la carpeta de la USB y ejecuta:

```powershell
cd E:\

# 1. Solo diagnóstico (no cambia nada)
powershell -ExecutionPolicy Bypass -File .\Repair-NetworkServices.ps1

# 2. Diagnóstico + reparación
powershell -ExecutionPolicy Bypass -File .\Repair-NetworkServices.ps1 -Fix

# 3. Si sigue sin red después de reiniciar
powershell -ExecutionPolicy Bypass -File .\Repair-NetworkServices.ps1 -Fix -ResetStack
```

4. **Reinicia** y vuelve a ejecutar el paso 1 para confirmar que los cambios se mantienen.

| Parámetro | Descripción |
|-----------|-------------|
| `-Fix` | Aplica las correcciones. |
| `-ResetStack` | Restablece Winsock y TCP/IP (requiere reinicio). Se puede combinar con `-Fix`. |
| `-LogDir <ruta>` | Carpeta donde se crea `NetDiag_<fecha>`. Por defecto, la carpeta del script. |

### Resultados

Cada ejecución crea una carpeta `NetDiag_AAAAMMDD_HHMMSS` junto al script con:

| Archivo | Contenido |
|---------|-----------|
| `transcript.txt` | Salida completa de la ejecución |
| `servicios_antes.csv` / `servicios_despues.csv` | Estado del catálogo antes y después de reparar |
| `servicios_windows_deshabilitados.csv` | Todos los servicios de Windows deshabilitados |
| `eventos_scm.csv` / `eventos_scm_despues.csv` | Eventos del Service Control Manager |
| `directiva_servicios.inf` | Directiva de seguridad aplicada a servicios (secedit) |
| `Services_backup.reg` | Copia de seguridad del registro de servicios (solo con `-Fix`) |

> ⚠️ **Privacidad:** estos archivos contienen el nombre del equipo, el usuario, direcciones MAC/IP y la lista de programas instalados como servicios. Revísalos antes de publicarlos en un *issue*.

## Deshacer los cambios

`-Fix` guarda una copia del registro antes de modificar nada. Para restaurarla:

```powershell
reg import "E:\NetDiag_AAAAMMDD_HHMMSS\Services_backup.reg"
```

y reinicia el equipo.

## Si el problema persiste

1. `sfc /scannow` (el script verifica que *TrustedInstaller* no esté deshabilitado, ya que sin él no funciona).
2. Sin Internet, DISM necesita un origen local (ISO/USB de la **misma versión** de Windows):
   `DISM /Online /Cleanup-Image /RestoreHealth /Source:WIM:D:\sources\install.wim:1 /LimitAccess`
3. Ejecuta el script con `-ResetStack` y reinicia.
4. Desinstala el adaptador en el Administrador de dispositivos (marcando "eliminar el driver") y reinicia.
5. Desinstala antivirus, VPN o firewalls de terceros: suelen dejar filtros NDIS/WFP rotos.
6. Si el script detectó un **optimizador**, desinstálalo o no lo vuelvas a ejecutar, y revisa sus tareas programadas. Si no, volverá a romper la red.

## Caso real

En un Windows 10 Enterprise 2016 LTSB sin red, el script encontró **148 servicios deshabilitados** por un optimizador, entre ellos `EventLog`, `nsi`, `BFE`, `Winmgmt`, `SamSs` y `PlugPlay`. La causa raíz del 1068 era:

```
Dhcp  <Auto>  -> DETENIDO
|-- NSI  <Disabled>  -> DESHABILITADO
NlaSvc  <Auto>  -> DETENIDO
|-- Eventlog  <Disabled>  -> DESHABILITADO
```

Con `-Fix` se restablecieron los tipos de inicio, se arrancaron los servicios en orden y el equipo recuperó la red.

## Aviso

El script modifica la configuración de servicios del sistema. Aunque crea una copia de seguridad y solo restaura valores por defecto de Windows, **úsalo bajo tu propia responsabilidad**. Si tienes servicios deshabilitados a propósito, revisa el diagnóstico antes de ejecutar `-Fix`. Windows Update (`wuauserv`, `BITS`, `UsoSvc`) **nunca** se modifica.

## Contribuir

¿Te funcionó, o encontraste un caso que no detecta? Abre un *issue* con el `transcript.txt` del diagnóstico (revisa antes la nota de privacidad). Si conoces valores por defecto que cambian en alguna build de Windows, se añaden en `$BuildOverrides` dentro del script.

## Licencia

[MIT](LICENSE)

---

## English summary

**Repair-NetworkServices** is a PowerShell script for **Windows 10 and 11** that diagnoses and fixes **error 1068** ("The dependency service or group failed to start") on network services such as DHCP Client, DNS Client and Network Location Awareness. This usually happens after using a "tweaker"/debloat tool or uninstalling an antivirus/VPN.

- Run without parameters: **diagnosis only**, nothing is changed. It walks the service dependency tree, finds the **root cause** (the deepest disabled, missing or failing dependency), detects debloat tools and policies that force services to *Disabled*, checks the firewall, adapters, NDIS filters and connectivity.
- `-Fix`: backs up the services registry key, restores the default Windows start types, starts services in dependency order, verifies they stay running and runs the diagnosis again.
- `-ResetStack`: also resets Winsock and TCP/IP.

Run it from an **elevated PowerShell** (copy it via USB, since the affected PC usually has no network):

```powershell
powershell -ExecutionPolicy Bypass -File .\Repair-NetworkServices.ps1        # diagnose
powershell -ExecutionPolicy Bypass -File .\Repair-NetworkServices.ps1 -Fix   # repair
```

To undo: `reg import <NetDiag folder>\Services_backup.reg` and reboot. Output messages are in Spanish.
