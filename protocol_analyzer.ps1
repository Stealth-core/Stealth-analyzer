param(
    [string] $protocolFileName = "c:\stealth\ussl_protocol_log.txt",  # use this parameter to point to a log file
    [string] $subnetFilter ="\d+.\d+.\d+.\d+"  # this parameter can be a simple "192.168.1" or any regex expression 
)
function octet2String {
    param ([string]$octet
    )
    ([uint16]::Parse($octet,'HexNumber')).ToString()
}
function  IP2string {
    param ([string]$hex1,
           [string]$hex2)
       $r= octet2String($hex1.Substring(0,2)) 
       $r += "."
       $r += octet2String($hex1.Substring(2,2)) 
       $r += "."
       $r +=  octet2String($hex2.Substring(0,2))
       $r += "."
       $r +=  octet2String($hex2.Substring(2,2))
       return $r
        
}
$sessionIDs = @{}
$protocolFile = Get-Content -Path $protocolFileName 
foreach ($line in $protocolFile ) {
    if (($line -match "SessionPDU")){
        if (($line -match " SE_SEND_S") -and ($line -match "RemoteIp")) {
            $sesID = [regex]::match($line,'SendSessionPDU\(([0-9A-F]{5,99})')
            $m = [regex]::match($line,'RemoteIp=((([0-9a-f]{1,4}):){1,7}([0-9a-f]{1,4}))')
            $t = [regex]::match($line,'; ([0-9]{4}\/[0-9]{2}\/[0-9]{2} [0-9]{1,2}:[0-9]{1,2}[0-9]{1,2}:[0-9]{1,2}.[0-9]{1,3})')
            $s = [regex]::match($line,'SEND_S([0-9])')
            $remoteIPv4=IP2string -hex1 $m.Groups[3].ToString() -hex2 $m.Groups[4].ToString()
            if (($remoteIPv4 -match $subnetFilter)){
                if  (-not $sessionIDs.ContainsKey($sesID.Groups[1].ToString())){
                    $sessionIDs += @{$sesID.Groups[1].ToString()=$remoteIPv4}
                } else {
                    $sessionIDs[$sesID.Groups[1].ToString()]=$remoteIPv4
                }
                Write-Host 'Send '$s' @' $t ' Remote IP ' $remoteIPv4
            }
        }
    } elseif ($line -match "ProcessPDU") {
            $sesID = [regex]::match($line,'ProcessPDU\(([0-9A-F]{5,99})')
            $sess = [regex]::match($line,'SESS[0-9]')

            # Write-Host '   --->>>' $line #   Rec S1 for ' $sesID.Groups[1] $sessionIDs[$sesID.Groups[1].ToString()]
            Write-Host '   --->>> Rec '$sess 'for RemoteIP '$sessionIDs[$sesID.Groups[1].ToString()]
        }
    }

