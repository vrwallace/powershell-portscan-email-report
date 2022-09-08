####################################
# Program: openportemailreport.ps1
# By: Von Wallace vonwallace@vonwallace.com
# To run add the following to the login script
# powershell.exe –Noninteractive –Noprofile –Command "C:\support\openportemailreport.ps1"
# Probes selected ports on all host located in C:\support\firewalllist.txt and grabs a banner if available
###################################

function ConvertFrom-Hexadecimal([string] $hexString) {
    [byte[]] $data = @()

    if ([string]::IsNullOrEmpty($hexString) -eq $true -or $hexString.Length % 2 -ne 0) {
        throw New-Object FormatException("Hexadecimal string must not be empty and must contain an even number of digits to be valid.");
    }

    $hexString = $hexString.ToUpperInvariant()
    $data = New-Object byte[] -ArgumentList ($hexString.Length / 2)

    for ([int] $index = 0; $index -lt $hexString.Length; $index += 2) {
        [int] $highDigitValue = if ($hexString[$index] -le ([char] '9')) { $hexString[$index] - ([char] '0') } else { $hexString[$index] - ([char] 'A') + 10 }
        [int] $lowDigitValue = if ($hexString[$index + 1] -le ([char] '9')) { $hexString[$index + 1] - ([char] '0') } else { $hexString[$index + 1] - ([char] 'A') + 10 }

        if ($highDigitValue -lt 0 -or $lowDigitValue -lt 0 -or $highDigitValue -gt 15 -or $lowDigitValue -gt 15) {
            throw New-Object FormatException("An invalid digit was encountered. Valid hexadecimal digits are 0-9 and A-F.")
        }
        else {
            [byte] $value = [byte](($highDigitValue -shl 4) -bor ($lowDigitValue -band 0x0F))
            $data[$index / 2] = $value;
        }
    }

    return , $data
}


$services = @{
    7     = "echo";
    9     = "discard";
    13    = "daytime";
    17    = "qotd";
    19    = "chargen";
    20    = "ftp-data";
    21    = "ftp";
    22    = "ssh";
    23    = "telnet";
    25    = "smtp";
    26    = "rsftp";
    43    = "whois";
    53    = "domain";
    69    = "tftp";
    79    = "finger";
    80    = "http";
    109   = "pop2";
    110   = "pop3";
    111   = "sunrpc";
    113   = "auth";
    115   = "sftp";
    119   = "nntp";
    123   = "ntp";
    135   = "epmap";
    137   = "netbios-ns";
    138   = "netbios-ds";
    139   = "netbios-ssn";
    143   = "imap2";
    161   = "snmp";
    162   = "snmptrap";
    199   = "smux";
    247   = "subntbcst-tftp";
    389   = "ldap";
    443   = "https";
    445   = "microsoft-ds";
    465   = "submissions";
    513   = "login";
    514   = "shell";
    554   = "rtsp";
    587   = "submission";
    631   = "ipp";
    636   = "ldaps";
    902   = "vmware";
    989   = "ftps-data";
    990   = "ftps";
    992   = "telnets";
    993   = "imaps";
    995   = "pop3s";
    1433  = "ms-sql-s";
    1720  = "h323";
    1723  = "pptp";
    1758  = "tftp-mcast";
    1818  = "etftp";
    2525  = "smtp-alt";
    3713  = "tftps";
    3306  = "mysql";
    3389  = "ms-wbt-server";
    4433  = "sonicwall";
    5432  = "postgresql";
    5500  = "fcp-addr-srvr1";
    5800  = "vnc1";
    5900  = "vnc2";
    8080  = "http-alt";
    8888  = "althttpd";
    9100  = "jetdirect";
    1080  = "W32.Beagle; WinHole; HLLW.Deadhat;  Webus";
    2745  = "Bagle Virus Backdoor; Beagle";
    3127  = "W32.Mockbot; Solame;  Novarg(Mydoom); W32.HLLW.Deadhat";
    4444  = "Napster; Prosiak; Swift Remote; Blaster.Worm;  W32.HLLW.Donk; W32.Mockbot; W32.Reidana";
    5554  = "W32.Dabber; Sasser";
    8866  = "W32.Beagle";
    9898  = "CrashCool; Dabber";
    12345 = "Amitis; Ashley; Cron/Crontab; Fat Bitch Trojan; GabanBus; Mypic; NetBus; NetBus Toy; NetBus Worm; Pie Bill Gates; Whack Job; X-bill";
    27374 = "Bad Blood; Baste; Ramen; Seeker; SubSeven; Subseven 2.1.4 DefCon 8;  SubSeven Muie; Ttfloader";
    31337 = "Back Orifice; Back Orifice 1.20 Patches; Back Orifice Russian; Baron Night; Beeone; BO Client; BO Facil; BO Spy; BO2; Cron/Crontab;  Emcommander; Freak2k; Freak88; c; Sockdmini; W32.HLLW.Gool"
}



[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

#settings
$Version = "1.00ps"
$smtpserver = "smtp.office365.com"
$smtpport = "587"
    


$smtpfrom = "someone@somewhere.net"
    
$smtpto = "someone@somewhere.net"
    

$sendusername = "someone@somewhere.net"
$sendpassword = "password"

$firewalllist="C:\support\firewalllist.txt"

$report = @"
<style>
TABLE {border-width: 1px; border-style: solid; border-color: black; border-collapse: collapse;}
TH {border-width: 1px; padding: 3px; border-style: solid; border-color: black; background-color: #6495ED;}
TD {border-width: 1px; padding: 3px; border-style: solid; border-color: black;}
</style>
"@    
$report = $report + "<h4>Open Ports Report</h4>"
$report = $report + "<h4>Version: " + $version + "</h4><br>"

       
$report = $report + "<h4>Open Ports for</h4>"      

$report = $report + "<table style=""width:100%"">
  <tr>
  <th>IP</th> 
    <th>Port</th>
    <th>Is Open</th>
    <th>Service</th> 
    <th>Banner</th> 
  </tr>"


$trig_null = ""
$trig_http = "OPTIONS / HTTP/1.0`r`n`r`n"
#$trig_http="HEAD /  HTTP/1.0`r`n`r`n";
$trig_mssql = ConvertFrom-Hexadecimal("100100e000000100d80000000100007100000000000000076c04000000000000e0030000000000000908000056000a006a000a007e0000007e002000be00090000000000d0000400d8000000d8000000000c29c6634200000000c8000000420061006e006e00650072004700720061006200420061006e006e006500720047007200610062004d006900630072006f0073006f0066007400200044006100740061002000410063006300650073007300200043006f006d0070006f006e0065006e00740073003100320037002e0030002e0030002e0031004f00440042004300")
$trig_ldap = ConvertFrom-Hexadecimal("300c0201016007020103040080003035020102633004000a01000a0100020100020100010100870b6f626a656374436c6173733010040e6e616d696e67436f6e7465787473");
#$trig_smtp="HELO bannergrab.com`r`nHELP`r`nVRFY postmaster`r`nVRFY bannergrab123`r`nEXPN postmaster`r`nQUIT`r`n";
$trig_smtp = "HELO bannergrab.com`r`nHELP`r`nQUIT`r`n"
$trig_fw1admin = "???`r`n?`r`n"
$trig_nbns = ConvertFrom-Hexadecimal("a2480000000100000000000020434b4141414141414141414141414141414141414141414141414141414141410000210001")
$trig_ntp = ConvertFrom-Hexadecimal("e30004fa000100000001000000000000000000000000000000000000000000000000000000000000ca9ba3352d7f950b160200010000000000000000160100010000000000000000")
$trig_nntp = "HELP`r`nLIST NEWSGROUPS`r`nQUIT`r`n"
$trig_pop = "QUIT`r`n"
$trig_finger = "root bin lp wheel spool adm mail postmaster news uucp snmp daemon`r`n"
$trig_snmp = ConvertFrom-Hexadecimal("302902010004067075626c6963a01c0204ffffffff020100020100300e300c06082b060102010101000500302a020100040770726976617465a01c0204fffffffe020100020100300e300c06082b060102010101000500")
$trig_telnet = "`r`r";
$trig_ftp = "HELP`nUSER anonymous`nPASS banner@grab.com`nQUIT`n"
$trig_echo = "Echo`r`n"
$trig_imap = "CAPABILITY`r`n"



$stream_reader = New-Object System.IO.StreamReader ( $firewalllist )
while ($null -ne ($current_line = $stream_reader.ReadLine())) {
    $Computername = $current_line



    $services.keys | Sort-object $_ | ForEach-Object {
        $item = $_
        $service = $($services[$_])
        write-host "Host" $Computername "Scanning Port: " $item "Service: " $service
        $rts = ""
   
        try {
            
            $tcpConnection = New-Object System.Net.Sockets.TcpClient($Computername, $Item)
            
        }
    
        catch {}
      
        
        if ($tcpConnection.Connected) {
            $tcpConnection.ReceiveTimeout = 2000;
            $tcpConnection.SendTimeout = 2000;
            $tcpStream = $tcpConnection.GetStream()
            $reader = New-Object System.IO.StreamReader($tcpStream)
            $writer = New-Object System.IO.StreamWriter($tcpStream)
            $writer.AutoFlush = $true


            try {
                
                switch ( $item ) {
                    ({ 80, 443, 631 -contains $PSItem }) {
                        $writer.WriteLine($trig_http)
                        break;
                    }
                    ({ 25, 26, 465, 587 -contains $PSItem }) {
                        $writer.WriteLine($trig_smtp)
                        break;
                    }
                    ({ 21, 69, 247, 1758, 1818, 3713 -contains $PSItem }) {
                        $writer.WriteLine($trig_ftp)
                        break;
                    }
                    ({ 23 -contains $PSItem }) {
                        $writer.WriteLine($trig_telnet)
                        break;
                    }
                    ({ 109, 110, 995 -contains $PSItem }) {
                        $writer.WriteLine($trig_pop)
                        break;
                    }
                    ({ 119 -contains $PSItem }) {
                        $writer.WriteLine($trig_nntp)
                        break;
                    }
                    ({ 137 -contains $PSItem }) {
                        $writer.WriteLine($trig_nbns)
                        break;
                    }
                    ({ 389, 636 -contains $PSItem }) {
                        $writer.WriteLine($trig_ldap)
                        break;
                    } ({ 1433 -contains $PSItem }) {
                        $writer.WriteLine($trig_mssql)
                        break;
                    }
                    ({ 162 -contains $PSItem }) {
                        $writer.WriteLine($trig_snmp)
                        break;
                    }
                 
                    ({ 123 -contains $PSItem }) {
                        $writer.WriteLine($trig_ntp)
                        break;
                    } ({ 79 -contains $PSItem }) {
                        $writer.WriteLine($trig_finger)
                        break;
                    } ({ 7, 9 -contains $PSItem }) {
                        $writer.WriteLine($trig_echo)
                        break;
                    } ({ 256 -contains $PSItem }) {
                        $writer.WriteLine($trig_fw1admin)
                        break;
                    }
                    Default {
                        $writer.WriteLine($trig_null)
                        break;
                    }
                }



                # Start-Sleep -Seconds 2
    
            }
            catch {}

            try { $rts = $reader.ReadToEnd() }
            catch {}
      
            $rts = $rts -replace '<.*?>', ''

            $rts = $rts -replace "`r`n", "<br>"
            write-host $Computername $rts

            $report = $report + "<tr><td>" + $Computername + "</td><td>" + $Item + "</td><td>Yes</td><td>" + $service + "</td><td>" + $rts + "</td></tr>" 
        
            $reader.Close()
            $writer.Close()
            $tcpConnection.Close()

        }
    }
}
$stream_reader.Close()

$report = $report + "</table>"

$message = new-object Net.Mail.MailMessage;
    
$message.From = $smtpfrom;
$message.To.Add($smtpto);
$message.Subject = $strcomputer + " Open Port Report " + (get-date) ;
$message.IsBodyHTML = $true
$message.Body = $report
    

$smtp = new-object Net.Mail.SmtpClient($smtpserver, $smtpport);
$smtp.EnableSSL = $true;
$smtp.Credentials = New-Object System.Net.NetworkCredential($sendUsername, $sendPassword);
$smtp.send($message);
write-host "Mail Sent to "  $smtpto ; 
