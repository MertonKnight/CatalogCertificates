$certifcateDirectoryPath = "C:\Users\Merto\Desktop\FPKI\"

$files = Get-ChildItem -Path $certifcateDirectoryPath -Recurse -File -Include *.txt,*.cer

$certInfoList = @()

foreach($file in $files)
{
    $reader = New-Object System.IO.StreamReader($file.FullName)

    $line = $reader.ReadLine()
    $reader.Close()

    if($line.Contains("-----BEGIN CERTIFICATE-----"))
    {
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($file.FullName)

        Write-Host('Subject: {0}' -f $cert.Subject);
        Write-Host('Issuer: {0}' -f $cert.Issuer);
        Write-Host('Version: {0}' -f $cert.Version);
        Write-Host('Valid Date: {0}' -f $cert.NotBefore);
        Write-Host('Expiry Date: {0}' -f $cert.NotAfter);
        Write-Host('Thumbprint: {0}' -f $cert.Thumbprint);
        Write-Host('Serial Number: {0}' -f $cert.SerialNumber);
        Write-Host('Friendly Name: {0}' -f $cert.PublicKey.Oid.FriendlyName);
        Write-Host('Public Key Format: {0}' -f $cert.PublicKey.EncodedKeyValue.Format($true));
        Write-Host('Raw Data Length: {0}' -f $cert.RawData.Length);
        Write-Host("`n");
        #Write-Host('Certificate to string: {0}' -f $cert.ToString());
        #Write-Host('Certificate to XML String: {0}', $cert.PublicKey.Key.ToXmlString($false));

        $index = $cert.Subject.IndexOf('CN=')
        if($index -eq -1)
        {
            $commonName = $cert.Subject.Split(',')[0].Substring(3)  
        }
        else 
        {
            $commonName = $cert.Subject.Split(',')[0].Substring($index + 3)
        }

        $certInfo = New-Object -TypeName psobject |
        Add-Member -MemberType NoteProperty -Name CommonName -Value ($commonName) -PassThru -Force |
        Add-Member -MemberType NoteProperty -Name Subject -Value ($cert.Subject) -PassThru -Force |
        Add-Member -MemberType NoteProperty -Name Issuer -Value ($cert.Issuer) -PassThru -Force |
        Add-Member -MemberType NoteProperty -Name SerialNumber -Value ($cert.SerialNumber) -PassThru -Force |
        Add-Member -MemberType NoteProperty -Name Startdate -Value ($cert.NotBefore) -PassThru -Force |
        Add-Member -MemberType NoteProperty -Name Enddate -Value ($cert.NotAfter) -PassThru -Force
        
        $certInfoList += $certInfo
    }
}

$certInfoList | Export-Csv -Path '.\Certificates.csv' -NoTypeInformation 