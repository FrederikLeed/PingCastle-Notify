Param(
    [string]$XmlFileDir = "C:\temp\pingfiles",
    [string]$Outputfile = "C:\temp\dashboard.html",
    [string]$webhookUrl = ""
)
Begin{

Function ExtractXML($xml) {
    # Initialize variables
    $contentPingCastleReportXML = $null
    $contentPingCastleReportXML = (Select-Xml -Path $xml -XPath "/HealthcheckData/RiskRules").node
    $domainName = (Select-Xml -Path $xml -XPath "/HealthcheckData/DomainFQDN").node.InnerXML
    $dateScan = [datetime](Select-Xml -Path $xml -XPath "/HealthcheckData/GenerationDate").node.InnerXML

    # Extract values from XML
    $value = $contentPingCastleReportXML.HealthcheckRiskRule | 
             Select-Object Category, Points, Rationale, RiskId

    # Ensure Points is an integer
    $value | ForEach-Object { $_.Points = [int]$_.Points }

    # Check if value is null and create a default object if needed
    if ($null -eq $value) {
        $value = New-Object psobject -Property @{
            Category = $category
            Points = 0
            DomainName = $domainName
        }
    } else {
        # Add domain name to each object in the collection
        $value | ForEach-Object { $_ | Add-Member -MemberType NoteProperty -Name "DomainName" -Value $domainName }
    }

    # Return the modified value
    return $value
}

# function to calc sum from xml
Function CaclSumGroup($a,$b,$c,$d) {
    $a1 = $a | Measure-Object -Sum Points
    $b1 = $b | Measure-Object -Sum Points
    $c1 = $c | Measure-Object -Sum Points
    $d1 = $d | Measure-Object -Sum Points
    return $a1.Sum + $b1.Sum + $c1.Sum + $d1.Sum 
}

# function to calc sum from one source
Function IsEqual($a,$b) {
    [int]$a1 = $a | Measure-Object -Sum Points | Select-Object -Expand Sum
    [int]$b1 = $b | Measure-Object -Sum Points | Select-Object -Expand Sum
    if($a1 -eq $b1) {
        return 1
    }
    return 0
}

Function CreatePingHTML {
    Param(
        [int]$All_StaleObjects_points,
        [int]$All_PrivilegedAccounts_points,
        [int]$All_Trusts_points,
        [int]$All_Anomalies_points
    )
    # Create the HTML content with proper variable integration
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Security Data Dashboard</title>
<script type="text/javascript" src="https://www.gstatic.com/charts/loader.js"></script>
<script type="text/javascript">
google.charts.load('current', {'packages':['gauge']});
google.charts.setOnLoadCallback(drawChart);

function drawChart() {
    var data = google.visualization.arrayToDataTable([
        ['Label', 'Value'],
        ['Stale', $All_StaleObjects_points],
        ['Privileged', $All_PrivilegedAccounts_points],
        ['Trusts', $All_Trusts_points],
        ['Anomalies', $All_Anomalies_points],
    ]);

    var maxValue = 1000; // This is your max value for the gauge
    var options = {
        width: 400, height: 120,
        greenFrom: 0, greenTo: maxValue * 0.33, // 33% of max
        yellowFrom: maxValue * 0.33, yellowTo: maxValue * 0.66, // 33% to 66% of max
        redFrom: maxValue * 0.66, redTo: maxValue, // 66% to 100% of max
        minorTicks: 50,
        max: maxValue
    };

    var chart = new google.visualization.Gauge(document.getElementById('chart_div'));

    chart.draw(data, options);
}
</script>
</head>
<body>
    <div id="chart_div" style="width: 800px; height: 240px;"></div>
</body>
</html>
"@

    # Replace placeholders with actual values
    $html = $html -replace '\$All_StaleObjects_points', $All_StaleObjects_points `
                   -replace '\$All_PrivilegedAccounts_points', $All_PrivilegedAccounts_points `
                   -replace '\$All_Trusts_points', $All_Trusts_points `
                   -replace '\$All_Anomalies_points', $All_Anomalies_points

    Return $html
}

Function PostToTeams {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$WebhookUrl,
        [int]$All_StaleObjects_points,
        [int]$All_PrivilegedAccounts_points,
        [int]$All_Trusts_points,
        [int]$All_Anomalies_points
    )

    # Format the message as a JSON payload
    $message = @{
        "@type" = "MessageCard"
        "@context" = "http://schema.org/extensions"
        "themeColor" = "0072C6"
        "title" = "Security Data Dashboard Update"
        "text" = "Here is the latest update on the security data points:"
        "sections" = @(
            @{
                "activityTitle" = "📊 Dashboard Metrics"
                "facts" = @(
                    @{
                        "name" = "Stale Objects"
                        "value" = $All_StaleObjects_points
                    },
                    @{
                        "name" = "Privileged Accounts"
                        "value" = $All_PrivilegedAccounts_points
                    },
                    @{
                        "name" = "Trusts"
                        "value" = $All_Trusts_points
                    },
                    @{
                        "name" = "Anomalies"
                        "value" = $All_Anomalies_points
                    }
                )
                "markdown" = $true
            }
        )
    } | ConvertTo-Json -Depth 4

    # Use Invoke-RestMethod to post the message to the Teams webhook
    Invoke-RestMethod -Uri $WebhookUrl -Method Post -ContentType "application/json" -Body $message
}


}
Process{

    $TotalAnoAnomalies = 0
    $TotalPrivilegedAccounts = 0
    $TotalStaleObjects = 0
    $TotalTrusts = 0
    $total_point = 0
    

foreach($x in (Get-ChildItem *.xml -Recurse -Path  $XmlFileDir)){

    $pingCastleReportXMLFullpath = $x.FullName
    # Get content on XML file
    try {

        $Anomalies = ExtractXML $pingCastleReportXMLFullpath | Where-Object{$_.Category -eq "Anomalies"}
        $Anomalies | foreach-object{$TotalAnoAnomalies += $_.points}

        $PrivilegedAccounts = ExtractXML $pingCastleReportXMLFullpath | Where-Object{$_.Category -eq  "PrivilegedAccounts"}
        $PrivilegedAccounts | foreach-object{$TotalPrivilegedAccounts += $_.points}

        $StaleObjects = ExtractXML $pingCastleReportXMLFullpath | Where-Object{$_.Category -eq  "StaleObjects"}
        $StaleObjects | foreach-object{$TotalStaleObjects += $_.points}

        $Trusts = ExtractXML $pingCastleReportXMLFullpath | Where-Object{$_.Category -eq  "Trusts"}
        $Trusts | foreach-object{$TotalTrusts += $_.points}

        $total_point += $TotalTrusts + $TotalStaleObjects + $TotalPrivilegedAccounts + $TotalAnomalies
        
    }
    catch {
        Write-Error -Message ("Unable to read the content of the xml file {0}" -f $pingCastleReportXMLFullpath)
    }
}

$html = CreatePingHTML -All_StaleObjects_points $TotalStaleObjects -All_PrivilegedAccounts_points $TotalPrivilegedAccounts -All_Trusts_points $TotalTrusts -All_Anomalies_points $TotalAnoAnomalies

# Save HTML content to a file
    Out-File -FilePath $Outputfile -Encoding UTF8 -InputObject $html

# You can use the Start-Process cmdlet to open the file in the default web browser
    #Start-Process "C:\temp\dashboard.html"


#    PostToTeams -WebhookUrl $webhookUrl `
#                -All_StaleObjects_points $TotalStaleObjects `
#                -All_PrivilegedAccounts_points $TotalPrivilegedAccounts `
#                -All_Trusts_points $TotalTrusts `
#                -All_Anomalies_points $TotalAnoAnomalies
    

}
End{

}