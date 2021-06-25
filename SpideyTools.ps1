Function Import-Har {
    <#
        .SYNOPSIS
            Import an HAR for analysis.

        .EXAMPLE
            Import-Har ./testsite.har

    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline=$true, Position=0)]
        [ValidateScript({Test-Path $_ })]
        [string]
        $HAR
    )
    process {
        Write-Host -F Y "Importing the HAR JSON Object..."
        $Global:ParsedHAR = (Get-Content $HAR) | ConvertFrom-Json
    }
    end {
        Write-Host -F Green "Done!"
    }
}


Function Get-Links {
    <#
        .SYNOPSIS
            Analyze web pages for links.

        .EXAMPLE
            Get-Links

        .EXAMPLE
            Invoke-WebRequest https://hackerob.com | Get-Links

    #>
    [CmdletBinding()]
    param(
        # ResponseData by default is all the responses found in the parsed HAR file.
        # You can actually give it any web response and it will pull out the links for you.
        [Parameter(Mandatory = $false, ValueFromPipeline=$true, Position=0)]
        $ResponseData = $Global:ParsedHAR.log.entries.response.content
    )
    process {
        $Global:links = [System.Collections.ArrayList]@()
        $Global:links += Get-HREFLinks $ResponseData
        $Global:links += Get-JSLinks $ResponseData
        $Global:links += Get-HTTPLinks $ResponseData
        $Global:links | Sort-Object -u
    }
}


Function Get-HREFLinks {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false, ValueFromPipeline=$true, Position=0)]
        $ResponseData = $Global:ParsedHAR.log.entries.response.content
    )
    process {
    #href=*
    $HrefRegex1 = "href=(\\`"|`"|')(.*?)(\\`"|`"|')"
    $ResponseData | Select-String -Pattern $HrefRegex1 -allmatches | 
        ForEach-Object { $_.matches.value } | Select-String -Pattern $HrefRegex1 | 
        ForEach-Object { $_.matches.groups[2].value } | Sort-Object -u
    #href","
    $HrefRegex2 = "href`"(,|: )`"(.*?)`""
    $ResponseData | Select-String -Pattern $HrefRegex2 -allmatches |
        ForEach-Object { $_.matches.value } | Select-String -Pattern $HrefRegex2 |
        ForEach-Object { $_.matches.groups[2].value } | Sort-Object -u
    }
}


Function Get-JSLinks {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false, ValueFromPipeline=$true, Position=0)]
        $ResponseData = $Global:ParsedHAR.log.entries.response.content
    )
    process {
        $JSRegex = "`"(\.?/[a-zA-Z0-9?=./-]*)`""
        $ResponseData | Select-String -pattern  $JSRegex -allmatches | 
            ForEach-Object { $_.matches.value} | Select-String -Pattern $JSRegex | 
            ForEach-Object { $_.matches.groups[1].value } | Sort-Object -u
    }
}


Function Get-HTTPLinks {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false, ValueFromPipeline=$true, Position=0)]
        $ResponseData = $Global:ParsedHAR.log.entries.response.content
    )
    process {
        $HTTPRegex = "(http:\/\/www\.|https:\/\/www\.|http:\/\/|https:\/\/)[^'`"()<>\s\n]*"
        $ResponseData | Select-String $HTTPRegex -allmatches | 
            ForEach-Object { $_.matches.value} | Sort-Object -u
    }
}


Function Save-AttackSurface {
    <#
        .SYNOPSIS
            Saves information on the different web pages including URL, Parameters, and Cookies to a CSV file.

        .EXAMPLE
            Save-AttackSurface

    #>
    [CmdletBinding()]
    param ()
    process {
        $Method = @{Name="Method"; Expression={$_.request.method}}
        $Response = @{Name="Response"; Expression={$_.response.status}}
        $URL = @{Name="URL"; Expression={$_.request.url.split("?")[0]}}
        $Parameters =  @{Name="Parameters"; Expression={$_.request.url.split("?")[1]}}
        $NumberofCookies = @{Name="Number of Request Cookies"; Expression={$_.request.cookies.count}}
    
        $Global:ParsedHAR.log.entries |  Where-Object {$_.response.status -ne 404} |
            Select-Object $Method, $Response, $URL, $Parameters, $NumberofCookies |
            Sort-Object -Property Paramaters, URL, Response, Method -u |
            Export-CSV -Path attacksurface.csv -NoTypeInformation
    }
}
