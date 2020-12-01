
function ReplaceLast {
    param(
        [String] $InputString, 
        [String] $OldValue, 
        [String] $NewValue
    )
    if($InputString.Length -eq 0 -or $OldValue.Length -eq 0 -or $NewValue.Length -eq 0 -or $InputString.LastIndexOf($OldValue) -lt 0) {
        return $InputString
    }
    return -Join @($InputString.Substring(0, $InputString.LastIndexOf($OldValue)), $NewValue, $InputString.Substring($InputString.LastIndexOf($OldValue)+$OldValue.Length))
}

$VowelMatchEvaluator = {
    param (
        [System.Text.RegularExpressions.Match] $MatchObject
    )
    if([char]::IsUpper($MatchObject.Groups['nValue'].Value)) {
        if([char]::IsUpper($MatchObject.Groups['vowel'].Value)) {
            return "{0}Y{1}" -F $MatchObject.Groups['nValue'].Value, $MatchObject.Groups['vowel'].Value
        }
    }
    "{0}y{1}" -F $MatchObject.Groups['nValue'].Value, $MatchObject.Groups['vowel'].Value
}

$RepeatedVowelEvaluator = {
    param (
        [System.Text.RegularExpressions.Match] $MatchObject
    )
    if($MatchObject.Groups['vowelString'].Value.Length -gt 1) {
        $TargetVowel = $MatchObject.Groups['vowelString'].Value[0].ToString()
        GetRandomString -StringParts @($TargetVowel.ToUpper(), $TargetVowel.ToUpper(), $TargetVowel.ToUpper(), $TargetVowel.ToLower()) -Min $MatchObject.Groups['vowelString'].Value.Length -Max ($MatchObject.Groups['vowelString'].Value.Length + 12)
    }
    else {
        $MatchObject.Groups['vowelString'].Value
    }
}

$PunctuationEvaluator = {
    param (
        [System.Text.RegularExpressions.Match] $MatchObject
    )
    $TargetValue = $MatchObject.Groups['matchString'].Value[0].ToString()
    if($TargetValue -eq ".") {
        GetRandomString -StringParts @($TargetValue) -Min 1 -Max 5
    }
    elseif($TargetValue -eq "!") {
        $Parts = @("?", "1")
        1..(Get-Random -Minimum 5 -Maximum 10) | %{$Parts += "!"}
        GetRandomString -StringParts $Parts -Min 1 -Max $Parts.Count -DependentSelection
    }
    elseif($TargetValue -eq "?") {
        $Parts = @("!", "!")
        1..(Get-Random -Minimum 5 -Maximum 10) | %{$Parts += "?"}
        GetRandomString -StringParts $Parts -Min 1 -Max $Parts.Count -DependentSelection
    }
    else {
        $TargetValue
    }
}

function GetFlavorText {
    $Flavors = @("*bites lip*", "*clears throat*", "*drools all over your cawk*", "*eyes roll back and goes balls deep*", 
        "*kisses and lickies your neck*", "*licks balls*", "*licks lips*", "*licks pre off your cock*", "*licks shaft*", 
        "*looks shocked*", "*loves your salty taste*", "*notices you have a bulge*", "*notices your bulge*", "*nuzzles*", 
        "*nuzzles your necky wecky*", "*pounces on you*", "*puts paws on your chest*", "*rubbies more on your bulgy wolgy*", 
        "*rubbies your bulgy wolgy*", "*rubs your chest*", "*runs paws down your chest and bites lip*", "*runs paws through hair*", 
        "*nuzzle wuzzle*", "*paws on your bulge as I lick my lips*", "*puts snout on balls and inhales deeply*", "*sexual things*", 
        "*sniffs feet*", "*squirms*", "*squirms more and wiggles butt*", "*starts getting hot*", "*starts taking off pants*", 
        "*suckles on your tip*", "*sweating profusely*", "*unbuttons your pants as my eyes glow*", "*unzips pants*", 
        "*wags tails*", "*wiggles butt*", "*wiggles butt and squirms*", "daddy likes ;)", "hehe ;)", "~murr~", "nyea~", 
        "Rawr X3", "~rawr~", "~yiff~", "*purs*", "~huff~", "~woof~", "~bark~", "~whine~", "*whines*")
    return Get-Random -InputObject $Flavors
}

function GetRandomString {
    param (
        [System.Array] $StringParts,
        [int] $Min = 0,
        [int] $Max = 0,
        [Switch] $DependentSelection = $false
    )
    if($StringParts.Count -eq 0) { 
        return "" 
    }
    if($Max -le 0) { 
        $Max = $StringParts.Count 
    }
    if($DependentSelection -eq $true -and $Max -gt $StringParts.Count) { 
        $Max = $StringParts.Count 
    }
    if($Min -lt 0 -or $Min -gt $Max) { 
        $Min = 0 
    }
    
    $Operations = (Get-Random -Minimum $Min -Maximum ($Max+1))
    
    if($Operations -lt 1) {
        return ""
    }
    if($DependentSelection -eq $true) {
        return (-Join (Get-Random -InputObject $StringParts -Count $Operations))
    }
    else {
        return (-Join (0..($Operations-1) | %{ Get-Random -InputObject $StringParts }))
    }
}

function RandomInsert {
    param(
        [String] $InputString,
        [System.Array] $InsertionCandidates = @(),
        [int] $MinInsertions = 0,
        [int] $MaxInsertions = 0,
        [Switch] $RandomCaseFlip = $false,
        [Switch] $PreserveCase = $false,
        [Switch] $RandomPunct = $false
    )

    if($InputString.Length -eq 0) { return $InputString }
    if($MaxInsertions -lt 0) { $MaxInsertions = $InputString.Length }
    if($MinInsertions -lt 0 -or $MinInsertions -gt $MaxInsertions) { $MinInsertions = 0 }
    if($InsertionCandidates.Count -eq 0) { 
        $InsertionCandidates = ($InputString.ToCharArray() | %{ if([char]::IsLetter($_)){$_.ToString()}} | Sort-Object -CaseSensitive -Property @{Expression={$_.Trim()}} -Unique) 
    }
    $Operations = $MinInsertions
    if($MinInsertions -ne $MaxInsertions) { 
        $Operations = Get-Random -Minimum $MinInsertions -Maximum $MaxInsertions 
    }
    
    For($i = 0; $i -lt $Operations; $i++) {
        $InsertionTarget = (Get-Random -Minimum 0 -Maximum $InputString.Length)    
        $InsertionCandidate = (Get-Random -InputObject $InsertionCandidates)
        if($PreserveCase -eq $true) {
            $SourceIndex = $InsertionTarget - 1; if ($SourceIndex -lt 0) { $SourceIndex = 0 }
            if([char]::IsUpper($InputString[$SourceIndex])) {
                $InsertionCandidate = $InsertionCandidate.ToUpper()
            }
            else {
                $InsertionCandidate = $InsertionCandidate.ToLower()
            }
        }
        $InputString = $InputString.Insert($InsertionTarget, $InsertionCandidate)
    }
    return $InputString
}

function Get-RetardText {
<#
.SYNOPSIS
    You're a fucking retard.
#>
    [CmdletBinding()]
    param( 
        [String] $InputString = "Quit being a retard."
    )
    return (-join($InputString.ToCharArray()|%{if(($i=!$i)){"$_".toupper()}else{"$_".tolower()}}))
}

function Get-OwoText {
<#
.SYNOPSIS
    You're a fucking degenerate.
#>
    param(
        [String] $InputString,
        [Switch] $Cocaine = $false,
        [Switch] $Confused = $false,
        [Switch] $Flavor = $false,
        [Switch] $Furry = $false
    )

    $Emoji = @(";;w;;", "^w^", ">w<", "UwU", "uwu", "0w0", "owo", "OvO", "-_-", "0_o", "XD", "X3", "<3", "๏w๏", ".///.", "o3o", "(・`ω´・)", "(´・ω・`)")
    $vowels = @('a', 'e', 'i', 'o', 'u', 'A', 'E', 'I', 'O', 'U')
    $InputString = $InputString.Replace('LL', 'W').Replace('ll', 'w').Replace('Ll', 'W').Replace('lL', 'w')

    if($Furry -eq $true) {
        $InputString = $InputString.Replace("my", "mwy").Replace("to", "tuwu").Replace("had", "hawd").Replace("you", "yuw").Replace("go", "gow").Replace("and", "awnd").Replace("have", "haw").Replace("es ", "ies ")
    }

    $InputString = $InputString.Replace('L', 'W').Replace('l', 'w').Replace('R', 'W').Replace('r', 'w')
    $InputString = ReplaceLast -InputString $InputString -OldValue '!' -NewValue ('! {0}' -F (Get-Random -InputObject $Emoji))
    $InputString = ReplaceLast -InputString $InputString -OldValue '?' -NewValue '? owo'
    $InputString = ReplaceLast -InputString $InputString -OldValue '.' -NewValue ('. {0}' -F (Get-Random -InputObject $Emoji))
    $InputString = [Regex]::new("(?<nValue>[nN])(?<vowel>[aeiouAEIOU])").Replace($InputString, $VowelMatchEvaluator)

    if($Cocaine -eq $true) {
        $InputString = [Regex]::new("(?<vowelString>([AEIOUY])\1{2,})", [System.Text.RegularExpressions.RegexOptions]::IgnoreCase).Replace($InputString, $RepeatedVowelEvaluator)
    }

    if($Confused -eq $true) {
        $InputString = [Regex]::new("(?<matchString>[\.!?])").Replace($InputString, $PunctuationEvaluator)
    }

    if($Flavor -eq $true) {
        $InputString = "{0} {1}" -F $InputString.Trim(), (GetFlavorText)
    }

    return $InputString
}

function Get-Cancer {
    param(
        $InputString
    )
    return (Get-RetardText -InputString (Get-OwoText -InputString $InputString -Furry -Cocaine -Confused -Flavor))
}

Get-Cancer -InputString "Four score and seven years ago our fathers brought forth on this continent, a new nation, conceived in Liberty, and dedicated to the proposition that all men are created equal."
