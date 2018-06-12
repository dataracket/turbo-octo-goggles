Get-Clipboard -Format Text > C:\test.txt
Get-Content -Path C:\test.txt | Where-Object {$_ -like '*text file*'}