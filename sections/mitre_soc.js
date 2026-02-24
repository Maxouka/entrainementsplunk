// =============================================================================
// MITRE ATT&CK & SOC Operations - Entrainement Sopra Steria
// =============================================================================

const mitreData = {
  overview: "Le framework MITRE ATT&CK (Adversarial Tactics, Techniques, and Common Knowledge) est une base de connaissances qui catalogue les tactiques et techniques utilisees par les attaquants. Il est organise en une matrice ou chaque colonne represente une tactique (le POURQUOI) et chaque cellule contient des techniques (le COMMENT). Sopra Steria utilise ce framework comme reference centrale pour la detection, la reponse aux incidents et le threat hunting. Il permet de standardiser le langage entre equipes SOC, de mesurer la couverture de detection et d'identifier les lacunes.",

  tactics: [
    // =========================================================================
    // TA0043 - RECONNAISSANCE
    // =========================================================================
    {
      id: "TA0043",
      name: "Reconnaissance",
      description: "L'adversaire collecte des informations sur la cible avant de lancer son attaque. Cela inclut la recherche d'informations techniques (IP, domaines, services exposes) et organisationnelles (employes, structure, technologies utilisees).",
      techniques: [
        {
          id: "T1595",
          name: "Active Scanning",
          description: "L'attaquant scanne activement l'infrastructure de la cible pour identifier les hotes, ports ouverts et services vulnerables. Utilisation d'outils comme Nmap, Masscan ou Shodan.",
          detection: "Surveiller les pics de connexions depuis une meme IP vers de nombreux ports ou hotes. Analyser les logs firewall et IDS pour des patterns de scan (SYN scan, scan sequentiel de ports).",
          splunkQuery: "index=firewall action=blocked OR action=denied | stats count by src_ip dest_port | where count > 50 | sort -count"
        },
        {
          id: "T1598",
          name: "Phishing for Information",
          description: "L'attaquant envoie des emails de phishing pour collecter des informations sensibles (identifiants, informations internes) sans necessairement livrer de malware. Spear-phishing cible avec pretexte credible.",
          detection: "Analyser les emails entrants pour des domaines suspects, liens vers des pages de credential harvesting. Surveiller les soumissions de formulaires vers des domaines externes recemment crees.",
          splunkQuery: "index=email sourcetype=exchange OR sourcetype=o365 | where match(sender_domain, \".*\\.(tk|ml|ga|cf|gq)$\") OR (url_domain!=recipient_domain AND url_category=\"newly_registered\") | table _time sender recipient subject url_domain"
        },
        {
          id: "T1592",
          name: "Gather Victim Host Information",
          description: "L'attaquant collecte des informations sur les configurations des hotes de la victime : materiel, logiciels installes, versions d'OS, correctifs appliques.",
          detection: "Difficile a detecter car souvent passif. Surveiller les requetes inhabituelles vers les serveurs web revelant des informations systeme (headers, pages d'erreur).",
          splunkQuery: "index=web sourcetype=access_combined | where status>=400 | stats count by src_ip uri_path status | where count > 20"
        },
        {
          id: "T1589",
          name: "Gather Victim Identity Information",
          description: "Collecte d'identifiants, adresses email, noms d'employes via LinkedIn, sites web de l'entreprise, fuites de donnees publiques.",
          detection: "Surveiller les tentatives d'enumeration d'utilisateurs (requetes LDAP excessives, tentatives de login avec des listes d'emails). Alerter sur l'utilisation de credentials provenant de fuites connues.",
          splunkQuery: "index=windows sourcetype=WinEventLog:Security EventCode=4625 | stats dc(TargetUserName) as unique_users count by src_ip | where unique_users > 10"
        }
      ]
    },

    // =========================================================================
    // TA0042 - RESOURCE DEVELOPMENT
    // =========================================================================
    {
      id: "TA0042",
      name: "Resource Development",
      description: "L'adversaire cree, achete ou compromet des ressources pour supporter ses operations : infrastructure (serveurs C2, domaines), comptes, outils et capacites offensives.",
      techniques: [
        {
          id: "T1583",
          name: "Acquire Infrastructure",
          description: "L'attaquant achete ou loue des serveurs, domaines, services cloud pour heberger son infrastructure d'attaque. Utilisation de VPS, domaines ressemblant a des domaines legitimes (typosquatting).",
          detection: "Surveiller les connexions vers des domaines recemment enregistres (< 30 jours). Utiliser des feeds de Threat Intelligence pour identifier les infrastructures malveillantes connues.",
          splunkQuery: "index=proxy OR index=dns | lookup domain_age_lookup domain AS dest_domain OUTPUT domain_age | where domain_age < 30 | stats count by dest_domain domain_age src_ip"
        },
        {
          id: "T1588",
          name: "Obtain Capabilities",
          description: "L'attaquant acquiert des outils offensifs : malwares, exploits, certificats numeriques voles. Peut inclure l'achat sur des marches noirs ou le developpement interne.",
          detection: "Surveiller les indicateurs de compromission (IOC) associes a des outils connus (Cobalt Strike, Mimikatz). Utiliser les signatures YARA et les feeds de threat intelligence.",
          splunkQuery: "index=endpoint sourcetype=sysmon EventCode=1 | lookup threat_intel_lookup hash AS Hashes OUTPUT threat_name | where isnotnull(threat_name) | table _time host CommandLine threat_name"
        },
        {
          id: "T1584",
          name: "Compromise Infrastructure",
          description: "L'attaquant compromet l'infrastructure de tiers pour l'utiliser dans ses operations, rendant l'attribution plus difficile et contournant les listes de blocage.",
          detection: "Surveiller les communications vers des sites legitimes mais compromis utilises comme relais C2. Analyser les patterns de trafic inhabituels vers des sites normalement peu visites.",
          splunkQuery: "index=proxy | stats count avg(bytes_out) by dest_domain src_ip | where count > 100 AND avg(bytes_out) > 1000 | lookup alexa_top1m domain AS dest_domain OUTPUT rank | where rank > 100000 OR isnull(rank)"
        }
      ]
    },

    // =========================================================================
    // TA0001 - INITIAL ACCESS
    // =========================================================================
    {
      id: "TA0001",
      name: "Initial Access",
      description: "L'adversaire tente d'obtenir un premier acces au reseau de la victime. Les vecteurs les plus courants sont le phishing, l'exploitation de services exposes et les comptes valides compromis.",
      techniques: [
        {
          id: "T1566",
          name: "Phishing",
          description: "Envoi d'emails avec des pieces jointes malveillantes (T1566.001) ou des liens vers des sites malveillants (T1566.002). Vecteur d'attaque le plus courant, represente plus de 80% des incidents initiaux.",
          detection: "Analyser les pieces jointes (macros, executables deguises). Surveiller les clics sur des URLs suspectes. Verifier les expediteurs avec SPF/DKIM/DMARC. Alerter sur les fichiers Office avec macros.",
          splunkQuery: "index=email | where (attachment_type=\".docm\" OR attachment_type=\".xlsm\" OR attachment_type=\".exe\" OR attachment_type=\".js\" OR attachment_type=\".vbs\" OR attachment_type=\".ps1\") | table _time sender recipient subject attachment_name attachment_type"
        },
        {
          id: "T1190",
          name: "Exploit Public-Facing Application",
          description: "Exploitation de vulnerabilites dans des applications accessibles depuis Internet : serveurs web, VPN, passerelles email. Exemples : Log4Shell, ProxyLogon, vulnerabilites Exchange.",
          detection: "Surveiller les logs applicatifs pour des patterns d'exploitation connus. Analyser les requetes web anormales (injections SQL, traversees de repertoires). Correler avec les scans de vulnerabilites.",
          splunkQuery: "index=web sourcetype=access_combined | where match(uri_path, \"(?i)(\\.\\.[\\/\\\\]|union.*select|<script|eval\\(|exec\\()\") | stats count by src_ip uri_path status | where count > 5"
        },
        {
          id: "T1078",
          name: "Valid Accounts",
          description: "Utilisation de comptes legitimes compromis (achetes sur le dark web, obtenus par phishing ou credential stuffing). Tres difficile a detecter car le comportement semble legitime.",
          detection: "Detecter les connexions depuis des localisations inhabituelles (impossible travel). Surveiller les horaires de connexion anormaux. Alerter sur les changements de pattern d'authentification.",
          splunkQuery: "index=windows sourcetype=WinEventLog:Security EventCode=4624 | iplocation src_ip | stats values(Country) as countries dc(Country) as country_count by TargetUserName | where country_count > 1"
        },
        {
          id: "T1133",
          name: "External Remote Services",
          description: "Utilisation de services d'acces distant legitimes (VPN, RDP, Citrix) avec des identifiants voles pour acceder au reseau interne.",
          detection: "Surveiller les connexions VPN/RDP depuis des IP ou pays inhabituels. Alerter sur les connexions en dehors des heures de travail. Verifier les authentifications multiples depuis des IP differentes.",
          splunkQuery: "index=vpn OR index=remote_access | stats count values(src_ip) as ips dc(src_ip) as ip_count by user | where ip_count > 3 | table user ips ip_count"
        },
        {
          id: "T1195",
          name: "Supply Chain Compromise",
          description: "Compromission de la chaine d'approvisionnement logicielle : modification de mises a jour legitimes (ex: SolarWinds), compromission de bibliotheques open source.",
          detection: "Verifier l'integrite des mises a jour (hashes, signatures). Surveiller les comportements anormaux apres les mises a jour logicielles. Maintenir un inventaire des composants logiciels (SBOM).",
          splunkQuery: "index=endpoint sourcetype=sysmon EventCode=1 | where (ParentImage LIKE \"%update%\" OR ParentImage LIKE \"%installer%\") AND (Image LIKE \"%cmd.exe\" OR Image LIKE \"%powershell.exe\") | table _time host ParentImage Image CommandLine"
        }
      ]
    },

    // =========================================================================
    // TA0002 - EXECUTION
    // =========================================================================
    {
      id: "TA0002",
      name: "Execution",
      description: "L'adversaire tente d'executer du code malveillant sur le systeme cible. Cela peut inclure l'execution de scripts, l'exploitation de fonctionnalites legitimes du systeme (Living off the Land) ou l'execution de binaires malveillants.",
      techniques: [
        {
          id: "T1059",
          name: "Command and Scripting Interpreter",
          description: "Utilisation d'interpreteurs de commandes (cmd, PowerShell, bash, Python, VBScript) pour executer des commandes ou scripts malveillants. PowerShell est le plus utilise sur Windows.",
          detection: "Surveiller les executions PowerShell avec encodage base64 (-EncodedCommand). Alerter sur les scripts telecharges et executes (Invoke-Expression, IEX). Logger les commandes via ScriptBlock Logging.",
          splunkQuery: "index=windows sourcetype=WinEventLog:Microsoft-Windows-PowerShell/Operational EventCode=4104 | where match(ScriptBlockText, \"(?i)(invoke-expression|iex|downloadstring|downloadfile|encodedcommand|frombase64|bypass)\") | table _time host ScriptBlockText"
        },
        {
          id: "T1204",
          name: "User Execution",
          description: "L'attaquant compte sur l'utilisateur pour executer le code malveillant : ouverture d'une piece jointe, clic sur un lien, activation de macros dans un document Office.",
          detection: "Surveiller les processus enfants suspects de Word, Excel, Outlook (cmd.exe, powershell.exe, wscript.exe). Alerter sur l'activation de macros dans des documents provenant d'Internet.",
          splunkQuery: "index=endpoint sourcetype=sysmon EventCode=1 | where (ParentImage LIKE \"%WINWORD.EXE\" OR ParentImage LIKE \"%EXCEL.EXE\" OR ParentImage LIKE \"%OUTLOOK.EXE\") AND (Image LIKE \"%cmd.exe\" OR Image LIKE \"%powershell.exe\" OR Image LIKE \"%wscript.exe\" OR Image LIKE \"%cscript.exe\") | table _time host ParentImage Image CommandLine User"
        },
        {
          id: "T1053",
          name: "Scheduled Task/Job",
          description: "Creation de taches planifiees (schtasks, cron, at) pour executer du code de maniere persistante ou a des moments specifiques.",
          detection: "Surveiller la creation de nouvelles taches planifiees (Event ID 4698). Alerter sur les taches creees par des processus inhabituels ou executant des scripts suspects.",
          splunkQuery: "index=windows sourcetype=WinEventLog:Security EventCode=4698 | rex field=TaskContent \"<Command>(?<command>[^<]+)</Command>\" | where match(command, \"(?i)(powershell|cmd|wscript|cscript|mshta|rundll32)\") | table _time host SubjectUserName TaskName command"
        },
        {
          id: "T1047",
          name: "Windows Management Instrumentation (WMI)",
          description: "Utilisation de WMI pour executer du code a distance ou localement. WMI permet l'execution de commandes, la collecte d'informations et la persistance.",
          detection: "Surveiller les executions de wmiprvse.exe avec des processus enfants suspects. Alerter sur les connexions WMI distantes (Event ID 4648 avec processus WMI).",
          splunkQuery: "index=endpoint sourcetype=sysmon EventCode=1 | where ParentImage LIKE \"%WmiPrvSE.exe\" AND (Image LIKE \"%cmd.exe\" OR Image LIKE \"%powershell.exe\") | table _time host Image CommandLine User"
        }
      ]
    },

    // =========================================================================
    // TA0003 - PERSISTENCE
    // =========================================================================
    {
      id: "TA0003",
      name: "Persistence",
      description: "L'adversaire cherche a maintenir son acces au systeme compromis meme apres un redemarrage ou un changement de mot de passe. Il installe des mecanismes de persistance discrets.",
      techniques: [
        {
          id: "T1547",
          name: "Boot or Logon Autostart Execution",
          description: "Ajout d'entrees dans les cles de registre Run/RunOnce, dossier Startup, ou modification de programmes de demarrage pour executer du code automatiquement au demarrage ou a la connexion.",
          detection: "Surveiller les modifications des cles de registre Run (Sysmon Event ID 13). Alerter sur les nouveaux fichiers dans les dossiers Startup. Comparer avec une baseline connue.",
          splunkQuery: "index=endpoint sourcetype=sysmon EventCode=13 | where match(TargetObject, \"(?i)(Run|RunOnce|Explorer\\\\Shell Folders|Winlogon)\") | table _time host Image TargetObject Details"
        },
        {
          id: "T1136",
          name: "Create Account",
          description: "Creation de nouveaux comptes locaux ou de domaine pour maintenir l'acces. Les comptes peuvent etre crees avec des noms ressemblant a des comptes de service legitimes.",
          detection: "Surveiller la creation de comptes (Event ID 4720). Alerter sur les comptes crees en dehors des processus standard de provisioning. Verifier les ajouts aux groupes privilegies.",
          splunkQuery: "index=windows sourcetype=WinEventLog:Security (EventCode=4720 OR EventCode=4722 OR EventCode=4728 OR EventCode=4732) | table _time host EventCode SubjectUserName TargetUserName GroupName"
        },
        {
          id: "T1543",
          name: "Create or Modify System Process",
          description: "Creation ou modification de services Windows pour executer du code malveillant avec des privileges eleves. Les services demarrent automatiquement et tournent en arriere-plan.",
          detection: "Surveiller la creation de nouveaux services (Event ID 7045). Alerter sur les services executant des binaires depuis des emplacements inhabituels (Temp, AppData, dossiers utilisateurs).",
          splunkQuery: "index=windows sourcetype=WinEventLog:System EventCode=7045 | where NOT match(ImagePath, \"(?i)(C:\\\\Windows|C:\\\\Program Files)\") | table _time host ServiceName ImagePath ServiceType StartType AccountName"
        },
        {
          id: "T1053",
          name: "Scheduled Task/Job (Persistence)",
          description: "Utilisation de taches planifiees comme mecanisme de persistance pour re-executer du code malveillant a intervalles reguliers ou au demarrage.",
          detection: "Surveiller les taches planifiees creees par des processus non standards. Alerter sur les taches avec des declencheurs au boot ou a intervalle court executant des scripts.",
          splunkQuery: "index=windows sourcetype=WinEventLog:Security EventCode=4698 | rex field=TaskContent \"<LogonTrigger>\" | rex field=TaskContent \"<BootTrigger>\" | table _time host SubjectUserName TaskName TaskContent"
        },
        {
          id: "T1546",
          name: "Event Triggered Execution",
          description: "Configuration de declencheurs evenementiels (WMI subscriptions, AppInit DLLs, fichiers .lnk modifies) pour executer du code lors d'evenements systeme specifiques.",
          detection: "Surveiller la creation de WMI Event Subscriptions (Sysmon Event ID 19-21). Alerter sur les modifications de AppInit_DLLs. Verifier les associations de fichiers modifiees.",
          splunkQuery: "index=endpoint sourcetype=sysmon (EventCode=19 OR EventCode=20 OR EventCode=21) | table _time host EventCode Operation Consumer Filter QueryLanguage Query"
        }
      ]
    },

    // =========================================================================
    // TA0004 - PRIVILEGE ESCALATION
    // =========================================================================
    {
      id: "TA0004",
      name: "Privilege Escalation",
      description: "L'adversaire tente d'obtenir des privileges plus eleves sur un systeme ou un reseau. Les techniques incluent l'exploitation de vulnerabilites, la manipulation de tokens d'acces et l'abus de configurations faibles.",
      techniques: [
        {
          id: "T1068",
          name: "Exploitation for Privilege Escalation",
          description: "Exploitation de vulnerabilites logicielles pour obtenir des privileges eleves. Cible souvent le noyau OS, les drivers ou les services privilegies.",
          detection: "Surveiller les crashes de processus privilegies. Alerter sur les processus utilisateur qui obtiennent soudainement des privileges SYSTEM. Maintenir les systemes a jour.",
          splunkQuery: "index=windows sourcetype=WinEventLog:Security EventCode=4672 | where SubjectUserName!=\"SYSTEM\" AND SubjectUserName!=\"LOCAL SERVICE\" AND SubjectUserName!=\"NETWORK SERVICE\" | stats count by SubjectUserName PrivilegeList host | where count > 5"
        },
        {
          id: "T1134",
          name: "Access Token Manipulation",
          description: "Manipulation de tokens d'acces Windows pour usurper l'identite d'un autre utilisateur ou obtenir des privileges eleves. Inclut la creation de tokens, le vol et l'impersonation.",
          detection: "Surveiller les appels API suspects (DuplicateToken, ImpersonateLoggedOnUser). Alerter sur les processus qui changent de contexte de securite de maniere inattendue.",
          splunkQuery: "index=endpoint sourcetype=sysmon EventCode=1 | where match(CommandLine, \"(?i)(token|impersonate|runas|privilege)\") | table _time host User Image CommandLine"
        },
        {
          id: "T1548",
          name: "Abuse Elevation Control Mechanism",
          description: "Contournement des mecanismes de controle d'elevation de privileges comme UAC (User Account Control) sous Windows ou sudo sous Linux.",
          detection: "Surveiller les tentatives de bypass UAC connues (eventtriggered, fodhelper, sdclt). Alerter sur les utilisations inhabituelles de sudo ou su.",
          splunkQuery: "index=endpoint sourcetype=sysmon EventCode=1 | where match(Image, \"(?i)(fodhelper|sdclt|eventvwr|computerdefaults)\\.exe\") AND IntegrityLevel=\"High\" | table _time host User Image CommandLine ParentImage"
        },
        {
          id: "T1078",
          name: "Valid Accounts (Privilege Escalation)",
          description: "Utilisation de comptes privilegies valides (comptes admin, comptes de service) obtenus via credential dumping ou social engineering.",
          detection: "Surveiller l'utilisation de comptes privilegies depuis des postes inhabituels. Alerter sur les connexions interactives avec des comptes de service.",
          splunkQuery: "index=windows sourcetype=WinEventLog:Security EventCode=4624 LogonType=10 | where match(TargetUserName, \"(?i)(admin|svc_|service)\") | stats count by TargetUserName src_ip host | table TargetUserName src_ip host count"
        }
      ]
    },

    // =========================================================================
    // TA0005 - DEFENSE EVASION
    // =========================================================================
    {
      id: "TA0005",
      name: "Defense Evasion",
      description: "L'adversaire tente d'eviter la detection par les outils de securite. C'est la tactique avec le plus de techniques car les attaquants investissent beaucoup d'efforts pour rester caches.",
      techniques: [
        {
          id: "T1070",
          name: "Indicator Removal",
          description: "Suppression des traces d'activite : nettoyage des logs, suppression de fichiers, effacement de l'historique de commandes. Event ID 1102 indique un effacement du journal de securite.",
          detection: "Alerter immediatement sur l'effacement des journaux de securite (1102). Surveiller la suppression de fichiers dans les dossiers temporaires. Centraliser les logs pour prevenir la suppression locale.",
          splunkQuery: "index=windows sourcetype=WinEventLog:Security EventCode=1102 | append [search index=windows sourcetype=WinEventLog:System EventCode=104] | table _time host EventCode SubjectUserName Message"
        },
        {
          id: "T1055",
          name: "Process Injection",
          description: "Injection de code dans un processus legitime pour eviter la detection et heriter de ses privileges. Techniques : DLL injection, process hollowing, thread hijacking.",
          detection: "Surveiller les appels API d'injection (CreateRemoteThread - Sysmon Event ID 8). Alerter sur les processus avec des DLLs chargees depuis des emplacements inhabituels.",
          splunkQuery: "index=endpoint sourcetype=sysmon EventCode=8 | where SourceImage!=TargetImage | lookup legitimate_injection_lookup SourceImage TargetImage OUTPUT is_legitimate | where is_legitimate!=\"true\" | table _time host SourceImage TargetImage StartFunction"
        },
        {
          id: "T1027",
          name: "Obfuscated Files or Information",
          description: "Obfuscation du code malveillant : encodage base64, chiffrement, compression, obfuscation de scripts PowerShell, packing de binaires.",
          detection: "Detecter les commandes PowerShell encodees en base64. Alerter sur les scripts avec un haut niveau d'entropie. Surveiller les decodages en memoire.",
          splunkQuery: "index=windows sourcetype=WinEventLog:Microsoft-Windows-PowerShell/Operational EventCode=4104 | where match(ScriptBlockText, \"(?i)(frombase64string|convert|decompress|gunzip|invoke-obfuscation)\") OR len(ScriptBlockText) > 5000 | table _time host ScriptBlockText"
        },
        {
          id: "T1036",
          name: "Masquerading",
          description: "Deguisement de fichiers ou processus malveillants en leur donnant des noms ou emplacements de fichiers legitimes (svchost.exe dans un mauvais dossier, extension double).",
          detection: "Verifier que les processus systeme s'executent depuis les bons repertoires. Alerter sur svchost.exe, lsass.exe, csrss.exe lances depuis un chemin autre que System32.",
          splunkQuery: "index=endpoint sourcetype=sysmon EventCode=1 | where (Image LIKE \"%svchost.exe\" OR Image LIKE \"%lsass.exe\" OR Image LIKE \"%csrss.exe\" OR Image LIKE \"%services.exe\") AND NOT match(Image, \"(?i)C:\\\\Windows\\\\System32\\\\\") | table _time host Image CommandLine User"
        },
        {
          id: "T1562",
          name: "Impair Defenses",
          description: "Desactivation ou modification des outils de securite : arret de l'antivirus, desactivation du firewall, modification des regles de detection, tampering avec les agents EDR.",
          detection: "Surveiller l'arret des services de securite. Alerter sur la modification des regles de firewall. Detecter la desactivation de Windows Defender ou d'autres AV.",
          splunkQuery: "index=endpoint sourcetype=sysmon EventCode=1 | where match(CommandLine, \"(?i)(disable|stop|uninstall|remove).*(defender|firewall|antivirus|security|tamper)\") OR match(Image, \"(?i)(net\\.exe|sc\\.exe|taskkill\\.exe)\") | table _time host User Image CommandLine"
        }
      ]
    },

    // =========================================================================
    // TA0006 - CREDENTIAL ACCESS
    // =========================================================================
    {
      id: "TA0006",
      name: "Credential Access",
      description: "L'adversaire tente de voler des identifiants (mots de passe, hashes, tickets Kerberos, tokens). Ces identifiants permettent de se deplacer lateralement et d'elever les privileges.",
      techniques: [
        {
          id: "T1110",
          name: "Brute Force",
          description: "Tentatives repetees de deviner les mots de passe : brute force simple, password spraying (un mot de passe teste sur beaucoup de comptes), credential stuffing (identifiants voles testes).",
          detection: "Surveiller les echecs de connexion multiples (4625). Pour le password spraying, detecter un meme mot de passe tente sur de nombreux comptes. Seuils : plus de 5 echecs en 5 minutes.",
          splunkQuery: "index=windows sourcetype=WinEventLog:Security EventCode=4625 | bin _time span=5m | stats count dc(TargetUserName) as unique_users by src_ip _time | where count > 10 OR unique_users > 5 | table _time src_ip count unique_users"
        },
        {
          id: "T1003",
          name: "OS Credential Dumping",
          description: "Extraction des identifiants depuis la memoire ou les fichiers systeme : LSASS dump (Mimikatz), extraction de SAM/SYSTEM, DCSync pour recuperer les hashes du domaine AD.",
          detection: "Surveiller les acces au processus LSASS (Sysmon Event ID 10). Alerter sur l'execution de Mimikatz ou ses variantes. Detecter les requetes DCSync (replication AD inhabituelle).",
          splunkQuery: "index=endpoint sourcetype=sysmon EventCode=10 TargetImage=\"*lsass.exe\" | where GrantedAccess=\"0x1010\" OR GrantedAccess=\"0x1410\" OR GrantedAccess=\"0x1438\" | table _time host SourceImage TargetImage GrantedAccess CallTrace"
        },
        {
          id: "T1558",
          name: "Steal or Forge Kerberos Tickets",
          description: "Vol ou falsification de tickets Kerberos : Kerberoasting (demande de TGS pour extraire le hash du service), Golden Ticket (falsification de TGT), Silver Ticket.",
          detection: "Detecter les demandes excessives de TGS (Event ID 4769) avec chiffrement RC4. Surveiller les anomalies de duree de vie des tickets. Alerter sur les TGT avec une duree anormale.",
          splunkQuery: "index=windows sourcetype=WinEventLog:Security EventCode=4769 | where TicketEncryptionType=\"0x17\" | stats count by ServiceName TargetUserName src_ip | where count > 3 | table ServiceName TargetUserName src_ip count"
        },
        {
          id: "T1555",
          name: "Credentials from Password Stores",
          description: "Extraction de mots de passe stockes dans les navigateurs, gestionnaires de mots de passe, fichiers de configuration, Credential Manager Windows.",
          detection: "Surveiller l'acces aux fichiers de stockage de mots de passe des navigateurs (Login Data de Chrome). Alerter sur l'utilisation de cmdkey ou vaultcmd.",
          splunkQuery: "index=endpoint sourcetype=sysmon EventCode=1 | where match(CommandLine, \"(?i)(cmdkey|vaultcmd|credential|chrome.*login|firefox.*logins)\") OR match(Image, \"(?i)(lazagne|mimikatz|credential)\") | table _time host User Image CommandLine"
        }
      ]
    },

    // =========================================================================
    // TA0007 - DISCOVERY
    // =========================================================================
    {
      id: "TA0007",
      name: "Discovery",
      description: "L'adversaire explore l'environnement compromis pour comprendre le reseau, les systemes, les comptes et les donnees disponibles. Phase essentielle avant le mouvement lateral.",
      techniques: [
        {
          id: "T1087",
          name: "Account Discovery",
          description: "Enumeration des comptes utilisateurs locaux et de domaine via net user, Get-ADUser, LDAP queries pour identifier les cibles d'interet.",
          detection: "Surveiller les commandes d'enumeration d'utilisateurs (net user, net group). Detecter les requetes LDAP massives depuis des postes non administratifs.",
          splunkQuery: "index=endpoint sourcetype=sysmon EventCode=1 | where match(CommandLine, \"(?i)(net\\s+(user|group|localgroup)|Get-AD(User|Group|Computer)|dsquery|whoami\\s+/all)\") | table _time host User Image CommandLine"
        },
        {
          id: "T1018",
          name: "Remote System Discovery",
          description: "Decouverte des systemes distants sur le reseau via ping sweep, net view, arp scan, requetes DNS, scan de ports pour identifier les cibles de mouvement lateral.",
          detection: "Detecter les ping sweep (ICMP massifs). Surveiller les commandes net view, arp -a. Alerter sur les scans de ports internes depuis des postes utilisateurs.",
          splunkQuery: "index=endpoint sourcetype=sysmon EventCode=1 | where match(CommandLine, \"(?i)(net\\s+view|ping\\s+-n|arp\\s+-a|nbtstat|nltest|nslookup)\") | stats count by host User CommandLine | where count > 3"
        },
        {
          id: "T1083",
          name: "File and Directory Discovery",
          description: "Exploration de fichiers et repertoires pour trouver des donnees sensibles : documents, configurations, fichiers de mots de passe, scripts avec des credentials.",
          detection: "Surveiller les commandes de recherche de fichiers (dir /s, find, Get-ChildItem recursive). Alerter sur la recherche de fichiers specifiques (*.kdbx, *.pem, password*).",
          splunkQuery: "index=endpoint sourcetype=sysmon EventCode=1 | where match(CommandLine, \"(?i)(dir\\s+/s|tree\\s+/f|Get-ChildItem.*Recurse|findstr.*password|find.*\\.pem|find.*\\.kdbx)\") | table _time host User CommandLine"
        },
        {
          id: "T1069",
          name: "Permission Groups Discovery",
          description: "Enumeration des groupes de securite pour identifier les membres des groupes privilegies (Domain Admins, Enterprise Admins, administrateurs locaux).",
          detection: "Surveiller les requetes sur les groupes privilegies. Alerter sur l'enumeration des groupes Domain Admins depuis des comptes non administratifs.",
          splunkQuery: "index=endpoint sourcetype=sysmon EventCode=1 | where match(CommandLine, \"(?i)(net\\s+group.*domain\\s+admins|Get-ADGroupMember|net\\s+localgroup.*administrators)\") | table _time host User Image CommandLine"
        }
      ]
    },

    // =========================================================================
    // TA0008 - LATERAL MOVEMENT
    // =========================================================================
    {
      id: "TA0008",
      name: "Lateral Movement",
      description: "L'adversaire se deplace d'un systeme a un autre au sein du reseau compromis pour atteindre ses objectifs. Utilise les identifiants voles et les protocoles d'administration.",
      techniques: [
        {
          id: "T1021",
          name: "Remote Services",
          description: "Utilisation de services d'acces distant (RDP, SSH, SMB/Windows Admin Shares, WinRM, VNC) pour se connecter a d'autres systemes avec des identifiants compromis.",
          detection: "Surveiller les connexions RDP (4624 Type 10) entre postes de travail (rare en utilisation normale). Alerter sur les connexions SMB admin (C$, ADMIN$) depuis des postes non administratifs.",
          splunkQuery: "index=windows sourcetype=WinEventLog:Security EventCode=4624 (LogonType=10 OR LogonType=3) | where NOT match(src_ip, \"^(10\\.0\\.0|192\\.168\\.1)\\.(1|2|3)$\") | stats count by TargetUserName src_ip host LogonType | sort -count"
        },
        {
          id: "T1570",
          name: "Lateral Tool Transfer",
          description: "Transfert d'outils d'attaque entre les systemes compromis via SMB, partages reseau, ou protocoles de transfert de fichiers pour eviter de retelecharger depuis Internet.",
          detection: "Surveiller les copies de fichiers executables via SMB entre postes. Detecter l'utilisation de PsExec, WMIC pour la copie de fichiers. Alerter sur les transferts de fichiers suspects.",
          splunkQuery: "index=endpoint sourcetype=sysmon EventCode=11 | where match(TargetFilename, \"(?i)(\\\\\\\\.*\\\\.*\\.(exe|dll|ps1|bat|vbs))\") | table _time host Image TargetFilename"
        },
        {
          id: "T1210",
          name: "Exploitation of Remote Services",
          description: "Exploitation de vulnerabilites de services distants pour se deplacer lateralement : EternalBlue (MS17-010), BlueKeep, vulnerabilites dans les services d'impression.",
          detection: "Surveiller les tentatives de connexion sur les ports SMB (445) entre postes de travail. Alerter sur les scans de vulnerabilites internes. Maintenir les correctifs a jour.",
          splunkQuery: "index=firewall dest_port=445 | where src_zone=\"workstations\" AND dest_zone=\"workstations\" | stats count by src_ip dest_ip | where count > 10 | sort -count"
        },
        {
          id: "T1550",
          name: "Use Alternate Authentication Material",
          description: "Utilisation de materiel d'authentification alternatif : Pass-the-Hash (hash NTLM), Pass-the-Ticket (ticket Kerberos), tokens d'acces web voles.",
          detection: "Detecter les authentifications NTLM inhabituelles (Event ID 4624 avec LogonType 9). Surveiller les utilisations de tickets Kerberos depuis des machines inattendues.",
          splunkQuery: "index=windows sourcetype=WinEventLog:Security EventCode=4624 LogonType=9 | stats count by TargetUserName src_ip host LogonProcessName | table _time TargetUserName src_ip host LogonProcessName count"
        }
      ]
    },

    // =========================================================================
    // TA0009 - COLLECTION
    // =========================================================================
    {
      id: "TA0009",
      name: "Collection",
      description: "L'adversaire collecte les donnees d'interet avant l'exfiltration. Il identifie, rassemble et prepare les donnees sensibles pour les extraire du reseau.",
      techniques: [
        {
          id: "T1560",
          name: "Archive Collected Data",
          description: "Compression et archivage des donnees collectees avant l'exfiltration via 7-Zip, WinRAR, tar, ZIP. Parfois avec chiffrement pour eviter l'inspection DLP.",
          detection: "Surveiller la creation de grandes archives (> 100 Mo). Alerter sur l'utilisation d'outils d'archivage dans des repertoires inhabituels. Detecter les archives chiffrees.",
          splunkQuery: "index=endpoint sourcetype=sysmon EventCode=1 | where match(Image, \"(?i)(7z|rar|winrar|zip|tar)\\.exe\") | where match(CommandLine, \"(?i)(a\\s|add|-p|-password)\") | table _time host User Image CommandLine"
        },
        {
          id: "T1005",
          name: "Data from Local System",
          description: "Collecte de donnees depuis le systeme local : documents, bases de donnees, fichiers de configuration, emails stockes localement.",
          detection: "Surveiller les acces massifs a des fichiers sensibles. Alerter sur les copies en masse de fichiers vers des dossiers temporaires. Detecter les lectures inhabituelles de bases de donnees.",
          splunkQuery: "index=endpoint sourcetype=sysmon EventCode=11 | where match(TargetFilename, \"(?i)\\\\(temp|tmp|staging)\\\\.*\\.(doc|xls|pdf|pst|mdb|sql)\") | stats count by host User TargetFilename | where count > 10"
        },
        {
          id: "T1039",
          name: "Data from Network Shared Drive",
          description: "Collecte de donnees depuis les partages reseau et serveurs de fichiers. Les partages contiennent souvent des documents sensibles accessibles a de nombreux utilisateurs.",
          detection: "Surveiller les acces en masse aux partages reseau (nombre de fichiers accedes par minute). Alerter sur les acces a des partages sensibles depuis des comptes inhabituels.",
          splunkQuery: "index=windows sourcetype=WinEventLog:Security EventCode=5145 | stats count dc(RelativeTargetName) as files_accessed by SubjectUserName ShareName src_ip | where files_accessed > 50 | sort -files_accessed"
        },
        {
          id: "T1114",
          name: "Email Collection",
          description: "Collecte d'emails via l'acces aux serveurs de messagerie, les fichiers PST locaux, ou les regles de transfert de messagerie vers des comptes externes.",
          detection: "Surveiller la creation de regles de transfert d'emails vers l'exterieur. Alerter sur l'export de boites aux lettres. Detecter les acces inhabituels a OWA/EWS.",
          splunkQuery: "index=o365 sourcetype=o365:management:activity Operation=Set-Mailbox OR Operation=New-InboxRule | where match(Parameters, \"(?i)(forward|redirect|external)\") | table _time UserId Operation Parameters"
        }
      ]
    },

    // =========================================================================
    // TA0011 - COMMAND AND CONTROL
    // =========================================================================
    {
      id: "TA0011",
      name: "Command and Control",
      description: "L'adversaire communique avec les systemes compromis pour les controler. Le canal C2 permet d'envoyer des commandes, recevoir des donnees et maintenir l'acces. Les techniques modernes utilisent le chiffrement et l'imitation de trafic legitime.",
      techniques: [
        {
          id: "T1071",
          name: "Application Layer Protocol",
          description: "Utilisation de protocoles applicatifs courants (HTTP/HTTPS, DNS, SMTP) pour les communications C2 afin de se fondre dans le trafic reseau normal.",
          detection: "Analyser les patterns de beaconing (connexions regulieres a intervalles fixes). Detecter les requetes DNS inhabituelles (longueur, frequence). Surveiller le trafic HTTPS vers des domaines suspects.",
          splunkQuery: "index=proxy | stats count avg(bytes_out) stdev(bytes_out) by dest_domain src_ip | where count > 100 AND stdev(bytes_out) < 100 | sort -count | head 20"
        },
        {
          id: "T1572",
          name: "Protocol Tunneling",
          description: "Encapsulation du trafic C2 dans des protocoles legitimes : tunnels DNS (dnscat2, iodine), tunnels HTTP, tunnels ICMP. Permet de contourner les firewalls et IDS.",
          detection: "Detecter le DNS tunneling : requetes DNS avec des sous-domaines tres longs, volume DNS anormal, requetes TXT excessives. Surveiller les tunnels SSH inverses.",
          splunkQuery: "index=dns | eval subdomain_length=len(query)-len(replace(query,\".\",\"\")) | where subdomain_length > 50 OR query_type=\"TXT\" | stats count avg(subdomain_length) by src_ip query | where count > 100"
        },
        {
          id: "T1573",
          name: "Encrypted Channel",
          description: "Chiffrement des communications C2 avec SSL/TLS, algorithmes personnalises ou protocoles proprietaires pour empecher l'inspection du contenu.",
          detection: "Inspecter les certificats SSL (auto-signes, emetteurs inhabituels). Analyser les JA3/JA3S fingerprints pour identifier les clients C2 connus. Surveiller le trafic chiffre vers des IP suspectes.",
          splunkQuery: "index=proxy ssl_issuer=* | where NOT match(ssl_issuer, \"(?i)(digicert|letsencrypt|comodo|globalsign|verisign|microsoft|google)\") | stats count by dest_domain ssl_issuer ssl_subject src_ip | sort -count"
        },
        {
          id: "T1102",
          name: "Web Service",
          description: "Utilisation de services web legitimes pour le C2 : Dropbox, Google Drive, Slack, Telegram, GitHub, Pastebin. Tres difficile a bloquer car ce sont des services legitimes.",
          detection: "Surveiller les volumes de trafic inhabituels vers les services de stockage cloud. Alerter sur les connexions API vers ces services depuis des postes non autorises.",
          splunkQuery: "index=proxy | where match(dest_domain, \"(?i)(pastebin|paste\\.ee|hastebin|ghostbin|telegram|discord\\.com/api|raw\\.githubusercontent)\") | stats count sum(bytes_out) as total_bytes by src_ip dest_domain | sort -total_bytes"
        }
      ]
    },

    // =========================================================================
    // TA0010 - EXFILTRATION
    // =========================================================================
    {
      id: "TA0010",
      name: "Exfiltration",
      description: "L'adversaire extrait les donnees collectees du reseau de la victime. L'exfiltration peut utiliser le canal C2 existant, des canaux alternatifs ou des methodes physiques.",
      techniques: [
        {
          id: "T1041",
          name: "Exfiltration Over C2 Channel",
          description: "Exfiltration des donnees via le meme canal utilise pour le Command and Control. Methode la plus courante car elle ne necessite pas d'infrastructure supplementaire.",
          detection: "Surveiller les transferts de donnees importants via les canaux C2 identifies. Alerter sur les volumes de donnees sortants inhabituels. Analyser les patterns d'upload.",
          splunkQuery: "index=proxy | stats sum(bytes_out) as total_upload by src_ip dest_domain | where total_upload > 104857600 | sort -total_upload | eval total_upload_MB=round(total_upload/1048576,2) | table src_ip dest_domain total_upload_MB"
        },
        {
          id: "T1567",
          name: "Exfiltration Over Web Service",
          description: "Exfiltration via des services cloud legitimes (Google Drive, Dropbox, OneDrive, Mega). Difficile a detecter car ces services sont autorises dans la plupart des organisations.",
          detection: "Surveiller les uploads importants vers les services de stockage cloud. Comparer avec les patterns d'utilisation normaux. Alerter sur les transferts en dehors des heures de travail.",
          splunkQuery: "index=proxy | where match(dest_domain, \"(?i)(drive\\.google|dropbox|onedrive|mega\\.nz|wetransfer|sendspace)\") | stats sum(bytes_out) as upload_bytes by src_ip dest_domain | where upload_bytes > 52428800 | eval upload_MB=round(upload_bytes/1048576,2)"
        },
        {
          id: "T1048",
          name: "Exfiltration Over Alternative Protocol",
          description: "Utilisation de protocoles alternatifs pour l'exfiltration : DNS, ICMP, FTP, SMTP. Permet de contourner les controles de securite orientes web.",
          detection: "Detecter les transferts de donnees via DNS (requetes avec donnees encodees). Surveiller le volume de trafic ICMP anormal. Alerter sur les connexions FTP sortantes non autorisees.",
          splunkQuery: "index=dns | stats sum(query_length) as total_query_length count by src_ip | where total_query_length > 10000 OR count > 500 | sort -total_query_length"
        },
        {
          id: "T1029",
          name: "Scheduled Transfer",
          description: "Exfiltration programmee a des heures specifiques ou a intervalles reguliers pour se fondre dans le trafic normal et eviter la detection par volume.",
          detection: "Analyser les patterns de transfert de donnees pour identifier les transferts reguliers inhabituels. Comparer avec les baselines de trafic normal.",
          splunkQuery: "index=proxy | bin _time span=1h | stats sum(bytes_out) as hourly_upload by src_ip _time | eventstats avg(hourly_upload) as avg_upload stdev(hourly_upload) as stdev_upload by src_ip | where hourly_upload > (avg_upload + 3*stdev_upload)"
        }
      ]
    },

    // =========================================================================
    // TA0040 - IMPACT
    // =========================================================================
    {
      id: "TA0040",
      name: "Impact",
      description: "L'adversaire tente de perturber, detruire ou manipuler les systemes et les donnees. Inclut le ransomware, le wiper, le deni de service et la manipulation de donnees.",
      techniques: [
        {
          id: "T1486",
          name: "Data Encrypted for Impact",
          description: "Chiffrement des donnees pour extorsion (ransomware). Les fichiers sont chiffres avec des algorithmes forts et une rancon est demandee pour la cle de dechiffrement. Menace majeure actuelle.",
          detection: "Surveiller les modifications massives de fichiers (renommage, changement d'extension). Detecter les processus qui accedent et modifient un grand nombre de fichiers rapidement. Alerter sur les notes de rancon.",
          splunkQuery: "index=endpoint sourcetype=sysmon EventCode=11 | stats count dc(TargetFilename) as unique_files by host Image | where unique_files > 100 AND count > 500 | sort -unique_files | table host Image unique_files count"
        },
        {
          id: "T1490",
          name: "Inhibit System Recovery",
          description: "Suppression des sauvegardes et des points de restauration pour empecher la recuperation apres une attaque de ransomware. Commandes : vssadmin delete shadows, bcdedit, wbadmin.",
          detection: "Alerter immediatement sur les commandes de suppression de Volume Shadow Copies. Surveiller les modifications de la configuration de demarrage. Proteger les sauvegardes offline.",
          splunkQuery: "index=endpoint sourcetype=sysmon EventCode=1 | where match(CommandLine, \"(?i)(vssadmin.*delete|wbadmin.*delete|bcdedit.*recoveryenabled.*no|wmic.*shadowcopy.*delete)\") | table _time host User Image CommandLine"
        },
        {
          id: "T1485",
          name: "Data Destruction",
          description: "Destruction intentionnelle de donnees par suppression, ecrasement ou formatage de disques. Peut etre utilise comme diversion ou comme objectif principal (wiper).",
          detection: "Surveiller les suppressions massives de fichiers. Alerter sur l'utilisation d'outils de formatage ou d'ecrasement de disques. Detecter les wipers connus via signatures.",
          splunkQuery: "index=endpoint sourcetype=sysmon EventCode=1 | where match(CommandLine, \"(?i)(format.*(/y|/q)|cipher.*(/w)|sdelete|dd\\s+if=|rm\\s+-rf\\s+/)\") | table _time host User Image CommandLine"
        },
        {
          id: "T1498",
          name: "Network Denial of Service",
          description: "Attaque par deni de service distribue (DDoS) pour rendre les services indisponibles. Peut etre volumetrique (saturation de bande passante), protocolaire ou applicatif.",
          detection: "Surveiller les pics de trafic reseau anormaux. Alerter sur les volumes de requetes inhabituels vers un meme service. Utiliser des solutions anti-DDoS en amont.",
          splunkQuery: "index=firewall | bin _time span=1m | stats count sum(bytes) as total_bytes dc(src_ip) as unique_sources by dest_ip _time | where count > 10000 OR unique_sources > 500 | sort -count"
        },
        {
          id: "T1491",
          name: "Defacement",
          description: "Modification du contenu visible d'un site web ou d'une application pour afficher des messages de l'attaquant. Souvent motive par l'hacktivisme ou la volonte de nuire a la reputation.",
          detection: "Surveiller l'integrite des fichiers web (checksums). Alerter sur les modifications de fichiers dans les repertoires web en dehors des deploiements planifies.",
          splunkQuery: "index=web_server sourcetype=file_integrity | where action=\"modified\" AND match(file_path, \"(?i)(wwwroot|htdocs|public_html|www)\") | table _time host file_path action user hash_before hash_after"
        }
      ]
    }
  ],

  // ===========================================================================
  // USE CASE MAPPING - Alertes SOC mappees a MITRE ATT&CK
  // ===========================================================================
  useCaseMapping: [
    {
      alert: "Echecs de connexion multiples depuis une meme IP",
      tactics: ["TA0006 Credential Access"],
      techniques: ["T1110 Brute Force"],
      response: "1. Verifier l'IP source (interne/externe, reputation). 2. Identifier les comptes cibles. 3. Verifier si une connexion reussie a suivi les echecs. 4. Si externe, bloquer l'IP au firewall. 5. Si interne, contacter l'utilisateur du poste source. 6. Verifier les logs VPN et proxy pour cette IP. 7. Si connexion reussie apres echecs, forcer la reinitialisation du mot de passe.",
      severity: "Medium",
      splunkQuery: "index=windows EventCode=4625 | stats count dc(TargetUserName) as users values(TargetUserName) as targets by src_ip | where count > 10"
    },
    {
      alert: "Execution PowerShell encodee en Base64",
      tactics: ["TA0002 Execution", "TA0005 Defense Evasion"],
      techniques: ["T1059.001 PowerShell", "T1027 Obfuscated Files"],
      response: "1. Decoder la commande base64 pour analyser le contenu. 2. Identifier le processus parent (origine de l'execution). 3. Verifier si l'utilisateur a besoin de PowerShell. 4. Analyser la charge utile (telechargement, C2, credential dumping). 5. Isoler le poste si malveillant confirme. 6. Scanner le reseau pour des IOC similaires. 7. Collecter les artefacts forensiques.",
      severity: "High",
      splunkQuery: "index=windows sourcetype=WinEventLog:Microsoft-Windows-PowerShell/Operational EventCode=4104 | where match(ScriptBlockText, \"(?i)(encodedcommand|frombase64)\")"
    },
    {
      alert: "Processus enfant suspect de Microsoft Office",
      tactics: ["TA0002 Execution", "TA0001 Initial Access"],
      techniques: ["T1204.002 User Execution: Malicious File", "T1566.001 Phishing: Spearphishing Attachment"],
      response: "1. Identifier le document Office source et le processus enfant (cmd, powershell, wscript). 2. Retrouver l'email d'origine (expediteur, sujet). 3. Analyser le document dans une sandbox. 4. Verifier si d'autres utilisateurs ont recu le meme email. 5. Bloquer l'expediteur et les IOC au niveau de la passerelle email. 6. Isoler le poste affecte. 7. Scanner les endpoints pour le meme document.",
      severity: "Critical",
      splunkQuery: "index=endpoint sourcetype=sysmon EventCode=1 | where ParentImage LIKE \"%WINWORD%\" OR ParentImage LIKE \"%EXCEL%\" | where Image LIKE \"%cmd.exe\" OR Image LIKE \"%powershell.exe\""
    },
    {
      alert: "Acces au processus LSASS detecte",
      tactics: ["TA0006 Credential Access"],
      techniques: ["T1003.001 OS Credential Dumping: LSASS Memory"],
      response: "1. Verifier le processus source accedant a LSASS (est-ce un outil de securite legitime?). 2. Verifier les droits d'acces demandes (0x1010 est suspect). 3. Si outil non legitime, isoler immediatement le poste. 4. Considerer tous les identifiants caches en memoire comme compromis. 5. Reinitialiser les mots de passe des comptes connectes. 6. Rechercher des mouvements lateraux subsequents. 7. Analyser le binaire suspect.",
      severity: "Critical",
      splunkQuery: "index=endpoint sourcetype=sysmon EventCode=10 TargetImage=\"*lsass.exe\" | where GrantedAccess=\"0x1010\" OR GrantedAccess=\"0x1410\""
    },
    {
      alert: "Nouveau service installe avec un chemin suspect",
      tactics: ["TA0003 Persistence", "TA0002 Execution"],
      techniques: ["T1543.003 Create or Modify System Process: Windows Service"],
      response: "1. Verifier le chemin du binaire du service (doit etre dans Program Files ou Windows). 2. Analyser le binaire (hash, signature numerique). 3. Verifier qui a cree le service (SubjectUserName). 4. Comparer avec la liste des services autorises (baseline). 5. Si suspect, desactiver le service immediatement. 6. Collecter le binaire pour analyse. 7. Rechercher d'autres indicateurs de compromission sur le poste.",
      severity: "High",
      splunkQuery: "index=windows EventCode=7045 | where NOT match(ImagePath, \"(?i)(C:\\\\Windows|C:\\\\Program Files)\") | table _time host ServiceName ImagePath"
    },
    {
      alert: "Effacement du journal de securite Windows",
      tactics: ["TA0005 Defense Evasion"],
      techniques: ["T1070.001 Indicator Removal: Clear Windows Event Logs"],
      response: "1. Identifier immediatement le compte qui a effectue l'effacement. 2. Verifier si l'effacement est planifie ou legitime (maintenance IT). 3. Si non planifie, traiter comme un incident de securite majeur. 4. Rechercher toute activite suspecte precedant l'effacement dans les logs centralises. 5. Isoler le poste. 6. Lancer une investigation forensique complete. 7. Verifier les autres systemes pour des effacements similaires.",
      severity: "Critical",
      splunkQuery: "index=windows EventCode=1102 OR EventCode=104 | table _time host SubjectUserName EventCode Message"
    },
    {
      alert: "Connexion RDP entre postes de travail",
      tactics: ["TA0008 Lateral Movement"],
      techniques: ["T1021.001 Remote Services: Remote Desktop Protocol"],
      response: "1. Verifier si la connexion RDP entre postes est autorisee par la politique de securite (normalement non). 2. Identifier l'utilisateur source et le poste de destination. 3. Verifier si des identifiants privilegies sont utilises. 4. Rechercher des indicateurs de compromission anterieurs sur le poste source. 5. Verifier les activites effectuees sur le poste de destination. 6. Isoler les deux postes si compromission suspectee.",
      severity: "High",
      splunkQuery: "index=windows EventCode=4624 LogonType=10 | where match(src_ip, \"^(10\\.|172\\.(1[6-9]|2|3[01])\\.|192\\.168\\.)\") | lookup workstation_list ip AS dest_ip OUTPUT type | where type=\"workstation\""
    },
    {
      alert: "Requetes DNS avec sous-domaines anormalement longs",
      tactics: ["TA0011 Command and Control", "TA0010 Exfiltration"],
      techniques: ["T1071.004 Application Layer Protocol: DNS", "T1048.001 Exfiltration Over Alternative Protocol"],
      response: "1. Analyser les requetes DNS suspectes (longueur, encodage, domaine cible). 2. Identifier le poste source. 3. Verifier si le domaine cible est connu comme infrastructure de DNS tunneling. 4. Calculer le volume de donnees potentiellement exfiltrees. 5. Bloquer le domaine au niveau DNS. 6. Isoler le poste source. 7. Analyser le malware responsable du tunneling DNS.",
      severity: "High",
      splunkQuery: "index=dns | eval query_length=len(query) | where query_length > 60 | stats count avg(query_length) by src_ip query | sort -count"
    },
    {
      alert: "Suppression des Volume Shadow Copies",
      tactics: ["TA0040 Impact"],
      techniques: ["T1490 Inhibit System Recovery"],
      response: "1. ALERTE MAXIMALE - indicateur fort de ransomware imminent. 2. Isoler immediatement le poste du reseau. 3. Identifier et isoler tous les systemes accedes par le meme compte. 4. Verifier les sauvegardes externes (doivent etre intactes et deconnectees). 5. Lancer la procedure de reponse ransomware. 6. Collecter les evidences avant toute remediation. 7. Informer la direction et preparer la communication de crise.",
      severity: "Critical",
      splunkQuery: "index=endpoint sourcetype=sysmon EventCode=1 | where match(CommandLine, \"(?i)(vssadmin.*delete|wmic.*shadowcopy.*delete)\") | table _time host User CommandLine"
    },
    {
      alert: "Telechargement massif vers un service cloud externe",
      tactics: ["TA0010 Exfiltration"],
      techniques: ["T1567 Exfiltration Over Web Service"],
      response: "1. Identifier le service cloud utilise et le volume de donnees. 2. Verifier si l'utilisateur est autorise a utiliser ce service. 3. Determiner les fichiers transferes (DLP logs). 4. Contacter l'utilisateur pour verification. 5. Si non autorise, bloquer l'acces au service et reinitialiser les identifiants. 6. Evaluer la sensibilite des donnees potentiellement exfiltrees. 7. Si donnees sensibles, lancer la procedure de notification de fuite de donnees.",
      severity: "High",
      splunkQuery: "index=proxy | where match(dest_domain, \"(?i)(dropbox|drive\\.google|mega\\.nz|wetransfer)\") | stats sum(bytes_out) as total_upload by src_ip user dest_domain | where total_upload > 52428800 | eval MB=round(total_upload/1048576,2)"
    }
  ]
};


// =============================================================================
// DONNEES SOC (Security Operations Center)
// =============================================================================

const socData = {

  // ===========================================================================
  // NIVEAUX SOC
  // ===========================================================================
  levels: [
    {
      level: "SOC L1 - Analyste Triage",
      responsibilities: [
        "Surveillance continue des alertes de securite (SIEM, EDR, IDS/IPS)",
        "Triage initial des alertes : vrai positif, faux positif, benin",
        "Classification et priorisation des incidents selon la severite",
        "Escalade des incidents confirmes vers le niveau L2",
        "Documentation des actions dans le systeme de ticketing",
        "Application des playbooks de reponse standardises",
        "Premiere collecte d'informations et de contexte",
        "Surveillance des tableaux de bord et indicateurs de sante"
      ],
      skills: [
        "Connaissance des bases de la cybersecurite (CIA, types d'attaques)",
        "Maitrise du SIEM (Splunk, QRadar, Sentinel) pour la recherche de logs",
        "Comprehension des protocoles reseau (TCP/IP, DNS, HTTP, SMTP)",
        "Connaissance des systemes d'exploitation (Windows, Linux)",
        "Capacite a lire et interpreter les logs (Windows Event Logs, Sysmon, firewall)",
        "Connaissance du framework MITRE ATT&CK (tactiques principales)",
        "Competences en communication ecrite et orale pour la documentation",
        "Gestion du stress et capacite a travailler en equipe 24/7"
      ]
    },
    {
      level: "SOC L2 - Analyste Investigation",
      responsibilities: [
        "Investigation approfondie des incidents escalades par le L1",
        "Analyse de malware de base (analyse statique, sandbox)",
        "Correlation d'evenements multiples pour identifier les attaques complexes",
        "Developpement et amelioration des regles de detection",
        "Analyse forensique preliminaire (memoire, disque, reseau)",
        "Coordination de la reponse aux incidents avec les equipes IT",
        "Redaction de rapports d'incident detailles",
        "Mentorat des analystes L1"
      ],
      skills: [
        "Maitrise avancee du SIEM et creation de requetes complexes",
        "Competences en analyse de malware (statique et dynamique)",
        "Connaissance approfondie de MITRE ATT&CK (techniques et sous-techniques)",
        "Experience en forensique numerique (Volatility, Autopsy, FTK)",
        "Scripting (Python, PowerShell) pour l'automatisation",
        "Comprehension avancee des attaques reseau et systeme",
        "Connaissance des outils offensifs (Metasploit, Cobalt Strike) pour mieux les detecter",
        "Capacite a conduire une investigation de bout en bout"
      ]
    },
    {
      level: "SOC L3 - Expert / Threat Hunter",
      responsibilities: [
        "Threat hunting proactif base sur les renseignements de menaces",
        "Analyse de malware avancee (reverse engineering)",
        "Developpement d'outils et d'automatisation pour le SOC",
        "Architecture et amelioration de la plateforme de detection",
        "Veille sur les menaces et les vulnerabilites (Threat Intelligence)",
        "Gestion des incidents majeurs et crises de securite",
        "Formation et developpement des competences de l'equipe",
        "Collaboration avec les equipes Red Team et pentest"
      ],
      skills: [
        "Expertise en reverse engineering et analyse de malware avancee",
        "Maitrise complete du framework MITRE ATT&CK et D3FEND",
        "Competences avancees en forensique (memoire, reseau, mobile)",
        "Developpement de signatures et regles de detection (YARA, Sigma, Snort)",
        "Programmation avancee (Python, Go, C) pour le developpement d'outils",
        "Connaissance approfondie de la Threat Intelligence (TTP, IOC, campagnes)",
        "Experience en gestion de crise et communication executive",
        "Certifications avancees (GCIH, GCIA, GCFA, OSCP)"
      ]
    }
  ],

  // ===========================================================================
  // REPONSE AUX INCIDENTS - NIST SP 800-61
  // ===========================================================================
  incidentResponse: {
    framework: "NIST SP 800-61 Rev. 2 - Computer Security Incident Handling Guide",
    phases: [
      {
        name: "1. Preparation",
        description: "Phase fondamentale qui consiste a preparer l'organisation a gerer efficacement les incidents de securite. Sans une bonne preparation, la reponse sera chaotique et inefficace.",
        activities: [
          "Mise en place d'une equipe de reponse aux incidents (CSIRT/CERT)",
          "Redaction et maintien des politiques et procedures de reponse",
          "Deploiement des outils de detection et de reponse (SIEM, EDR, SOAR)",
          "Formation reguliere de l'equipe SOC (exercices, tabletop, red team)",
          "Etablissement des canaux de communication (internes et externes)",
          "Inventaire des actifs critiques et classification des donnees",
          "Mise en place de sauvegardes testees regulierement",
          "Etablissement de baselines de comportement normal pour la detection",
          "Mise a jour des contacts d'urgence et des matrices d'escalade",
          "Tests reguliers du plan de reponse aux incidents (exercices de simulation)"
        ]
      },
      {
        name: "2. Detection et Analyse",
        description: "Identification des incidents de securite, validation de leur authenticite et analyse de leur portee et impact. Phase critique ou la rapidite et la precision sont essentielles.",
        activities: [
          "Surveillance continue des alertes SIEM, EDR et IDS/IPS",
          "Triage et validation des alertes (elimination des faux positifs)",
          "Collecte et preservation des evidences numeriques",
          "Correlation des evenements pour identifier la chaine d'attaque complete",
          "Determination du vecteur d'attaque initial",
          "Evaluation de l'etendue de la compromission (systemes affectes)",
          "Classification de l'incident selon sa severite et son impact",
          "Notification des parties prenantes selon la matrice d'escalade",
          "Documentation detaillee de toutes les observations et actions",
          "Utilisation du framework MITRE ATT&CK pour mapper les TTP observes"
        ]
      },
      {
        name: "3. Confinement, Eradication et Recuperation",
        description: "Limitation de l'impact de l'incident, elimination de la menace et restauration des systemes a un etat operationnel normal. Phase d'action qui necessite coordination et precision.",
        activities: [
          "Confinement a court terme : isolation reseau des systemes compromis",
          "Confinement a long terme : application de correctifs, renforcement des regles",
          "Preservation des evidences avant toute action de remediation",
          "Eradication : suppression du malware, fermeture des acces non autorises",
          "Reinitialisation des identifiants compromis",
          "Verification de l'absence de persistance residuelle",
          "Restauration des systemes depuis des sauvegardes verifiees",
          "Mise a jour et patching des vulnerabilites exploitees",
          "Surveillance accrue post-remediation pour detecter toute resurgence",
          "Validation du retour a la normale avec les equipes metier"
        ]
      },
      {
        name: "4. Activite Post-Incident",
        description: "Retour d'experience (RETEX) pour ameliorer les processus et la posture de securite. Phase souvent negligee mais essentielle pour l'amelioration continue.",
        activities: [
          "Reunion de retour d'experience (lessons learned) avec toutes les parties prenantes",
          "Redaction du rapport d'incident complet (timeline, impact, actions, recommandations)",
          "Identification des lacunes dans la detection et la reponse",
          "Mise a jour des regles de detection pour couvrir les TTP observes",
          "Amelioration des playbooks et procedures de reponse",
          "Mise a jour de la base de connaissances des IOC et des menaces",
          "Partage des indicateurs avec les partenaires (CERT, ISACs)",
          "Formation complementaire de l'equipe basee sur les lacunes identifiees",
          "Evaluation et amelioration des outils et de l'infrastructure SOC",
          "Suivi de l'implementation des recommandations post-incident"
        ]
      }
    ]
  },

  // ===========================================================================
  // CYBER KILL CHAIN (Lockheed Martin)
  // ===========================================================================
  killChain: {
    description: "La Cyber Kill Chain de Lockheed Martin est un modele qui decrit les 7 etapes d'une cyberattaque. Contrairement a MITRE ATT&CK qui est une matrice detaillee, la Kill Chain offre une vue lineaire et sequentielle de l'attaque. Les deux modeles sont complementaires : la Kill Chain pour la comprehension strategique, MITRE pour l'analyse tactique detaillee.",
    phases: [
      {
        name: "1. Reconnaissance",
        description: "L'attaquant collecte des informations sur la cible : adresses email, technologies utilisees, employes cles, adresses IP, services exposes. Utilise des sources OSINT, reseaux sociaux, scan de ports.",
        detection: "Difficile a detecter car souvent passive. Surveiller les scans de ports externes, les requetes DNS inhabituelles vers vos domaines, les tentatives d'enumeration de comptes email. Utiliser des honeypots pour detecter la reconnaissance active.",
        mitreTactics: "TA0043 Reconnaissance"
      },
      {
        name: "2. Weaponization (Armement)",
        description: "L'attaquant cree l'arme cyber : document piege avec exploit, malware personnalise, payload Cobalt Strike. Combine un exploit avec une charge utile (backdoor, RAT). Se fait hors du reseau de la victime.",
        detection: "Phase quasi-impossible a detecter car elle se deroule en dehors de votre infrastructure. Utiliser la Threat Intelligence pour anticiper les outils et techniques utilises par les groupes d'attaquants connus.",
        mitreTactics: "TA0042 Resource Development"
      },
      {
        name: "3. Delivery (Livraison)",
        description: "L'arme est livree a la cible : email de phishing avec piece jointe ou lien, site web compromis (watering hole), cle USB deposee, exploitation de service expose.",
        detection: "Analyser les emails entrants (pieces jointes, liens, expediteurs). Surveiller les telechargements depuis le web. Utiliser des sandboxes pour detonner les fichiers suspects. Verifier les connexions vers des domaines recemment crees.",
        mitreTactics: "TA0001 Initial Access"
      },
      {
        name: "4. Exploitation",
        description: "L'exploit est declenche : vulnerabilite logicielle exploitee, macro Office executee, utilisateur qui clique sur un lien piege. C'est le moment ou l'attaquant obtient l'execution de code.",
        detection: "Surveiller les processus enfants suspects (Office qui lance PowerShell). Detecter les tentatives d'exploitation connues via IDS/IPS. Alerter sur les crash de processus et les comportements anormaux d'applications.",
        mitreTactics: "TA0002 Execution"
      },
      {
        name: "5. Installation",
        description: "L'attaquant installe un acces persistant : backdoor, RAT (Remote Access Trojan), web shell, creation de compte, tache planifiee. Objectif : maintenir l'acces meme apres un redemarrage.",
        detection: "Surveiller les nouveaux services installes (7045), les modifications de registre (Sysmon 13), les nouvelles taches planifiees (4698), la creation de comptes (4720). Comparer avec les baselines connues.",
        mitreTactics: "TA0003 Persistence, TA0004 Privilege Escalation"
      },
      {
        name: "6. Command and Control (C2)",
        description: "L'attaquant etablit un canal de communication avec le systeme compromis pour envoyer des commandes et recevoir des donnees. Utilise souvent HTTP/HTTPS, DNS, ou des services cloud legitimes pour se camoufler.",
        detection: "Analyser les patterns de beaconing (connexions periodiques). Detecter le DNS tunneling. Surveiller les connexions vers des domaines suspects ou recemment crees. Inspecter le trafic chiffre (JA3/JA3S fingerprints).",
        mitreTactics: "TA0011 Command and Control"
      },
      {
        name: "7. Actions on Objectives (Actions sur les objectifs)",
        description: "L'attaquant realise ses objectifs finaux : vol de donnees, deploiement de ransomware, espionnage, sabotage, destruction. C'est la phase ou l'impact sur l'organisation se materialise.",
        detection: "Surveiller l'exfiltration de donnees (volumes de transfert anormaux). Detecter le mouvement lateral (connexions entre postes). Alerter sur le chiffrement massif de fichiers (ransomware). Surveiller les acces aux donnees sensibles.",
        mitreTactics: "TA0009 Collection, TA0010 Exfiltration, TA0040 Impact"
      }
    ]
  },

  // ===========================================================================
  // USE CASES DE DETECTION
  // ===========================================================================
  useCases: {
    description: "Un Use Case de detection est une regle ou un scenario de detection concu pour identifier une activite suspecte ou malveillante specifique. Il definit les sources de donnees, la logique de detection, la severite et la procedure de reponse. Chaque Use Case doit etre mappe au framework MITRE ATT&CK.",
    template: {
      name: "Nom descriptif du Use Case",
      description: "Description de ce que le Use Case detecte et pourquoi",
      dataSources: "Sources de donnees necessaires (logs)",
      logic: "Logique de detection (requete SPL, conditions)",
      severity: "Criticite de l'alerte (Low, Medium, High, Critical)",
      response: "Procedure de reponse en cas d'alerte",
      mitre: "Mapping MITRE ATT&CK (Tactic/Technique)"
    },
    examples: [
      {
        name: "Detection de Brute Force",
        description: "Detecte les tentatives de brute force sur les comptes en surveillant les echecs de connexion multiples depuis une meme source en un temps court.",
        dataSources: "Windows Security Logs (Event ID 4625), logs VPN, logs d'authentification applicatifs",
        logic: "Plus de 10 echecs de connexion depuis une meme IP en 5 minutes, ou plus de 5 comptes differents testes depuis une meme IP en 10 minutes (password spraying).",
        severity: "Medium (elevee a High si un compte admin est cible)",
        response: "Verifier la source (interne/externe). Si externe, bloquer l'IP. Si interne, investiguer le poste source. Verifier si une connexion reussie a suivi. Reinitialiser le mot de passe si compromission suspectee.",
        mitre: "TA0006 Credential Access / T1110 Brute Force",
        splunkQuery: "index=windows EventCode=4625 | bin _time span=5m | stats count dc(TargetUserName) as unique_users by src_ip _time | where count > 10 OR unique_users > 5"
      },
      {
        name: "Detection de Mouvement Lateral via RDP",
        description: "Detecte les connexions RDP entre postes de travail qui ne sont normalement pas autorisees. Les connexions RDP devraient aller des postes de travail vers les serveurs, pas entre postes.",
        dataSources: "Windows Security Logs (Event ID 4624 LogonType 10), logs reseau (connexions port 3389)",
        logic: "Connexion RDP (LogonType 10) ou le poste source ET le poste de destination sont des postes de travail (pas des serveurs ni des jump hosts autorises).",
        severity: "High",
        response: "Identifier l'utilisateur et les deux postes concernes. Verifier les activites precedentes sur le poste source (signes de compromission). Isoler les deux postes si la compromission est suspectee. Analyser les logs du poste de destination.",
        mitre: "TA0008 Lateral Movement / T1021.001 Remote Desktop Protocol",
        splunkQuery: "index=windows EventCode=4624 LogonType=10 | lookup asset_type src_ip OUTPUT src_type | lookup asset_type dest_ip OUTPUT dest_type | where src_type=\"workstation\" AND dest_type=\"workstation\""
      },
      {
        name: "Detection de Credential Dumping LSASS",
        description: "Detecte les tentatives d'acces au processus LSASS pour extraire les identifiants en memoire. Technique utilisee par Mimikatz et d'autres outils de credential dumping.",
        dataSources: "Sysmon (Event ID 10 - Process Access), Windows Security Logs",
        logic: "Acces au processus lsass.exe avec des droits d'acces suspects (GrantedAccess contenant 0x1010, 0x1410, 0x1438) depuis un processus qui n'est pas un outil de securite legitime.",
        severity: "Critical",
        response: "Isoler immediatement le poste. Identifier tous les comptes dont les identifiants etaient en memoire. Reinitialiser tous les mots de passe concernes. Lancer une investigation forensique. Rechercher les mouvements lateraux subsequents.",
        mitre: "TA0006 Credential Access / T1003.001 LSASS Memory",
        splunkQuery: "index=endpoint sourcetype=sysmon EventCode=10 TargetImage=\"*lsass.exe\" | where NOT match(SourceImage, \"(?i)(MsMpEng|csrss|svchost|wininit)\") | where GrantedAccess=\"0x1010\" OR GrantedAccess=\"0x1410\""
      },
      {
        name: "Detection de Persistance via Tache Planifiee",
        description: "Detecte la creation de taches planifiees suspectes utilisees comme mecanisme de persistance. Les taches executant des scripts ou des binaires depuis des emplacements inhabituels sont signalees.",
        dataSources: "Windows Security Logs (Event ID 4698), Sysmon (Event ID 1 pour schtasks.exe)",
        logic: "Creation d'une tache planifiee (4698) dont la commande pointe vers un script (ps1, bat, vbs) ou un executable dans un dossier temporaire, AppData, ou dossier utilisateur.",
        severity: "High",
        response: "Analyser la tache planifiee creee (commande, declencheur, frequence). Identifier le processus et l'utilisateur ayant cree la tache. Verifier le binaire ou script cible. Desactiver la tache si malveillante. Investiguer l'origine de la creation.",
        mitre: "TA0003 Persistence / T1053.005 Scheduled Task",
        splunkQuery: "index=windows EventCode=4698 | rex field=TaskContent \"<Command>(?<command>[^<]+)\" | where match(command, \"(?i)(temp|appdata|users.*desktop|powershell|cmd|wscript)\")"
      },
      {
        name: "Detection de DNS Tunneling",
        description: "Detecte l'exfiltration de donnees ou les communications C2 via le protocole DNS. Les requetes DNS avec des sous-domaines anormalement longs ou un volume de requetes excessif sont des indicateurs.",
        dataSources: "Logs DNS (serveur DNS interne, Sysmon Event ID 22, passive DNS)",
        logic: "Requetes DNS avec des sous-domaines de longueur superieure a 50 caracteres, ou plus de 500 requetes DNS vers un meme domaine en une heure, ou requetes TXT inhabituelles.",
        severity: "High",
        response: "Identifier le poste source. Analyser le domaine cible (reputation, age, registrar). Bloquer le domaine au niveau DNS. Isoler le poste. Analyser le malware utilisant le tunnel DNS. Evaluer le volume de donnees potentiellement exfiltrees.",
        mitre: "TA0011 Command and Control / T1071.004 DNS, TA0010 Exfiltration / T1048",
        splunkQuery: "index=dns | eval query_length=len(query) | where query_length > 50 OR query_type=\"TXT\" | stats count avg(query_length) as avg_len by src_ip query | where count > 100 OR avg_len > 50"
      },
      {
        name: "Detection de Ransomware (Modification Massive de Fichiers)",
        description: "Detecte l'activite de chiffrement de ransomware en surveillant les modifications rapides et massives de fichiers, typiques d'un processus de chiffrement.",
        dataSources: "Sysmon (Event ID 11 - FileCreate, Event ID 2 - FileCreationTime), EDR telemetry",
        logic: "Un meme processus modifie plus de 100 fichiers uniques en moins de 5 minutes, ou renomme des fichiers avec des extensions connues de ransomware (.encrypted, .locked, .crypt).",
        severity: "Critical",
        response: "Isoler immediatement le poste du reseau. Identifier et terminer le processus de chiffrement. Evaluer l'etendue des fichiers chiffres. Verifier l'integrite des sauvegardes. NE PAS payer la rancon. Contacter les autorites (ANSSI/CERT-FR). Lancer la procedure de crise ransomware.",
        mitre: "TA0040 Impact / T1486 Data Encrypted for Impact",
        splunkQuery: "index=endpoint sourcetype=sysmon EventCode=11 | bin _time span=5m | stats dc(TargetFilename) as unique_files count by host Image _time | where unique_files > 100"
      }
    ]
  },

  // ===========================================================================
  // PLAYBOOKS DE REPONSE
  // ===========================================================================
  playbooks: {
    description: "Un playbook de reponse aux incidents est un guide pas-a-pas qui definit les actions a prendre face a un type d'incident specifique. Il standardise la reponse, reduit le temps de reaction et assure la coherence entre les analystes. Chaque playbook doit etre regulierement teste et mis a jour.",
    template: {
      trigger: "Condition declenchant le playbook",
      triage: "Actions de triage initial",
      investigation: "Etapes d'investigation detaillees",
      containment: "Actions de confinement",
      eradication: "Actions d'eradication de la menace",
      recovery: "Procedure de recuperation",
      lessons: "Retour d'experience et ameliorations"
    },
    examples: [
      {
        name: "Playbook - Reponse a un Email de Phishing",
        steps: [
          {
            phase: "Declenchement",
            actions: [
              "Alerte declenchee par : signalement utilisateur, detection passerelle email, ou regle SIEM",
              "Priorite initiale : Medium (elevee si piece jointe executee ou identifiants soumis)"
            ]
          },
          {
            phase: "Triage (15 minutes max)",
            actions: [
              "Verifier l'expediteur (SPF, DKIM, DMARC, reputation du domaine)",
              "Analyser les headers de l'email (chemin de routage, X-headers)",
              "Examiner les URLs et pieces jointes (VirusTotal, sandbox)",
              "Determiner combien d'utilisateurs ont recu le meme email",
              "Classifier : phishing de masse, spear-phishing, ou BEC (Business Email Compromise)"
            ]
          },
          {
            phase: "Investigation (30 minutes max)",
            actions: [
              "Identifier tous les destinataires via les logs de la passerelle email",
              "Verifier qui a clique sur les liens (logs proxy/DNS)",
              "Verifier qui a ouvert les pieces jointes (logs endpoint/EDR)",
              "Verifier si des identifiants ont ete soumis (logs du domaine de phishing)",
              "Analyser la charge utile dans une sandbox (Any.Run, Joe Sandbox)",
              "Extraire les IOC : domaines, IP, hashes, patterns de l'email"
            ]
          },
          {
            phase: "Confinement",
            actions: [
              "Bloquer l'expediteur au niveau de la passerelle email",
              "Bloquer les URLs et domaines malveillants (proxy, DNS, firewall)",
              "Supprimer l'email de toutes les boites aux lettres (purge Exchange/O365)",
              "Si credentials soumis : reinitialiser immediatement les mots de passe",
              "Si piece jointe executee : isoler le poste du reseau via EDR",
              "Revoquer les sessions actives si identifiants compromis"
            ]
          },
          {
            phase: "Eradication et Recuperation",
            actions: [
              "Scanner les postes compromis pour tout malware installe",
              "Supprimer les mecanismes de persistance identifies",
              "Verifier les regles de transfert de messagerie (inbox rules)",
              "Reimager le poste si necessaire",
              "Restaurer les fichiers affectes depuis les sauvegardes",
              "Confirmer la remise en service avec l'utilisateur"
            ]
          },
          {
            phase: "Post-Incident",
            actions: [
              "Mettre a jour les regles de detection de la passerelle email",
              "Ajouter les IOC a la base de Threat Intelligence",
              "Envoyer une communication de sensibilisation aux utilisateurs",
              "Documenter l'incident dans le systeme de ticketing",
              "Rediger le rapport d'incident avec les IOC et la timeline"
            ]
          }
        ]
      },
      {
        name: "Playbook - Reponse a un Ransomware",
        steps: [
          {
            phase: "Declenchement",
            actions: [
              "Alerte declenchee par : EDR (chiffrement massif), SIEM (suppression shadow copies), ou signalement utilisateur (fichiers inaccessibles, note de rancon)",
              "Priorite : CRITIQUE - Activation immediate de la cellule de crise"
            ]
          },
          {
            phase: "Triage (5 minutes max - URGENCE)",
            actions: [
              "Identifier le ou les postes affectes",
              "Determiner si le chiffrement est toujours en cours",
              "Identifier le type de ransomware (note de rancon, extension des fichiers)",
              "Evaluer la propagation : quels partages reseau sont touches?",
              "ISOLER IMMEDIATEMENT les systemes affectes du reseau"
            ]
          },
          {
            phase: "Investigation",
            actions: [
              "Identifier le vecteur d'infection initial (email, exploit, RDP expose)",
              "Determiner depuis combien de temps l'attaquant est present (dwell time)",
              "Identifier tous les systemes compromis (mouvement lateral)",
              "Verifier l'integrite des sauvegardes (sont-elles chiffrees aussi?)",
              "Identifier les comptes compromis utilises par l'attaquant",
              "Collecter les evidences forensiques (memoire, logs, artefacts)",
              "Verifier si des donnees ont ete exfiltrees AVANT le chiffrement (double extorsion)"
            ]
          },
          {
            phase: "Confinement",
            actions: [
              "Isoler tous les segments reseau affectes",
              "Desactiver les comptes compromis",
              "Bloquer les IOC identifies (IP C2, domaines, hashes)",
              "Deconnecter les sauvegardes du reseau pour les proteger",
              "Bloquer le trafic SMB lateral (port 445) entre les postes de travail",
              "Desactiver les services de bureau a distance (RDP) non essentiels",
              "NE PAS eteindre les machines (risque de perte de preuves en memoire)"
            ]
          },
          {
            phase: "Eradication et Recuperation",
            actions: [
              "Identifier et supprimer tous les mecanismes de persistance",
              "Reinitialiser TOUS les mots de passe du domaine (y compris le compte KRBTGT 2 fois)",
              "Reimager tous les systemes compromis",
              "Restaurer les donnees depuis des sauvegardes verifiees et propres",
              "Appliquer les correctifs de securite manquants",
              "Renforcer les configurations de securite identifiees comme faibles",
              "Restaurer les services par ordre de priorite metier",
              "Verifier un eventuel outil de dechiffrement gratuit (No More Ransom Project)"
            ]
          },
          {
            phase: "Post-Incident",
            actions: [
              "Declarer l'incident a l'ANSSI si applicable (OIV, OSE)",
              "Notifier la CNIL si donnees personnelles impactees (72h)",
              "Rediger un rapport complet avec timeline et recommandations",
              "Implementer les recommandations de renforcement",
              "Tester et ameliorer les sauvegardes (regle 3-2-1)",
              "Former les utilisateurs sur le vecteur d'infection identifie",
              "NE JAMAIS payer la rancon (pas de garantie, finance le crime)"
            ]
          }
        ]
      },
      {
        name: "Playbook - Reponse a un Compte Compromis",
        steps: [
          {
            phase: "Declenchement",
            actions: [
              "Alerte declenchee par : impossible travel (connexion depuis 2 pays en peu de temps), connexion depuis IP malveillante, comportement anormal du compte, ou signalement utilisateur",
              "Priorite : High (Critical si compte a privileges)"
            ]
          },
          {
            phase: "Triage (10 minutes max)",
            actions: [
              "Verifier l'alerte : la connexion suspecte est-elle un vrai positif?",
              "Identifier le compte concerne et son niveau de privilege",
              "Verifier l'IP source (geolocalisation, reputation, VPN d'entreprise?)",
              "Determiner si l'acces est toujours actif",
              "Contacter l'utilisateur par un canal alternatif (telephone, pas email)"
            ]
          },
          {
            phase: "Investigation",
            actions: [
              "Analyser l'historique de connexion du compte (dernieres 72h)",
              "Identifier toutes les sessions actives du compte",
              "Verifier les changements effectues (regles de messagerie, delegations)",
              "Rechercher des acces a des donnees sensibles ou des partages",
              "Verifier si le mot de passe a ete change par l'attaquant",
              "Identifier le vecteur de compromission (phishing, brute force, fuite de mot de passe)",
              "Verifier si d'autres comptes sont compromis avec le meme vecteur"
            ]
          },
          {
            phase: "Confinement",
            actions: [
              "Reinitialiser immediatement le mot de passe du compte",
              "Revoquer toutes les sessions actives et tokens d'authentification",
              "Activer ou renforcer le MFA sur le compte",
              "Bloquer l'IP source suspecte si externe",
              "Desactiver temporairement le compte si les actions de l'attaquant ne sont pas claires",
              "Verifier et supprimer les regles de transfert d'email ajoutees"
            ]
          },
          {
            phase: "Eradication et Recuperation",
            actions: [
              "Verifier que tous les acces non autorises ont ete fermes",
              "Restaurer les configurations du compte modifiees par l'attaquant",
              "Verifier les droits et les groupes du compte (pas d'elevation)",
              "Scanner le poste de l'utilisateur si malware suspecte",
              "Generer un nouveau mot de passe fort et le communiquer securement",
              "Reactiver le compte et confirmer avec l'utilisateur"
            ]
          },
          {
            phase: "Post-Incident",
            actions: [
              "Determiner si des donnees sensibles ont ete accedees ou exfiltrees",
              "Notifier le DPO si donnees personnelles impactees",
              "Renforcer la politique de mots de passe si necessaire",
              "Former l'utilisateur sur la securite des identifiants",
              "Ajouter les IOC a la base de Threat Intelligence",
              "Mettre a jour les regles de detection (nouveau pattern d'alerte)"
            ]
          }
        ]
      }
    ]
  },

  // ===========================================================================
  // TYPES DE LOGS ET EVENEMENTS CLES
  // ===========================================================================
  logTypes: [
    {
      source: "Windows Security Logs",
      description: "Journaux de securite Windows generes par le systeme d'exploitation. Source de donnees fondamentale pour la detection d'activites suspectes sur les postes et serveurs Windows. Configures via la politique d'audit (GPO).",
      keyEvents: [
        { code: "4624", name: "Connexion reussie (Successful Logon)", description: "Enregistre chaque connexion reussie avec le type de logon (2=Interactive, 3=Network, 10=RDP). Essentiel pour tracer les acces." },
        { code: "4625", name: "Echec de connexion (Failed Logon)", description: "Enregistre les tentatives de connexion echouees. Utile pour detecter le brute force. Le sous-code d'etat indique la raison (mot de passe incorrect, compte verrouille)." },
        { code: "4672", name: "Privileges speciaux attribues (Special Privileges)", description: "Enregistre quand un utilisateur se connecte avec des privileges administratifs. Permet de tracer l'utilisation de comptes privilegies." },
        { code: "4720", name: "Compte utilisateur cree (User Account Created)", description: "Enregistre la creation d'un nouveau compte local ou de domaine. Permet de detecter la creation de comptes backdoor par un attaquant." },
        { code: "4728", name: "Membre ajoute a un groupe de securite global (Security Group Member Added)", description: "Enregistre l'ajout d'un membre a un groupe de securite global (ex: Domain Admins). Critique pour detecter l'elevation de privileges." },
        { code: "4732", name: "Membre ajoute a un groupe local (Local Group Member Added)", description: "Enregistre l'ajout d'un membre a un groupe local (ex: Administrateurs). Permet de detecter l'ajout non autorise de comptes aux groupes d'administration locale." },
        { code: "7045", name: "Service installe (Service Installed)", description: "Enregistre l'installation d'un nouveau service Windows. Les attaquants utilisent souvent des services pour la persistance et l'execution de code." },
        { code: "1102", name: "Journal d'audit efface (Audit Log Cleared)", description: "Enregistre l'effacement du journal de securite. Indicateur tres suspect de defense evasion. Doit declencher une alerte immediate." },
        { code: "4648", name: "Connexion avec identifiants explicites (Explicit Credentials Logon)", description: "Enregistre l'utilisation d'identifiants explicites (runas, connexion reseau avec d'autres credentials). Utile pour detecter le pass-the-hash et le mouvement lateral." },
        { code: "4688", name: "Nouveau processus cree (New Process Created)", description: "Enregistre la creation de chaque processus avec la ligne de commande (si auditee). Alternative a Sysmon Event ID 1 pour le suivi des executions." },
        { code: "4698", name: "Tache planifiee creee (Scheduled Task Created)", description: "Enregistre la creation de taches planifiees. Permet de detecter les mecanismes de persistance bases sur les taches planifiees." },
        { code: "4769", name: "Ticket de service Kerberos demande (Kerberos Service Ticket Request)", description: "Enregistre les demandes de tickets de service Kerberos (TGS). Permet de detecter le Kerberoasting (nombreuses demandes TGS avec chiffrement RC4)." }
      ]
    },
    {
      source: "Sysmon (System Monitor)",
      description: "Outil Microsoft Sysinternals qui fournit une telemetrie detaillee sur les activites systeme. Indispensable pour la detection avancee. Complement essentiel aux logs Windows natifs. Configure via un fichier XML.",
      keyEvents: [
        { code: "1", name: "Process Creation", description: "Enregistre la creation de processus avec le hash, la ligne de commande complete, le processus parent, l'utilisateur et le niveau d'integrite. Evenement le plus important pour la detection." },
        { code: "3", name: "Network Connection", description: "Enregistre les connexions reseau etablies par les processus avec l'IP/port source et destination. Permet de lier les processus a leurs communications reseau." },
        { code: "7", name: "Image Loaded (DLL)", description: "Enregistre le chargement de DLL par les processus. Permet de detecter le DLL sideloading et les injections de DLL malveillantes." },
        { code: "8", name: "CreateRemoteThread", description: "Enregistre la creation de threads distants dans un autre processus. Indicateur fort d'injection de processus (technique d'evasion et d'elevation de privileges)." },
        { code: "10", name: "Process Access", description: "Enregistre les acces inter-processus. Critique pour detecter le credential dumping (acces a LSASS). Les droits d'acces accordes indiquent l'intention." },
        { code: "11", name: "File Created", description: "Enregistre la creation de fichiers. Permet de detecter le depot de fichiers malveillants, les documents telecharges et les modifications suspectes." },
        { code: "13", name: "Registry Value Set", description: "Enregistre les modifications de valeurs de registre. Essentiel pour detecter la persistance via les cles Run, les modifications de configuration de securite." },
        { code: "22", name: "DNS Query", description: "Enregistre les requetes DNS effectuees par les processus. Permet de lier les resolutions DNS aux processus responsables, utile pour detecter le C2 et le DNS tunneling." },
        { code: "19-21", name: "WMI Events (Filter/Consumer/Binding)", description: "Enregistre la creation de souscriptions d'evenements WMI. Technique de persistance furtive utilisee par les attaquants avances." },
        { code: "25", name: "Process Tampering", description: "Detecte le tampering de processus comme le process hollowing et le process herpaderping. Technique d'evasion avancee." }
      ]
    },
    {
      source: "Logs Firewall",
      description: "Journaux generes par les firewalls reseau (Palo Alto, Fortinet, Check Point, pfSense). Enregistrent le trafic autorise et bloque. Source essentielle pour la surveillance perimetrique et la detection d'activites reseau suspectes.",
      keyFields: [
        { field: "src_ip / dst_ip", description: "Adresses IP source et destination. Permettent d'identifier les parties communicantes." },
        { field: "src_port / dst_port", description: "Ports source et destination. Le port de destination indique le service cible." },
        { field: "action (allow/deny/drop)", description: "Action effectuee par le firewall. Les deny/drop en masse peuvent indiquer un scan ou une attaque." },
        { field: "protocol", description: "Protocole utilise (TCP, UDP, ICMP). Utile pour identifier les types de trafic." },
        { field: "bytes_sent / bytes_received", description: "Volume de donnees transferees. Utile pour detecter l'exfiltration de donnees." },
        { field: "application", description: "Application identifiee par le firewall next-gen (L7). Permet de detecter les tunnels et les protocoles deguises." },
        { field: "zone (src_zone / dst_zone)", description: "Zones de securite source et destination. Le trafic inter-zones inhabituel peut indiquer un mouvement lateral." },
        { field: "threat_name / threat_id", description: "Menaces detectees par le moteur IPS integre. Alertes sur les exploits et le trafic malveillant connu." }
      ]
    },
    {
      source: "Logs Proxy / Web",
      description: "Journaux generes par les proxys web (Squid, Zscaler, BlueCoat, FortiProxy) et les passerelles web securisees. Enregistrent toutes les requetes HTTP/HTTPS des utilisateurs. Essentiels pour detecter le C2 sur HTTP et l'exfiltration via le web.",
      keyFields: [
        { field: "url / uri", description: "URL complete de la requete. Permet d'identifier les sites visites et les patterns de C2." },
        { field: "dest_domain / host", description: "Domaine de destination. Utile pour la categorisation et la detection de domaines malveillants." },
        { field: "src_ip / user", description: "Adresse IP source et utilisateur authentifie. Permet d'identifier qui a initie la requete." },
        { field: "http_method", description: "Methode HTTP (GET, POST, PUT). Les POST volumineux peuvent indiquer une exfiltration." },
        { field: "status_code", description: "Code de reponse HTTP. Les 200 vers des sites suspects confirment une connexion C2 reussie." },
        { field: "bytes_out / content_length", description: "Volume de donnees envoyees. Utile pour detecter l'exfiltration (upload important)." },
        { field: "user_agent", description: "User-Agent du client. Les user-agents inhabituels ou absents peuvent indiquer des outils automatises ou du malware." },
        { field: "category", description: "Categorie du site (reputation). Les categories comme 'uncategorized', 'newly_registered' sont a surveiller." },
        { field: "ssl_issuer / ssl_subject", description: "Informations sur le certificat SSL. Les certificats auto-signes ou suspects indiquent un C2 potentiel." }
      ]
    },
    {
      source: "Logs DNS",
      description: "Journaux des serveurs DNS internes et des resolvers. Enregistrent toutes les requetes de resolution de noms. Source critique pour detecter le DNS tunneling, les communications C2 via DNS et les domaines malveillants.",
      keyFields: [
        { field: "query / query_name", description: "Nom de domaine demande. Permet d'identifier les domaines resolus et de detecter les DGA (Domain Generation Algorithm)." },
        { field: "query_type", description: "Type de requete DNS (A, AAAA, MX, TXT, CNAME). Les requetes TXT excessives peuvent indiquer du DNS tunneling." },
        { field: "src_ip", description: "IP du client effectuant la requete. Permet d'identifier le poste concerne." },
        { field: "answer / rdata", description: "Reponse DNS. Permet de verifier les IP resolues et de detecter les redirections malveillantes." },
        { field: "response_code (RCODE)", description: "Code de reponse DNS (NOERROR, NXDOMAIN, SERVFAIL). Un taux eleve de NXDOMAIN peut indiquer un DGA." },
        { field: "query_length", description: "Longueur de la requete DNS. Les requetes avec des sous-domaines tres longs (>50 caracteres) sont suspectes de tunneling." }
      ]
    },
    {
      source: "Logs Active Directory / LDAP",
      description: "Journaux des controleurs de domaine Active Directory. Enregistrent les authentifications, les modifications d'objets et les operations de replication. Source critique pour la securite du domaine Windows.",
      keyFields: [
        { field: "EventCode 4662", description: "Acces a un objet AD. Permet de detecter les requetes DCSync (replication de hashes)." },
        { field: "EventCode 4768", description: "Demande de TGT Kerberos (Authentication Service). Utile pour la detection d'attaques AS-REP Roasting." },
        { field: "EventCode 4769", description: "Demande de TGS Kerberos (Ticket Granting Service). Utile pour detecter le Kerberoasting." },
        { field: "EventCode 4771", description: "Pre-authentification Kerberos echouee. Complement du 4625 pour les echecs d'authentification Kerberos." },
        { field: "EventCode 5136", description: "Modification d'objet AD. Permet de detecter les modifications de GPO, ajout de SPN, modifications suspectes." },
        { field: "EventCode 4756/4757", description: "Ajout/suppression de membre dans un groupe universel. Surveillance des groupes privilegies." }
      ]
    }
  ],

  // ===========================================================================
  // METRIQUES SOC CLES
  // ===========================================================================
  metrics: {
    description: "Les metriques cles pour evaluer la performance d'un SOC et sa capacite a detecter et repondre aux menaces.",
    kpis: [
      { name: "MTTD (Mean Time To Detect)", description: "Temps moyen entre le debut de l'attaque et sa detection. Objectif : moins de 24h. Meilleur indicateur de maturite de detection.", target: "< 24 heures" },
      { name: "MTTR (Mean Time To Respond)", description: "Temps moyen entre la detection et la resolution de l'incident. Inclut le triage, l'investigation et la remediation.", target: "< 4 heures pour les critiques" },
      { name: "MTTA (Mean Time To Acknowledge)", description: "Temps moyen entre la generation de l'alerte et sa prise en charge par un analyste.", target: "< 15 minutes" },
      { name: "Taux de faux positifs", description: "Pourcentage d'alertes qui s'averent etre des faux positifs apres investigation. Un taux trop eleve cause la fatigue des analystes.", target: "< 30%" },
      { name: "Couverture MITRE ATT&CK", description: "Pourcentage de techniques MITRE ATT&CK couvertes par au moins une regle de detection. Mesure la couverture de detection.", target: "> 60% des techniques prioritaires" },
      { name: "Volume d'alertes par analyste", description: "Nombre d'alertes a traiter par analyste par jour. Un volume trop eleve reduit la qualite de l'analyse.", target: "< 50 alertes/analyste/jour" }
    ]
  },

  // ===========================================================================
  // QUESTIONS D'ENTRETIEN SOC / MITRE FREQUENTES
  // ===========================================================================
  interviewQuestions: [
    {
      question: "Qu'est-ce que le framework MITRE ATT&CK et comment l'utilisez-vous au quotidien en SOC?",
      answer: "MITRE ATT&CK est une base de connaissances des tactiques et techniques d'attaque basee sur des observations reelles. Au quotidien en SOC, je l'utilise pour : 1) Mapper les alertes aux techniques ATT&CK pour comprendre ou en est l'attaquant dans sa progression. 2) Evaluer notre couverture de detection en identifiant les techniques non couvertes par nos regles. 3) Prioriser le developpement de nouvelles regles de detection. 4) Communiquer avec un langage commun lors des reunions d'incident. 5) Guider le threat hunting en ciblant les techniques les plus utilisees par les groupes menaçant notre secteur."
    },
    {
      question: "Quelle est la difference entre une tactique et une technique dans MITRE ATT&CK?",
      answer: "Une tactique represente le POURQUOI - l'objectif strategique de l'attaquant (ex: Persistence = maintenir l'acces). Une technique represente le COMMENT - la methode specifique utilisee pour atteindre cet objectif (ex: T1547 Boot or Logon Autostart Execution). Les sous-techniques precisent davantage (ex: T1547.001 Registry Run Keys). Une meme technique peut appartenir a plusieurs tactiques. Par exemple, T1053 Scheduled Task est a la fois une technique d'Execution et de Persistence."
    },
    {
      question: "Comment procedez-vous pour analyser une alerte en tant qu'analyste SOC L1?",
      answer: "1) Je prends l'alerte et note l'heure, la source et la severite. 2) Je lis la description de la regle pour comprendre ce qui est detecte. 3) Je contextualise : qui est l'utilisateur? Quel est le systeme? Est-ce un serveur critique? 4) J'enrichis avec des sources externes (reputation IP, VirusTotal pour les hashes). 5) Je verifie les logs complementaires (logs avant/apres l'alerte). 6) Je determine si c'est un vrai positif, faux positif ou benin. 7) Si vrai positif, j'applique le playbook de reponse ou j'escalade en L2. 8) Je documente toutes mes actions et conclusions dans le ticket."
    },
    {
      question: "Quels sont les Event IDs Windows les plus importants pour un analyste SOC?",
      answer: "Les Event IDs critiques sont : 4624/4625 (connexion reussie/echouee) pour tracer les authentifications, 4672 (privileges speciaux) pour les acces privilegies, 4720 (creation de compte) pour la persistance, 4728/4732 (ajout a un groupe) pour l'elevation de privileges, 7045 (service installe) pour la persistance, 1102 (journal efface) pour l'evasion, 4698 (tache planifiee creee) pour la persistance, et 4769 (ticket Kerberos) pour le Kerberoasting. Avec Sysmon, les Event IDs 1 (creation de processus), 3 (connexion reseau), 8 (CreateRemoteThread) et 10 (acces processus) sont essentiels."
    },
    {
      question: "Expliquez la difference entre la Cyber Kill Chain et MITRE ATT&CK.",
      answer: "La Cyber Kill Chain de Lockheed Martin est un modele lineaire en 7 etapes qui decrit la progression d'une attaque de la reconnaissance a l'impact. Elle est utile pour comprendre la vue d'ensemble strategique d'une attaque. MITRE ATT&CK est une matrice beaucoup plus detaillee avec 14 tactiques et des centaines de techniques basees sur des observations reelles. ATT&CK n'impose pas de linearite : un attaquant peut sauter des etapes ou revenir en arriere. ATT&CK est plus operationnel pour la detection quotidienne, tandis que la Kill Chain est meilleure pour la communication executive et la planification strategique. Les deux sont complementaires."
    },
    {
      question: "Comment detecteriez-vous une attaque de ransomware en cours?",
      answer: "Plusieurs indicateurs permettent de detecter un ransomware en cours : 1) Modification massive de fichiers en peu de temps (Sysmon Event ID 11 avec un meme processus touchant des centaines de fichiers). 2) Suppression des Volume Shadow Copies (vssadmin delete shadows). 3) Desactivation de Windows Defender ou de l'EDR. 4) Chiffrement de fichiers avec changement d'extensions (.encrypted, .locked). 5) Apparition de fichiers README ou notes de rancon. 6) Trafic C2 vers des IP connues de groupes ransomware. En Splunk, je surveillerais les commandes vssadmin, bcdedit, wbadmin et les modifications massives de fichiers avec des requetes statistiques."
    },
    {
      question: "Qu'est-ce que le concept de 'Living off the Land' (LOLBins)?",
      answer: "Living off the Land designe l'utilisation par les attaquants d'outils et binaires deja presents sur le systeme (LOLBins - Living Off the Land Binaries) au lieu d'installer des malwares dedies. Exemples : PowerShell pour l'execution de scripts, certutil.exe pour telecharger des fichiers, mshta.exe pour executer du HTA, rundll32.exe pour charger des DLL malveillantes, regsvr32.exe pour le proxy d'execution. L'avantage pour l'attaquant est que ces outils sont signes Microsoft et ne sont pas detectes comme malveillants par les antivirus. La detection repose sur l'analyse du contexte d'execution : qui lance quoi, avec quels arguments, et est-ce coherent avec l'utilisation normale?"
    },
    {
      question: "Chez Sopra Steria, l'approche cybersecurite est centree sur MITRE ATT&CK. Comment implementeriez-vous cela?",
      answer: "Pour centrer l'approche sur MITRE ATT&CK chez Sopra Steria : 1) Cartographier toutes les regles de detection existantes sur la matrice ATT&CK pour identifier la couverture actuelle. 2) Identifier les lacunes (techniques sans detection) et prioriser le developpement de nouvelles regles. 3) Utiliser ATT&CK Navigator pour visualiser la couverture et les priorites. 4) Integrer le mapping ATT&CK dans tous les tickets d'incident et rapports. 5) Baser le threat hunting sur les techniques les plus utilisees par les groupes ciblant nos clients (secteur bancaire, defense, etc.). 6) Mesurer regulierement l'evolution de la couverture comme KPI. 7) Utiliser les groupes d'attaquants documentes dans ATT&CK pour creer des scenarios de simulation (purple team)."
    }
  ]
};


// =============================================================================
// EXPORTS
// =============================================================================

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { mitreData, socData };
}
