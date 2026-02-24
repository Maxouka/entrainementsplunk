const splunkData = {

  // ============================================================
  // 1. ARCHITECTURE SPLUNK
  // ============================================================
  architecture: [
    {
      title: "Universal Forwarder (UF)",
      description: "Agent leger installe sur les machines sources (serveurs, postes de travail). Il collecte les logs bruts et les transmet aux Indexers ou Heavy Forwarders. Il ne fait AUCUN parsing ni transformation des donnees. C'est le composant le plus deploye dans une infrastructure Splunk. Consomme tres peu de ressources (CPU/RAM). Port d'ecoute par defaut : 9997 (envoi vers l'indexer).",
      icon: "📡"
    },
    {
      title: "Heavy Forwarder (HF)",
      description: "Forwarder avance capable de parser, filtrer et router les donnees AVANT de les envoyer a l'indexer. Utilise quand on veut masquer des donnees sensibles (ex: anonymiser des champs PII), filtrer du bruit, ou agir comme proxy de collecte. Consomme plus de ressources qu'un UF car il execute le parsing. Souvent place en DMZ pour collecter les logs de sources externes.",
      icon: "🔀"
    },
    {
      title: "Indexer",
      description: "Coeur du stockage Splunk. Il recoit les donnees des forwarders, les parse, les indexe et les stocke dans des index. Les donnees sont compressees et stockees dans des buckets (Hot -> Warm -> Cold -> Frozen -> Thawed). C'est l'indexer qui repond aux requetes de recherche du Search Head. Dans un cluster, plusieurs indexers travaillent ensemble avec un facteur de replication pour la haute disponibilite. Ports : 9997 (reception), 8089 (management).",
      icon: "💾"
    },
    {
      title: "Search Head (SH)",
      description: "Interface utilisateur principale de Splunk. C'est la ou les analystes SOC ecrivent leurs requetes SPL, creent des dashboards, configurent des alertes et menent leurs investigations. Le Search Head distribue les requetes aux indexers, recoit les resultats partiels et les fusionne. Dans un cluster Search Head, plusieurs SH partagent les configurations (saved searches, dashboards). Port web : 8000 (interface utilisateur), 8089 (API REST/management).",
      icon: "🔍"
    },
    {
      title: "Deployment Server (DS)",
      description: "Serveur de gestion centralise pour deployer et maintenir les configurations sur tous les forwarders. Permet de pousser des fichiers de configuration (inputs.conf, outputs.conf, etc.) vers des groupes de machines appeles 'Server Classes'. Essentiel dans les grands environnements avec des centaines ou milliers de forwarders. Evite de configurer chaque forwarder manuellement.",
      icon: "📦"
    },
    {
      title: "License Master",
      description: "Gere les licences Splunk et surveille le volume de donnees indexees quotidiennement. Splunk est licence par volume de donnees ingere par jour (ex: 100 Go/jour, 1 To/jour). Si le quota est depasse 5 fois en 30 jours, Splunk passe en mode restreint (recherche desactivee). Le License Master est critique pour le suivi des couts.",
      icon: "🔑"
    },
    {
      title: "Cluster Master / Manager Node",
      description: "Orchestre un cluster d'indexers. Gere la replication des donnees entre indexers (facteur de replication = nombre de copies des donnees brutes, facteur de recherche = nombre de copies des donnees indexees). Assure la haute disponibilite et la continuite de service en cas de panne d'un indexer. Renomme 'Manager Node' dans les versions recentes de Splunk.",
      icon: "👑"
    },
    {
      title: "SHC Deployer",
      description: "Deploie les configurations et knowledge objects (saved searches, dashboards, alertes) sur un cluster de Search Heads. Garantit que tous les Search Heads ont la meme configuration. Utilise le mecanisme de 'bundles' pour distribuer les apps et configurations.",
      icon: "🚀"
    }
  ],

  // ============================================================
  // 2. CONCEPTS FONDAMENTAUX
  // ============================================================
  concepts: [
    {
      term: "Index",
      definition: "Un index est un depot de donnees dans Splunk, equivalent a une base de donnees ou un schema. Les donnees sont separees par index pour des raisons de performance, de retention et de securite (controle d'acces par index). Chaque index a sa propre politique de retention. Les index par defaut sont : 'main' (donnees generales), '_internal' (logs internes Splunk), '_audit' (logs d'audit Splunk).",
      example: "index=main | index=security | index=network | index=windows | index=linux | index=firewall | index=proxy"
    },
    {
      term: "Sourcetype",
      definition: "Le sourcetype definit le FORMAT des donnees. Il indique a Splunk comment parser les evenements bruts : ou couper les lignes, comment extraire le timestamp, quels champs extraire automatiquement. C'est le parametre le plus important pour un parsing correct. Splunk inclut des centaines de sourcetypes pre-configures.",
      example: "sourcetype=WinEventLog:Security | sourcetype=syslog | sourcetype=access_combined | sourcetype=pan:traffic | sourcetype=cisco:asa | sourcetype=aws:cloudtrail | sourcetype=linux_secure"
    },
    {
      term: "Source",
      definition: "La source indique l'ORIGINE physique des donnees : chemin du fichier, nom du script, port reseau, etc. Permet d'identifier d'ou viennent exactement les donnees.",
      example: "source=/var/log/syslog | source=WinEventLog:Security | source=udp:514 | source=/var/log/apache2/access.log"
    },
    {
      term: "Host",
      definition: "Le champ host identifie la MACHINE qui a genere l'evenement. Correspond generalement au hostname du serveur ou du poste de travail. Champ essentiel pour l'investigation : permet d'isoler rapidement tous les logs d'une machine compromise.",
      example: "host=SERV-DC01 | host=WEB-PROD-01 | host=PC-FINANCE-042"
    },
    {
      term: "Field (Champ)",
      definition: "Un champ est une paire cle=valeur extraite des evenements. Certains champs sont extraits automatiquement (_time, _raw, host, source, sourcetype) et d'autres par le parsing du sourcetype. On peut aussi creer des champs personnalises avec eval ou rex. Les champs sont la base de toute analyse dans Splunk.",
      example: "src_ip=192.168.1.100 | dest_ip=10.0.0.5 | user=admin | action=allowed | EventCode=4625 | status=200"
    },
    {
      term: "Event (Evenement)",
      definition: "Un evenement est une entree individuelle dans Splunk : une ligne de log, un enregistrement. Chaque evenement a un timestamp (_time), un contenu brut (_raw) et des metadonnees (host, source, sourcetype, index). Un evenement peut etre une seule ligne ou multi-lignes (ex: stack trace Java).",
      example: "Un evenement typique : '2024-01-15 14:32:05 WARN Authentication failed for user admin from 192.168.1.100'"
    },
    {
      term: "Search Time vs Index Time",
      definition: "Index Time = moment ou les donnees sont ingerees et stockees. Les transformations Index Time sont appliquees une seule fois et ne peuvent pas etre modifiees apres coup (ex: suppression de champs sensibles). Search Time = moment ou un utilisateur lance une requete. Les extractions Search Time sont appliquees dynamiquement a chaque recherche. Splunk favorise le Search Time car c'est plus flexible. Regle d'or : faire le minimum a l'Index Time et le maximum au Search Time.",
      example: "Index Time : routing vers un index, transformation de donnees. Search Time : extraction de champs avec rex, lookups, calculs avec eval."
    },
    {
      term: "Knowledge Objects",
      definition: "Ensemble d'objets de configuration qui enrichissent les donnees dans Splunk : saved searches (requetes sauvegardees), reports (rapports planifies), alerts (alertes), dashboards (tableaux de bord), field extractions (extractions de champs), lookups (tables de correspondance), event types (types d'evenements), tags, macros, workflow actions. Ils sont partageables entre utilisateurs et apps.",
      example: "Une macro : `brute_force_detection(5,10)` | Un lookup : | lookup asset_list ip AS src_ip OUTPUT department, criticality"
    },
    {
      term: "Apps et Add-ons",
      definition: "Une App est un package complet avec interface utilisateur (dashboards, vues, navigations). Un Add-on (TA = Technology Add-on) fournit des inputs, des extractions de champs et des knowledge objects SANS interface. Splunkbase est le marketplace officiel. Apps essentielles pour un SOC : Splunk Enterprise Security (ES), Splunk SOAR, Splunk UBA, TA pour les sources de logs.",
      example: "Apps : Splunk Enterprise Security, IT Service Intelligence. Add-ons : Splunk Add-on for Microsoft Windows, Splunk Add-on for Palo Alto Networks."
    },
    {
      term: "Buckets (Stockage)",
      definition: "Les donnees dans un index passent par plusieurs etapes de stockage : Hot Bucket (ecriture active, stockage rapide SSD), Warm Bucket (lecture seule, toujours sur disque rapide), Cold Bucket (lecture seule, stockage moins cher), Frozen Bucket (archive ou suppression, hors de Splunk sauf SmartStore), Thawed Bucket (donnees restaurees depuis Frozen). La politique de retention definit combien de temps les donnees restent dans chaque phase.",
      example: "maxHotBuckets=10 | frozenTimePeriodInSecs=7776000 (90 jours) | coldPath=$SPLUNK_DB/security/colddb"
    },
    {
      term: "Role-Based Access Control (RBAC)",
      definition: "Splunk gere les acces par roles. Chaque role definit quels index sont accessibles, quelles commandes SPL sont autorisees, et quelles capacites sont attribuees. Roles par defaut : admin (acces total), power (creation de knowledge objects partages), user (recherche et dashboards prives). On peut creer des roles personnalises pour un SOC : soc_analyst_l1, soc_analyst_l2, soc_manager.",
      example: "Role soc_analyst_l1 : acces aux index security, windows, network. Pas d'acces a l'index hr_sensitive."
    },
    {
      term: "SPL (Search Processing Language)",
      definition: "Le langage de requete de Splunk. Syntaxe en pipe (|) similaire au shell Unix. La recherche commence toujours par une clause de recherche (index, sourcetype, mots-cles) puis enchaine des commandes de transformation. La premiere commande avant le premier pipe est implicitement une commande 'search'. SPL est le coeur du travail d'analyste SOC sur Splunk.",
      example: "index=security sourcetype=WinEventLog:Security EventCode=4625 | stats count by src_ip | sort -count | head 10"
    },
    {
      term: "CIM (Common Information Model)",
      definition: "Le CIM est un modele de donnees normalise par Splunk. Il definit des noms de champs standards pour differents types de donnees (Authentication, Network Traffic, Malware, etc.). Permet d'ecrire des requetes qui fonctionnent sur TOUTES les sources de donnees, quel que soit le vendeur. Essentiel pour Splunk Enterprise Security. Equivalent du concept de normalisation dans Rapid7.",
      example: "Au lieu de chercher 'EventCode=4625' (Windows specifique), on utilise le datamodel Authentication avec action=failure. Cela capte aussi les echecs SSH Linux, les echecs VPN, etc."
    },
    {
      term: "Data Models et Pivot",
      definition: "Un Data Model est une representation hierarchique et structuree des donnees indexees. Il s'appuie sur le CIM et permet de faire des recherches accelerees sans connaitre le SPL en detail. Pivot est l'interface graphique qui permet de creer des rapports et dashboards a partir de Data Models sans ecrire de SPL. Les Data Models sont acceleres pour des performances optimales.",
      example: "Le Data Model 'Authentication' contient les objets : Authentication, Successful_Authentication, Failed_Authentication avec des champs normalises (user, src, dest, action)."
    }
  ],

  // ============================================================
  // 3. COMMANDES SPL PAR CATEGORIE
  // ============================================================
  splCommands: [
    {
      category: "Recherche de base",
      commands: [
        {
          cmd: "search",
          syntax: "search <termes de recherche>",
          description: "Commande de base pour filtrer les evenements. Implicite au debut de chaque requete. Supporte les wildcards (*), les operateurs booleens (AND, OR, NOT), les comparaisons (=, !=, <, >, >=, <=). Les mots-cles sont sensibles a la casse pour les valeurs, pas pour les operateurs.",
          example: "index=security sourcetype=WinEventLog:Security EventCode=4625 NOT user=SYSTEM src_ip=192.168.* | search action=failure"
        },
        {
          cmd: "fields",
          syntax: "| fields [+|-] <champ1> <champ2> ...",
          description: "Selectionne ou exclut des champs du resultat. Avec '+' on inclut (par defaut), avec '-' on exclut. Ameliore les performances en reduisant les donnees transmises. Toujours utiliser tot dans la requete pour optimiser.",
          example: "index=security EventCode=4625 | fields src_ip, dest, user, _time | fields - _raw, _indextime"
        },
        {
          cmd: "rex",
          syntax: "| rex field=<champ> \"(?P<nouveau_champ>regex)\"",
          description: "Extraction de champs a la volee avec des expressions regulieres (regex). Utilise la syntaxe des groupes nommes Python. Tres utile quand les champs ne sont pas extraits automatiquement par le sourcetype. Mode sed disponible aussi pour remplacer du texte.",
          example: "index=proxy | rex field=url \"https?://(?P<domain>[^/]+)\" | stats count by domain | sort -count"
        },
        {
          cmd: "regex",
          syntax: "| regex <champ>=<regex> ou | regex <champ>!=<regex>",
          description: "Filtre les evenements qui matchent (ou ne matchent pas) une expression reguliere. Contrairement a rex, regex ne cree pas de champ, il filtre seulement. Plus puissant que 'search' pour le filtrage par pattern complexe.",
          example: "index=security | regex src_ip!=\"^10\\.\" | regex user=\"^(admin|root|Administrator)$\""
        }
      ]
    },
    {
      category: "Filtrage et transformation",
      commands: [
        {
          cmd: "where",
          syntax: "| where <expression>",
          description: "Filtre les resultats avec des expressions evaluees. Plus puissant que 'search' car supporte les fonctions (len(), like(), cidrmatch(), etc.) et les comparaisons de champs entre eux. Traite les valeurs null differemment de search. Sensible a la casse par defaut.",
          example: "index=security EventCode=4625 | stats count by src_ip | where count > 50\n\n... | where like(user, \"admin%\")\n... | where cidrmatch(\"10.0.0.0/8\", src_ip)\n... | where len(query) > 100"
        },
        {
          cmd: "stats",
          syntax: "| stats <fonctions> by <champs>",
          description: "Commande d'agregation LA PLUS IMPORTANTE de Splunk. Calcule des statistiques sur les evenements. Fonctions : count, dc (distinct count), sum, avg, min, max, values, list, first, last, earliest, latest, median, stdev, perc<N>. Supprime les evenements bruts et produit une table de resultats.",
          example: "index=security EventCode=4625 | stats count AS tentatives, dc(Account_Name) AS comptes_uniques, values(Account_Name) AS comptes_cibles by src_ip | sort -tentatives"
        },
        {
          cmd: "eval",
          syntax: "| eval <champ>=<expression>",
          description: "Cree ou modifie des champs avec des expressions calculees. Supporte : arithmetique (+,-,*,/,%), concatenation (.), conditions (if/case), fonctions de chaine (lower, upper, len, substr, replace, split, mvindex), fonctions de temps (now(), relative_time(), strftime(), strptime()), fonctions reseau (cidrmatch), et bien plus. Essentiel pour enrichir les donnees.",
          example: "... | eval severity=if(count>100, \"critique\", if(count>50, \"haute\", \"moyenne\"))\n... | eval duree_minutes=round((end_time - start_time)/60, 2)\n... | eval domain=lower(mvindex(split(email, \"@\"), 1))\n... | eval is_internal=if(cidrmatch(\"10.0.0.0/8\", src_ip), \"oui\", \"non\")"
        },
        {
          cmd: "table",
          syntax: "| table <champ1> <champ2> ...",
          description: "Formate les resultats en tableau avec uniquement les champs specifies, dans l'ordre specifie. Contrairement a 'fields', 'table' reformate completement l'affichage. A utiliser en fin de requete pour presenter les resultats.",
          example: "index=security EventCode=4625 | stats count by src_ip, user | sort -count | table src_ip, user, count"
        },
        {
          cmd: "rename",
          syntax: "| rename <ancien> AS <nouveau>",
          description: "Renomme des champs pour un affichage plus lisible. Supporte les wildcards. Utile pour les dashboards et rapports partages avec des non-techniciens.",
          example: "... | rename src_ip AS \"IP Source\", dest_ip AS \"IP Destination\", count AS \"Nombre de tentatives\"\n... | rename DomainController_* AS DC_*"
        },
        {
          cmd: "sort",
          syntax: "| sort [+|-]<champ> [limit=N]",
          description: "Trie les resultats. Le prefixe '-' trie en ordre decroissant, '+' en ordre croissant (defaut). On peut trier sur plusieurs champs. Par defaut, limite a 10000 resultats.",
          example: "... | sort -count, +user | head 20\n... | sort 0 -_time  (le '0' retire la limite de 10000)"
        },
        {
          cmd: "dedup",
          syntax: "| dedup [N] <champ1> [champ2] [sortby ...]",
          description: "Supprime les evenements dupliques base sur les valeurs de champs specifies. Garde par defaut le premier evenement rencontre (le plus recent si les donnees sont triees par temps). Le parametre N permet de garder les N premiers de chaque groupe.",
          example: "index=security EventCode=4624 | dedup user, src_ip | table _time, user, src_ip, Logon_Type\n... | dedup 3 user sortby -_time"
        },
        {
          cmd: "top",
          syntax: "| top [limit=N] [showperc=t|f] <champ> [by <champ2>]",
          description: "Affiche les N valeurs les plus frequentes d'un champ. Retourne automatiquement count et percent. Equivalent raccourci de '| stats count by champ | sort -count | head N'.",
          example: "index=security EventCode=4625 | top limit=10 src_ip\nindex=proxy | top limit=5 url by src_ip showperc=f"
        },
        {
          cmd: "rare",
          syntax: "| rare [limit=N] <champ> [by <champ2>]",
          description: "Inverse de 'top' : affiche les valeurs les MOINS frequentes. Tres utile en securite pour detecter les anomalies et les comportements inhabituels (user-agent rare, port inhabituel, etc.).",
          example: "index=proxy | rare useragent limit=20\nindex=network | rare dest_port by src_ip"
        },
        {
          cmd: "head / tail",
          syntax: "| head N / | tail N",
          description: "head : garde les N premiers resultats. tail : garde les N derniers resultats. Simple et rapide pour limiter l'affichage.",
          example: "index=security | stats count by user | sort -count | head 10\nindex=security | sort _time | tail 5"
        },
        {
          cmd: "fillnull",
          syntax: "| fillnull [value=X] [champ1 champ2]",
          description: "Remplace les valeurs null/manquantes par une valeur specifiee. Par defaut remplace par une chaine vide. Utile pour nettoyer les resultats avant un export ou un dashboard.",
          example: "... | fillnull value=\"N/A\" department, manager\n... | fillnull value=0 bytes_out"
        },
        {
          cmd: "iplocation",
          syntax: "| iplocation <champ_ip>",
          description: "Enrichit un champ d'adresse IP avec des informations de geolocalisation (Country, City, Region, lat, lon). Utilise la base GeoIP MaxMind integree. Tres utile pour les dashboards de geolocalisation des attaques.",
          example: "index=security EventCode=4625 | iplocation src_ip | stats count by src_ip, Country, City | sort -count"
        }
      ]
    },
    {
      category: "Analyse temporelle",
      commands: [
        {
          cmd: "timechart",
          syntax: "| timechart [span=<intervalle>] <fonction> [by <champ>]",
          description: "Cree une serie temporelle. L'axe X est toujours le temps (_time). Chaque ligne ou barre represente une serie definie par 'by'. Ideal pour visualiser les tendances, les pics d'activite, les patterns. Le span definit la granularite (1m, 5m, 1h, 1d, etc.). C'est LA commande pour les graphiques temporels.",
          example: "index=security EventCode=4625 | timechart span=1h count by src_ip\nindex=network | timechart span=5m avg(bytes) by dest_port\nindex=proxy | timechart span=15m dc(src_ip) AS utilisateurs_uniques"
        },
        {
          cmd: "chart",
          syntax: "| chart <fonction> over <champ_x> [by <champ_serie>]",
          description: "Similaire a timechart mais l'axe X peut etre n'importe quel champ (pas seulement le temps). Permet de creer des graphiques a barres, camemberts, etc. Le 'over' definit l'axe X et le 'by' definit les series.",
          example: "index=security EventCode=4625 | chart count over src_ip by Logon_Type\nindex=proxy | chart sum(bytes) over department by action"
        },
        {
          cmd: "bin (anciennement bucket)",
          syntax: "| bin <champ> [span=<intervalle>] [bins=<nombre>]",
          description: "Regroupe les valeurs numeriques ou temporelles en intervalles (buckets). Souvent utilise avec _time pour creer des fenetres temporelles avant un stats. Peut aussi regrouper des valeurs numeriques continues.",
          example: "index=security EventCode=4625 | bin _time span=5m | stats count by _time, src_ip | where count > 10\n... | bin bytes span=1000 | stats count by bytes"
        },
        {
          cmd: "earliest / latest (modificateurs de temps)",
          syntax: "earliest=<temps> latest=<temps>",
          description: "Filtres temporels dans la clause de recherche. Formats : -1h (1 heure avant), -7d@d (7 jours avant, arrondi au debut du jour), -1mon@mon (debut du mois dernier). Les time modifiers au debut de la requete optimisent les performances car ils limitent les buckets a scanner. Toujours preferer ces modificateurs au time picker quand possible.",
          example: "index=security earliest=-24h latest=now() EventCode=4625\nindex=security earliest=-7d@d latest=@d (les 7 derniers jours complets)\nindex=security earliest=01/15/2024:00:00:00 latest=01/16/2024:00:00:00"
        },
        {
          cmd: "predict",
          syntax: "| predict <champ> [future_timespan=<N>] [algorithm=<algo>]",
          description: "Predit les valeurs futures d'un champ base sur les tendances passees. Algorithmes disponibles : LLP, LLP5, LLT, LLT5, LLB, LLB5. Utile pour detecter les anomalies (valeurs reelles hors de l'intervalle de confiance).",
          example: "index=network | timechart span=1h sum(bytes) AS trafic | predict trafic future_timespan=24"
        }
      ]
    },
    {
      category: "Commandes avancees",
      commands: [
        {
          cmd: "eventstats",
          syntax: "| eventstats <fonctions> [by <champs>]",
          description: "Comme 'stats' mais CONSERVE les evenements originaux en ajoutant les resultats statistiques comme nouveaux champs. Permet de comparer chaque evenement a la statistique globale. Tres puissant pour detecter les anomalies.",
          example: "index=proxy | stats sum(bytes) AS total_bytes by src_ip | eventstats avg(total_bytes) AS moyenne, stdev(total_bytes) AS ecart_type | eval zscore=(total_bytes - moyenne) / ecart_type | where zscore > 3 | table src_ip, total_bytes, moyenne, zscore"
        },
        {
          cmd: "streamstats",
          syntax: "| streamstats [window=N] [current=t|f] <fonctions> [by <champs>]",
          description: "Calcule des statistiques cumulatives ou glissantes en parcourant les evenements dans l'ordre. Chaque evenement recoit un calcul base sur lui-meme et les evenements precedents. Parfait pour : calcul de moyenne mobile, detection de sequences, compteurs cumulatifs, detection de changements de comportement.",
          example: "index=network src_ip=10.0.0.50 | sort _time | streamstats window=10 avg(bytes) AS avg_bytes, stdev(bytes) AS stdev_bytes | eval anomaly=if(bytes > avg_bytes + 2*stdev_bytes, \"OUI\", \"NON\")\n\n... | sort _time | streamstats count AS sequence_num by session_id"
        },
        {
          cmd: "transaction",
          syntax: "| transaction <champs> [maxspan=<duree>] [maxpause=<duree>] [startswith=<condition>] [endswith=<condition>]",
          description: "Regroupe les evenements en transactions basees sur des champs communs et des contraintes temporelles. Cree un champ 'duration' (duree de la transaction) et 'eventcount' (nombre d'evenements). ATTENTION : tres couteux en ressources, preferer stats quand possible.",
          example: "index=web | transaction session_id maxspan=30m maxpause=5m | table session_id, duration, eventcount\n\nindex=security | transaction src_ip maxspan=1h startswith=(EventCode=4624) endswith=(EventCode=4634) | eval duree_session_min=round(duration/60,2)"
        },
        {
          cmd: "join",
          syntax: "| join [type=inner|outer|left] <champ_commun> [subsearch]",
          description: "Fusionne les resultats de deux recherches basees sur un champ commun. Similaire au JOIN SQL. ATTENTION : limite a 50000 lignes par defaut cote subsearch. Preferer 'stats' ou 'lookup' quand possible pour de meilleures performances. Types : inner (defaut, intersection), outer (union), left (tout le cote gauche).",
          example: "index=security EventCode=4625 | stats count AS echecs by src_ip | join src_ip [search index=security EventCode=4624 | stats count AS reussites by src_ip] | eval ratio=round(echecs/(echecs+reussites)*100,2) | table src_ip, echecs, reussites, ratio"
        },
        {
          cmd: "lookup",
          syntax: "| lookup <nom_lookup> <champ_lookup> [AS <champ_local>] OUTPUT <champs_sortie>",
          description: "Enrichit les evenements avec des donnees externes provenant d'un fichier CSV ou d'une connexion KV Store. Equivalent des tables de reference. Essentiel pour : listes d'assets, informations utilisateur, listes de menaces (threat intel), correspondance GeoIP personnalisee. Le fichier CSV doit etre charge dans Splunk au prealable.",
          example: "index=security EventCode=4625 | lookup asset_inventory ip AS src_ip OUTPUT hostname, department, criticality | stats count by src_ip, hostname, department, criticality | sort -count\n\n... | lookup threat_intel_ioc ip AS dest_ip OUTPUT threat_type, confidence | where isnotnull(threat_type)"
        },
        {
          cmd: "inputlookup",
          syntax: "| inputlookup <nom_lookup> [where <condition>]",
          description: "Charge directement le contenu d'un fichier lookup comme source de donnees (sans joindre a des evenements). Utile pour consulter des listes de reference, des inventaires, des listes blanches/noires.",
          example: "| inputlookup threat_intel_ioc | where threat_type=\"malware\" | table ip, domain, threat_type, last_seen\n| inputlookup asset_inventory | stats count by department, criticality"
        },
        {
          cmd: "outputlookup",
          syntax: "| outputlookup <nom_lookup> [append=t]",
          description: "Ecrit les resultats d'une recherche dans un fichier lookup. Permet de creer ou mettre a jour des tables de reference dynamiquement. Avec append=t, ajoute aux donnees existantes au lieu de les remplacer.",
          example: "index=security EventCode=4625 | stats count by src_ip | where count > 100 | outputlookup suspicious_ips.csv"
        },
        {
          cmd: "subsearch",
          syntax: "[search ... | fields champ | format]",
          description: "Une recherche imbriquee entre crochets dont le resultat est utilise comme filtre dans la recherche principale. Le subsearch s'execute EN PREMIER et ses resultats sont injectes dans la requete principale. Limite a 10000 resultats et 60 secondes par defaut.",
          example: "index=security EventCode=4624 [search index=security EventCode=4625 | stats count by src_ip | where count > 50 | fields src_ip] | stats count by src_ip, user, Logon_Type"
        },
        {
          cmd: "append",
          syntax: "| append [subsearch]",
          description: "Ajoute les resultats d'une sous-recherche a la fin des resultats courants. Contrairement a join qui fusionne horizontalement (ajout de colonnes), append empile verticalement (ajout de lignes).",
          example: "index=security EventCode=4625 | stats count AS echecs by src_ip | append [search index=security EventCode=4624 | stats count AS succes by src_ip] | stats first(echecs) AS echecs, first(succes) AS succes by src_ip"
        },
        {
          cmd: "map",
          syntax: "| map search=\"<requete>\" [maxsearches=N]",
          description: "Execute une recherche pour chaque resultat de la recherche precedente. Equivalent d'une boucle for. Le '$' permet de referencer les champs du resultat precedent. ATTENTION : tres couteux, limite a 10 recherches par defaut.",
          example: "index=security EventCode=4625 | stats count by src_ip | where count > 20 | head 5 | map search=\"search index=security src_ip=$src_ip$ EventCode=4624 | stats count AS succes, values(user) AS users\""
        },
        {
          cmd: "multisearch",
          syntax: "| multisearch [search ...] [search ...]",
          description: "Execute plusieurs recherches en parallele et combine les resultats. Plus performant que 'append' car les recherches s'executent simultanement.",
          example: "| multisearch [search index=security EventCode=4625 | stats count AS brute_force] [search index=security EventCode=4720 | stats count AS new_accounts] [search index=security EventCode=1102 | stats count AS logs_effaces]"
        },
        {
          cmd: "foreach",
          syntax: "| foreach <champs> [eval <<FIELD>>=...]",
          description: "Applique une operation identique a plusieurs champs. Utile quand on doit transformer de nombreux champs de la meme facon. <<FIELD>> est remplace par le nom de chaque champ.",
          example: "... | foreach bytes_in, bytes_out [eval <<FIELD>>_mb=round(<<FIELD>>/1024/1024, 2)]"
        },
        {
          cmd: "tstats",
          syntax: "| tstats <fonctions> from datamodel=<modele> where <conditions> by <champs>",
          description: "Version ultra-rapide de stats qui interroge les data models acceleres (tsidx). 10 a 100x plus rapide que stats sur les memes donnees. Utilise massivement dans Splunk Enterprise Security. C'est la commande privilegiee pour les recherches de correlation et les dashboards performants.",
          example: "| tstats count from datamodel=Authentication where Authentication.action=failure by Authentication.src, Authentication.user, _time span=5m | rename Authentication.* AS *"
        },
        {
          cmd: "collect",
          syntax: "| collect index=<index> sourcetype=<sourcetype>",
          description: "Ecrit les resultats d'une recherche dans un index Splunk. Permet de creer des donnees derivees, des summary indexes pour des rapports plus rapides. Utilise dans les scheduled searches pour pre-calculer des statistiques.",
          example: "index=security EventCode=4625 | stats count by src_ip, _time | where count > 10 | collect index=summary sourcetype=brute_force_summary"
        }
      ]
    },
    {
      category: "Formattage et visualisation",
      commands: [
        {
          cmd: "convert",
          syntax: "| convert <fonction>(<champ>)",
          description: "Convertit les types de champs. Fonctions : ctime (epoch vers date lisible), mktime (date vers epoch), dur2sec (duree vers secondes), auto (conversion automatique).",
          example: "... | convert ctime(_time) AS date_lisible\n... | convert dur2sec(duration) AS duree_secondes"
        },
        {
          cmd: "addtotals",
          syntax: "| addtotals [row=t|f] [col=t|f] [fieldname=<nom>]",
          description: "Ajoute des totaux par ligne et/ou colonne. Utile pour les tableaux recapitulatifs dans les dashboards.",
          example: "... | chart count by department, severity | addtotals col=t fieldname=\"TOTAL\""
        },
        {
          cmd: "xyseries",
          syntax: "| xyseries <champ_x> <champ_nom_serie> <champ_valeur>",
          description: "Transforme un resultat de stats en format tableau croise (pivot). Convertit les lignes en colonnes.",
          example: "... | stats count by src_ip, dest_port | xyseries src_ip dest_port count"
        },
        {
          cmd: "trendline",
          syntax: "| trendline <type><periode>(<champ>) AS <alias>",
          description: "Calcule une ligne de tendance (moyenne mobile). Types : sma (simple), ema (exponentiel), wma (pondere). Utile pour lisser les courbes dans les dashboards.",
          example: "... | timechart span=1h count | trendline sma5(count) AS tendance"
        }
      ]
    }
  ],

  // ============================================================
  // 4. EXERCICES PRATIQUES SOC
  // ============================================================
  exercises: [
    {
      title: "Detection de brute force",
      scenario: "Le SOC recoit une alerte de tentatives de connexion multiples echouees. Vous devez identifier les IPs sources qui effectuent du brute force sur les comptes Windows Active Directory dans les dernieres 24 heures.",
      hint: "Pensez a l'EventCode 4625 (Logon Failure) dans les logs Windows Security. Regroupez par IP source et fenetre temporelle pour identifier les attaques concentrees.",
      solution: "index=security sourcetype=WinEventLog:Security EventCode=4625 earliest=-24h\n| bin _time span=5m\n| stats count AS tentatives, dc(Account_Name) AS comptes_cibles, values(Account_Name) AS liste_comptes by _time, src_ip\n| where tentatives > 10\n| sort -tentatives\n| table _time, src_ip, tentatives, comptes_cibles, liste_comptes\n| iplocation src_ip\n| rename src_ip AS \"IP Source\", tentatives AS \"Tentatives\", comptes_cibles AS \"Comptes cibles uniques\", Country AS \"Pays\"",
      explanation: "EventCode 4625 = echec de connexion Windows. On regroupe par fenetres de 5 minutes et IP source avec bin + stats. dc() compte les comptes distincts cibles (un brute force cible souvent plusieurs comptes). values() liste les comptes cibles. Le seuil de 10 tentatives par 5 minutes est un indicateur de brute force. iplocation enrichit avec la geolocalisation."
    },
    {
      title: "Detection de mouvement lateral",
      scenario: "Apres une compromission initiale, un attaquant se deplace lateralement dans le reseau. Vous devez detecter les connexions reseau (Logon Type 3) inhabituelles entre postes de travail, surtout celles utilisant des comptes privilegies.",
      hint: "EventCode 4624 (Logon Success) avec Logon_Type=3 (Network Logon). Filtrez les connexions normales (serveurs vers DC, etc.) et concentrez-vous sur les connexions workstation-to-workstation.",
      solution: "index=security sourcetype=WinEventLog:Security EventCode=4624 Logon_Type=3 earliest=-24h\n| where NOT match(Account_Name, \"^(SYSTEM|ANONYMOUS LOGON|DWM-|UMFD-)\")\n| where NOT match(Account_Name, \"\\$$\")\n| eval src_host=lower(Source_Network_Address), dest_host=lower(host)\n| where src_host != dest_host\n| stats count, dc(dest_host) AS destinations_uniques, values(dest_host) AS machines_accedees, earliest(_time) AS premiere_connexion, latest(_time) AS derniere_connexion by Account_Name, src_host\n| where destinations_uniques > 3\n| convert ctime(premiere_connexion) AS premiere, ctime(derniere_connexion) AS derniere\n| sort -destinations_uniques\n| table Account_Name, src_host, destinations_uniques, machines_accedees, count, premiere, derniere",
      explanation: "Logon_Type=3 = connexion reseau (partage de fichiers, PsExec, WMI, etc.). On exclut les comptes systeme (SYSTEM, comptes machine '$') qui generent du bruit. Le mouvement lateral se detecte par un meme compte se connectant a PLUSIEURS machines depuis une seule source. Le seuil de 3+ destinations est un bon indicateur. Un attaquant utilisant PsExec, WMI ou RDP generera ces evenements."
    },
    {
      title: "Execution PowerShell suspecte",
      scenario: "L'equipe de threat intelligence signale une campagne utilisant des scripts PowerShell obfusques. Vous devez identifier les executions PowerShell suspectes contenant des patterns d'obfuscation ou des commandes dangereuses.",
      hint: "EventCode 4104 (Script Block Logging) capture le contenu des scripts PowerShell. Cherchez des patterns d'obfuscation comme -enc, base64, IEX, Invoke-Expression, downloadstring, etc.",
      solution: "index=security sourcetype=WinEventLog:Security EventCode=4104 earliest=-7d\n| eval script_lower=lower(ScriptBlockText)\n| eval suspicious_indicators=0\n| eval suspicious_indicators=if(match(script_lower, \"invoke-expression|iex\\s*\\(\"), suspicious_indicators+1, suspicious_indicators)\n| eval suspicious_indicators=if(match(script_lower, \"downloadstring|downloadfile|webclient|net\\.webclient\"), suspicious_indicators+1, suspicious_indicators)\n| eval suspicious_indicators=if(match(script_lower, \"frombase64string|convert.*base64|-enc\\s+-\"), suspicious_indicators+1, suspicious_indicators)\n| eval suspicious_indicators=if(match(script_lower, \"invoke-mimikatz|invoke-shellcode|invoke-obfuscation\"), suspicious_indicators+3, suspicious_indicators)\n| eval suspicious_indicators=if(match(script_lower, \"bypass|unrestricted|hidden|noninteractive\"), suspicious_indicators+1, suspicious_indicators)\n| eval suspicious_indicators=if(match(script_lower, \"add-type.*dllimport|reflection\\.assembly\"), suspicious_indicators+2, suspicious_indicators)\n| where suspicious_indicators >= 2\n| sort -suspicious_indicators\n| table _time, host, UserID, suspicious_indicators, ScriptBlockText\n| rename suspicious_indicators AS \"Score de suspicion\"",
      explanation: "EventCode 4104 (PowerShell Script Block Logging) enregistre le contenu COMPLET des scripts PowerShell, meme obfusques (Splunk recoit le contenu decode). On cree un systeme de scoring : chaque pattern suspect incremente le score. Les outils offensifs connus (Mimikatz, Shellcode) donnent un score plus eleve. Un score >= 2 indique une activite probablement malveillante. Cette approche reduit les faux positifs car un seul indicateur peut etre legitime."
    },
    {
      title: "Exfiltration DNS",
      scenario: "Vous suspectez qu'un malware utilise le protocole DNS pour exfiltrer des donnees. Les donnees sont encodees dans les sous-domaines des requetes DNS. Detectez les requetes DNS anormalement longues ou frequentes vers des domaines suspects.",
      hint: "Les requetes DNS legitimes ont rarement des sous-domaines tres longs. Un domaine d'exfiltration aura des patterns comme 'aGVsbG8gd29ybGQ=.evil.com'. Cherchez les requetes avec un nombre eleve de caracteres ou un ratio de caracteres inhabituels.",
      solution: "index=network sourcetype=stream:dns OR sourcetype=dns query_type=A earliest=-24h\n| eval query_length=len(query)\n| eval subdomain=mvindex(split(query, \".\"), 0)\n| eval subdomain_length=len(subdomain)\n| eval entropy=0\n| eval has_numbers=if(match(subdomain, \"[0-9]\"), 1, 0)\n| eval base64_chars=if(match(subdomain, \"[A-Za-z0-9+/=]{20,}\"), 1, 0)\n| where query_length > 50 OR subdomain_length > 30 OR base64_chars=1\n| stats count AS requetes, dc(query) AS domaines_uniques, avg(query_length) AS longueur_moyenne, values(query) AS exemples_requetes by src_ip\n| where requetes > 100 OR domaines_uniques > 50\n| eval longueur_moyenne=round(longueur_moyenne, 1)\n| sort -requetes\n| table src_ip, requetes, domaines_uniques, longueur_moyenne, exemples_requetes",
      explanation: "L'exfiltration DNS encode les donnees volees dans les sous-domaines (ex: base64). Les indicateurs sont : longueur de requete > 50 caracteres (normal = ~20-30), sous-domaines > 30 caracteres, patterns base64, et un volume eleve de requetes vers un meme domaine de second niveau. On combine la detection par longueur et par volume pour reduire les faux positifs. Les CDN et services cloud peuvent generer des faux positifs (filtrer les domaines connus)."
    },
    {
      title: "Escalade de privileges",
      scenario: "Detectez les cas ou un utilisateur normal recoit des privileges administrateurs ou est ajoute a un groupe sensible (Domain Admins, Enterprise Admins, Administrators, etc.).",
      hint: "EventCode 4672 (Special privileges assigned to new logon), EventCode 4728/4732/4756 (membre ajoute a un groupe). Concentrez-vous sur les groupes sensibles et les heures hors bureau.",
      solution: "index=security sourcetype=WinEventLog:Security (EventCode=4728 OR EventCode=4732 OR EventCode=4756) earliest=-7d\n| eval group_type=case(\n    EventCode=4728, \"Groupe global\",\n    EventCode=4732, \"Groupe local\",\n    EventCode=4756, \"Groupe universel\"\n)\n| search Group_Name IN (\"Domain Admins\", \"Enterprise Admins\", \"Schema Admins\", \"Administrators\", \"Administrateurs\", \"Admins du domaine\", \"Account Operators\", \"Backup Operators\", \"Server Operators\")\n| eval heure=strftime(_time, \"%H\")\n| eval hors_bureau=if(heure<7 OR heure>20, \"OUI\", \"NON\")\n| table _time, host, SubjectUserName, MemberName, Group_Name, group_type, hors_bureau\n| rename SubjectUserName AS \"Modifie par\", MemberName AS \"Utilisateur ajoute\", Group_Name AS \"Groupe\", hors_bureau AS \"Hors heures bureau\"\n| sort -_time",
      explanation: "EventCode 4728 = ajout dans un groupe global de securite, 4732 = groupe local, 4756 = groupe universel. On filtre les groupes a hauts privileges. L'indicateur 'hors_bureau' aide a detecter les modifications suspectes en dehors des heures normales. Un attaquant ayant compromis un compte admin va souvent s'ajouter (ou ajouter un compte controle) a un groupe privilegies pour maintenir son acces."
    },
    {
      title: "Detection de beaconing (communication C2)",
      scenario: "Un malware communique avec son serveur C2 (Command & Control) a intervalles reguliers. Ce pattern de 'beaconing' est caracteristique des malwares. Detectez les communications reseau avec des intervalles reguliers vers des destinations externes.",
      hint: "Le beaconing se caracterise par des connexions a intervalles tres reguliers (ex: toutes les 60 secondes +/- quelques secondes). Calculez l'ecart-type des intervalles entre les connexions vers chaque destination.",
      solution: "index=network sourcetype=firewall action=allowed dest_port=443 OR dest_port=80 earliest=-24h\n| where NOT cidrmatch(\"10.0.0.0/8\", dest_ip) AND NOT cidrmatch(\"172.16.0.0/12\", dest_ip) AND NOT cidrmatch(\"192.168.0.0/16\", dest_ip)\n| sort 0 src_ip, dest_ip, _time\n| streamstats current=f window=1 latest(_time) AS prev_time by src_ip, dest_ip\n| eval interval=_time - prev_time\n| where isnotnull(interval) AND interval > 0 AND interval < 3600\n| stats count AS connexions, avg(interval) AS intervalle_moyen, stdev(interval) AS ecart_type, min(interval) AS min_interval, max(interval) AS max_interval by src_ip, dest_ip\n| where connexions > 20\n| eval coefficient_variation=round((ecart_type/intervalle_moyen)*100, 2)\n| where coefficient_variation < 15\n| eval intervalle_moyen=round(intervalle_moyen, 1)\n| eval ecart_type=round(ecart_type, 2)\n| sort coefficient_variation\n| table src_ip, dest_ip, connexions, intervalle_moyen, ecart_type, coefficient_variation\n| rename coefficient_variation AS \"CV (%)\" , intervalle_moyen AS \"Intervalle moyen (s)\", ecart_type AS \"Ecart-type (s)\"",
      explanation: "Le beaconing est detecte par la REGULARITE des intervalles entre connexions. On calcule le coefficient de variation (CV = ecart-type / moyenne * 100). Un CV < 15% indique des intervalles tres reguliers = probablement un beacon automatise. Un humain naviguant genererait un CV > 50%. streamstats avec window=1 permet de calculer l'intervalle entre chaque connexion consecutive. On exclut les IPs privees (destinations internes) et on requiert un minimum de connexions pour la fiabilite statistique."
    },
    {
      title: "Creation et modification de comptes",
      scenario: "Surveillez la creation de nouveaux comptes utilisateurs et les modifications suspectes (reactivation de comptes desactives, changement de mot de passe par un autre utilisateur). Ces activites peuvent indiquer une persistance d'attaquant.",
      hint: "EventCode 4720 (creation de compte), EventCode 4738 (modification de compte), EventCode 4722 (compte active), EventCode 4724 (reset de mot de passe). Croisez avec les heures et les auteurs des modifications.",
      solution: "index=security sourcetype=WinEventLog:Security (EventCode=4720 OR EventCode=4722 OR EventCode=4724 OR EventCode=4725 OR EventCode=4726 OR EventCode=4738) earliest=-7d\n| eval action=case(\n    EventCode=4720, \"Compte cree\",\n    EventCode=4722, \"Compte active\",\n    EventCode=4724, \"Mot de passe reinitialise\",\n    EventCode=4725, \"Compte desactive\",\n    EventCode=4726, \"Compte supprime\",\n    EventCode=4738, \"Compte modifie\"\n)\n| eval heure=strftime(_time, \"%H:%M\")\n| eval jour=strftime(_time, \"%A\")\n| eval suspect=if(\n    (EventCode=4720 AND NOT match(SubjectUserName, \"^(svc_|SYSTEM)\")) OR\n    (EventCode=4722 AND match(TargetUserName, \"(admin|test|temp)\")) OR\n    (EventCode=4724 AND SubjectUserName!=TargetUserName),\n    \"OUI\", \"NON\"\n)\n| table _time, heure, jour, action, SubjectUserName, TargetUserName, host, suspect\n| rename SubjectUserName AS \"Effectue par\", TargetUserName AS \"Compte cible\", suspect AS \"Suspect\"\n| sort -_time",
      explanation: "On surveille le cycle de vie complet des comptes. Les indicateurs suspects sont : creation de compte par un non-service account, activation d'un compte avec des noms suspects (admin, test, temp), et reinitialisation de mot de passe par un AUTRE utilisateur (SubjectUserName != TargetUserName). Un attaquant cree souvent un compte backdoor ou reactive un compte desactive pour maintenir son acces."
    },
    {
      title: "Installation de services suspects",
      scenario: "Un attaquant ayant obtenu des privileges administrateur installe souvent un service Windows malveillant pour la persistance. Detectez les installations de nouveaux services, en particulier ceux executant des binaires depuis des emplacements inhabituels.",
      hint: "EventCode 7045 (nouveau service installe) dans le log System. Concentrez-vous sur les services dont le chemin d'execution n'est pas dans les repertoires systeme standards.",
      solution: "index=security sourcetype=WinEventLog:System EventCode=7045 earliest=-7d\n| eval service_path=lower(ImagePath)\n| eval suspicious_path=if(\n    NOT match(service_path, \"^(c:\\\\windows\\\\|c:\\\\program files|c:\\\\programdata\\\\microsoft)\"),\n    \"OUI\", \"NON\"\n)\n| eval suspicious_name=if(\n    match(ServiceName, \"^[a-z]{8}$\") OR match(ServiceName, \"^svc[0-9]+\") OR len(ServiceName) < 4,\n    \"OUI\", \"NON\"\n)\n| eval cmd_in_path=if(match(service_path, \"(cmd\\.exe|powershell|mshta|wscript|cscript|regsvr32|rundll32)\"), \"OUI\", \"NON\")\n| eval risk_score=0\n| eval risk_score=if(suspicious_path=\"OUI\", risk_score+3, risk_score)\n| eval risk_score=if(suspicious_name=\"OUI\", risk_score+2, risk_score)\n| eval risk_score=if(cmd_in_path=\"OUI\", risk_score+4, risk_score)\n| eval risk_score=if(ServiceType=\"user mode service\" AND StartType=\"auto start\", risk_score+1, risk_score)\n| where risk_score >= 3\n| sort -risk_score\n| table _time, host, ServiceName, ImagePath, ServiceType, StartType, risk_score, suspicious_path, cmd_in_path\n| rename risk_score AS \"Score de risque\"",
      explanation: "EventCode 7045 = installation d'un nouveau service Windows. Les indicateurs de malveillance sont : (1) chemin hors des repertoires systeme standards, (2) nom de service aleatoire ou tres court, (3) utilisation de cmd.exe/powershell dans le chemin du service (technique Living off the Land), (4) demarrage automatique. Le scoring permet de prioriser les investigations. Un PsExec legitime genere aussi un 7045 (service PSEXESVC) mais son chemin sera dans ADMIN$."
    },
    {
      title: "Detection d'effacement de logs",
      scenario: "Un attaquant sophistique efface les logs Windows pour couvrir ses traces. Detectez les effacements de journaux d'evenements et identifiez le responsable.",
      hint: "EventCode 1102 (journal de securite efface) dans le log Security, EventCode 104 (journal systeme efface) dans le log System. L'absence de logs est aussi un indicateur.",
      solution: "index=security (sourcetype=WinEventLog:Security EventCode=1102) OR (sourcetype=WinEventLog:System EventCode=104) earliest=-30d\n| eval action=case(\n    EventCode=1102, \"Journal Security efface\",\n    EventCode=104, \"Journal \" . LogName . \" efface\"\n)\n| eval criticite=\"CRITIQUE\"\n| table _time, host, SubjectUserName, SubjectDomainName, action, criticite\n| rename SubjectUserName AS \"Utilisateur\", SubjectDomainName AS \"Domaine\"\n| append [\n    search index=security sourcetype=WinEventLog:Security earliest=-7d\n    | timechart span=1h count by host\n    | untable _time, host, count\n    | where count < 10\n    | eval action=\"Volume de logs anormalement bas\"\n    | eval criticite=\"HAUTE\"\n    | table _time, host, action, count, criticite\n]\n| sort -_time",
      explanation: "EventCode 1102 = effacement du journal de securite Windows (TOUJOURS suspect). EventCode 104 = effacement d'un autre journal. La deuxieme partie de la requete utilise 'append' pour detecter aussi les GAPS dans les logs (periodes avec anormalement peu d'evenements), ce qui peut indiquer un effacement partiel ou un forwarder en panne. L'effacement de logs est un indicateur fort de compromission et doit TOUJOURS etre investigue."
    },
    {
      title: "Exfiltration de donnees via HTTP/HTTPS",
      scenario: "Detectez les transferts de donnees sortants anormalement volumineux qui pourraient indiquer une exfiltration de donnees via le protocole HTTP/HTTPS. Un utilisateur normal ne devrait pas envoyer des gigaoctets de donnees en upload.",
      hint: "Cherchez dans les logs proxy ou firewall les connexions sortantes avec un volume d'upload (bytes_out) anormalement eleve. Comparez chaque utilisateur a la baseline normale.",
      solution: "index=proxy OR index=network sourcetype=proxy OR sourcetype=firewall earliest=-24h\n| where isnotnull(bytes_out) AND bytes_out > 0\n| where NOT cidrmatch(\"10.0.0.0/8\", dest_ip) AND NOT cidrmatch(\"172.16.0.0/12\", dest_ip) AND NOT cidrmatch(\"192.168.0.0/16\", dest_ip)\n| stats sum(bytes_out) AS total_upload, count AS nb_connexions, dc(dest_ip) AS destinations, values(dest_ip) AS top_destinations by src_ip\n| eval total_upload_mb=round(total_upload/1024/1024, 2)\n| eventstats avg(total_upload_mb) AS moyenne_upload, stdev(total_upload_mb) AS stdev_upload\n| eval zscore=round((total_upload_mb - moyenne_upload) / stdev_upload, 2)\n| where zscore > 3 OR total_upload_mb > 500\n| sort -total_upload_mb\n| table src_ip, total_upload_mb, nb_connexions, destinations, zscore, top_destinations\n| rename total_upload_mb AS \"Upload (Mo)\", zscore AS \"Z-Score\", destinations AS \"Destinations uniques\"",
      explanation: "On calcule le volume total d'upload par IP source vers des destinations EXTERNES uniquement (exclusion des plages RFC1918). Le z-score compare chaque utilisateur a la moyenne : un zscore > 3 signifie que l'upload est a plus de 3 ecarts-types de la moyenne (statistiquement tres anormal). Le seuil absolu de 500 Mo capture aussi les exfiltrations dans des environnements a faible trafic. Les destinations multiples et le nombre de connexions aident a contextualiser (une mise a jour cloud vs une exfiltration)."
    },
    {
      title: "Detection de Pass-the-Hash / Pass-the-Ticket",
      scenario: "Detectez les techniques Pass-the-Hash et Pass-the-Ticket utilisees pour le mouvement lateral sans connaitre le mot de passe en clair. Ces techniques laissent des traces specifiques dans les logs Windows.",
      hint: "Pass-the-Hash : EventCode 4624 avec Logon_Type=3 et LogonProcessName=NtLmSsp et KeyLength=0. Pass-the-Ticket : EventCode 4768/4769 avec des anomalies dans le champ TicketEncryptionType (RC4 = suspect).",
      solution: "index=security sourcetype=WinEventLog:Security EventCode=4624 Logon_Type=3 LogonProcessName=NtLmSsp earliest=-24h\n| where KeyLength=0 OR KeyLength=\"0\"\n| where NOT match(Account_Name, \"^(ANONYMOUS LOGON|SYSTEM)$\")\n| where NOT match(Account_Name, \"\\$$\")\n| stats count, dc(host) AS machines_cibles, values(host) AS liste_cibles by Account_Name, Source_Network_Address\n| where count > 3\n| sort -count\n| eval technique=\"Pass-the-Hash\"\n| table technique, Account_Name, Source_Network_Address, count, machines_cibles, liste_cibles\n| append [\n    search index=security sourcetype=WinEventLog:Security EventCode=4769 earliest=-24h\n    | where TicketEncryptionType=\"0x17\"\n    | where NOT match(ServiceName, \"\\$$\")\n    | stats count, dc(ServiceName) AS services_cibles by Account_Name, Client_Address\n    | where count > 5\n    | eval technique=\"Pass-the-Ticket (RC4)\"\n    | table technique, Account_Name, Client_Address, count, services_cibles\n]\n| sort -count",
      explanation: "Pass-the-Hash se detecte par : Logon_Type=3 (reseau) + NtLmSsp (protocole NTLM) + KeyLength=0 (pas de negociation de cle Kerberos, car le hash est utilise directement). Pass-the-Ticket se detecte par l'EventCode 4769 (Ticket Kerberos TGS) avec un chiffrement RC4 (0x17) qui est obsolete et souvent utilise par les outils offensifs comme Mimikatz. Les comptes machine (terminant par $) sont exclus car ils generent du bruit."
    },
    {
      title: "Analyse de taches planifiees suspectes (persistance)",
      scenario: "Les attaquants utilisent souvent les taches planifiees Windows pour maintenir leur acces (persistance). Detectez la creation de nouvelles taches planifiees executant des commandes suspectes.",
      hint: "EventCode 4698 (tache planifiee creee) dans les logs Security. Analysez le contenu XML de la tache pour identifier les commandes executees.",
      solution: "index=security sourcetype=WinEventLog:Security EventCode=4698 earliest=-7d\n| eval task_content=lower(TaskContent)\n| eval suspicious=0\n| eval suspicious=if(match(task_content, \"powershell|cmd\\.exe|wscript|cscript|mshta|certutil|bitsadmin\"), suspicious+2, suspicious)\n| eval suspicious=if(match(task_content, \"\\\\temp\\\\|\\\\tmp\\\\|appdata|\\\\users\\\\public\"), suspicious+2, suspicious)\n| eval suspicious=if(match(task_content, \"http://|https://|ftp://\"), suspicious+3, suspicious)\n| eval suspicious=if(match(task_content, \"encodedcommand|-enc |-e |-ep bypass\"), suspicious+4, suspicious)\n| eval suspicious=if(match(task_content, \"downloadstring|downloadfile|invoke-webrequest|wget|curl\"), suspicious+3, suspicious)\n| where suspicious >= 2\n| sort -suspicious\n| table _time, host, SubjectUserName, TaskName, suspicious, TaskContent\n| rename suspicious AS \"Score\", SubjectUserName AS \"Cree par\", TaskName AS \"Nom de la tache\"",
      explanation: "EventCode 4698 capture la creation de taches planifiees avec leur contenu XML complet. Les indicateurs suspects sont : utilisation d'interpreteurs de commandes (PowerShell, cmd), chemin dans des repertoires temporaires ou utilisateur, URLs dans le contenu (download de payload), et commandes encodees. Le scoring hierarchise les alertes. Une tache planifiee avec PowerShell + URL + encoding est presque certainement malveillante (score >= 7)."
    }
  ],

  // ============================================================
  // 5. COMPARAISON RAPID7 INSIGHTIDR VS SPLUNK
  // ============================================================
  rapid7Comparison: {
    intro: "Maxime a de l'experience avec Rapid7 InsightIDR. Voici comment ses competences se transposent dans l'ecosysteme Splunk. Les concepts fondamentaux sont similaires, mais la mise en oeuvre et la terminologie different.",
    mappings: [
      {
        rapid7: "Log Search (LEQL)",
        splunk: "Search & Reporting App (SPL)",
        notes: "LEQL (Log Entry Query Language) est plus simple et structure. SPL est beaucoup plus puissant et flexible avec son systeme de pipes. En LEQL tu fais 'where(src_ip = 10.0.0.1) calculate(count)' ; en SPL c'est 'src_ip=10.0.0.1 | stats count'. La logique est similaire mais SPL offre plus de 140 commandes contre ~20 operations en LEQL."
      },
      {
        rapid7: "Log Sets",
        splunk: "Index + Sourcetype",
        notes: "Les Log Sets de Rapid7 (Firewall Activity, Authentication Activity, etc.) correspondent a la combinaison index + sourcetype dans Splunk. Dans Splunk, tu as un controle plus granulaire : tu choisis toi-meme comment organiser tes index et sourcetypes."
      },
      {
        rapid7: "Pre-built Detections (AttackIQ)",
        splunk: "Correlation Searches (Splunk ES)",
        notes: "Les detections pre-construites de Rapid7 basees sur le comportement utilisateur sont equivalentes aux Correlation Searches de Splunk Enterprise Security. Dans Splunk ES, tu peux facilement creer et modifier tes propres regles de correlation en SPL."
      },
      {
        rapid7: "Investigations",
        splunk: "Notable Events + Investigation Workbench (ES)",
        notes: "Les Investigations Rapid7 avec leur timeline correspondent aux Notable Events de Splunk ES. L'Investigation Workbench de Splunk ES permet de pivoter sur les artefacts (IP, user, host) de facon similaire a la timeline Rapid7."
      },
      {
        rapid7: "Dashboards & Rapports",
        splunk: "Dashboards (Simple XML / Dashboard Studio)",
        notes: "Les dashboards Splunk sont beaucoup plus personnalisables que ceux de Rapid7. Deux modes : Simple XML (classique, code) et Dashboard Studio (nouveau, drag-and-drop). Splunk permet des drilldowns interactifs et des tokens dynamiques pour des dashboards veritablement interactifs."
      },
      {
        rapid7: "User Behavior Analytics (UBA)",
        splunk: "Splunk UBA / Risk-Based Alerting (ES)",
        notes: "L'UBA de Rapid7 est integre nativement. Splunk propose Splunk UBA (produit separe) et Risk-Based Alerting dans ES qui attribue des scores de risque aux entites (users, hosts). Les deux approches detectent les anomalies comportementales."
      },
      {
        rapid7: "InsightConnect (SOAR)",
        splunk: "Splunk SOAR (anciennement Phantom)",
        notes: "InsightConnect est le SOAR de Rapid7 ; Splunk SOAR (ex-Phantom) est son equivalent. Les deux permettent l'automatisation avec des playbooks. Splunk SOAR est considere comme le leader du marche avec plus de 350 integrations et un editeur de playbooks visuel."
      },
      {
        rapid7: "Agents InsightIDR",
        splunk: "Universal Forwarder (UF)",
        notes: "L'agent InsightIDR collecte et envoie les logs. L'Universal Forwarder de Splunk fait la meme chose mais est plus configurable. Le UF ne fait que transferer les donnees brutes, tandis que l'agent InsightIDR fait aussi de la detection endpoint."
      },
      {
        rapid7: "Threat Intelligence (automatique)",
        splunk: "Threat Intelligence Framework (ES)",
        notes: "Rapid7 integre automatiquement la threat intelligence dans ses detections. Splunk ES a un framework de threat intelligence configurable qui supporte STIX/TAXII, CSV, et des sources personnalisees. Plus de travail de configuration initial dans Splunk mais plus de flexibilite."
      },
      {
        rapid7: "Cloud natif (SaaS uniquement)",
        splunk: "On-premise / Cloud / Hybride",
        notes: "Rapid7 InsightIDR est 100% SaaS. Splunk offre trois modes : on-premise (tu geres tout), Splunk Cloud (SaaS gere par Splunk), ou hybride. En SOC Sopra Steria, tu auras probablement un deploiement on-premise ou hybride chez les clients."
      },
      {
        rapid7: "Regex dans LEQL (where(/pattern/))",
        splunk: "rex, regex, match()",
        notes: "Les regex dans LEQL sont limitees a du filtrage. Dans SPL, tu peux filtrer (regex), extraire des champs (rex), ou utiliser dans des conditions (match() dans eval/where). SPL offre plus de flexibilite pour manipuler les donnees avec les regex."
      }
    ]
  },

  // ============================================================
  // 6. ALERTES SPLUNK
  // ============================================================
  alerts: {
    description: "Les alertes Splunk permettent de surveiller les donnees en continu et de declencher des actions automatiques quand des conditions sont remplies. C'est le mecanisme principal pour la detection dans un SOC. Une alerte est essentiellement une saved search avec un declencheur et des actions.",
    types: [
      {
        type: "Alertes planifiees (Scheduled Alerts)",
        description: "S'executent selon un cron schedule (ex: toutes les 5 minutes, toutes les heures). La recherche couvre une fenetre temporelle definie. C'est le type le plus courant car il equilibre performance et reactivite. Exemple : verifier les brute force toutes les 5 minutes sur les 10 dernieres minutes.",
        avantage: "Performant, predictible, ne surcharge pas les indexers.",
        inconvenient: "Delai entre l'evenement et l'alerte (jusqu'a l'intervalle du cron)."
      },
      {
        type: "Alertes en temps reel (Real-Time Alerts)",
        description: "S'executent en continu sur un flux de donnees en temps reel. Detection quasi-instantanee. ATTENTION : tres gourmandes en ressources car elles maintiennent une recherche permanente sur les indexers.",
        avantage: "Detection immediate, pas de delai.",
        inconvenient: "Tres couteux en ressources. A utiliser avec parcimonie pour les alertes critiques uniquement."
      },
      {
        type: "Notable Events (Splunk ES)",
        description: "Dans Splunk Enterprise Security, les Correlation Searches generent des Notable Events (evenements notables). Ce sont des alertes enrichies avec severite, urgence, proprietaire, statut, et un workflow de gestion d'incident integre dans l'Incident Review dashboard. C'est le mecanisme standard d'alerte dans un SOC utilisant Splunk ES.",
        avantage: "Workflow complet de gestion d'incident, priorisation par risque, enrichissement automatique.",
        inconvenient: "Necessite Splunk Enterprise Security (licence additionnelle)."
      }
    ],
    creation: "Processus de creation d'une alerte Splunk :\n\n1. ECRIRE LA RECHERCHE : Developper et tester la requete SPL dans Search & Reporting. S'assurer que les resultats sont pertinents avec peu de faux positifs.\n\n2. SAUVEGARDER COMME ALERTE : Cliquer sur 'Save As' > 'Alert'. Donner un nom descriptif et une description.\n\n3. CONFIGURER LE DECLENCHEUR :\n   - Schedule : definir la frequence (cron expression ou presets)\n   - Time Range : fenetre temporelle de la recherche (ex: -15m)\n   - Trigger Condition : 'Number of results > 0', 'Number of results > N', 'Custom condition'\n   - Throttle : eviter les alertes repetitives (supprimer les doublons pendant N minutes)\n\n4. CONFIGURER LES ACTIONS :\n   - Send email : notification par email (avec resultats en piece jointe optionnel)\n   - Log event : ecrire un evenement dans un index\n   - Webhook : appeler une URL (integration SOAR, ticketing)\n   - Run script : executer un script\n   - Notable Event (ES) : creer un notable event avec severite et proprietaire\n   - Custom actions : actions personnalisees via des apps\n\n5. DEFINIR LES PERMISSIONS : Qui peut voir/modifier l'alerte. Partager au niveau de l'app ou globalement.\n\n6. TESTER ET MONITORER : Verifier dans Activity > Triggered Alerts que l'alerte se declenche correctement. Ajuster les seuils en fonction des faux positifs.",
    bestPractices: [
      "Toujours throttle les alertes pour eviter le flood (ex: supprimer les doublons pour une meme IP pendant 1 heure)",
      "Utiliser des alertes planifiees plutot que temps reel quand possible (rapport couts/benefices)",
      "Inclure le contexte dans le message d'alerte (IP, user, count, evenements) pour faciliter le triage",
      "Tester l'alerte pendant 1-2 semaines en mode log-only avant de l'activer en production",
      "Documenter chaque alerte : objectif, seuils, faux positifs connus, runbook associe",
      "Revoir regulierement les alertes (tuning) : desactiver celles qui generent trop de faux positifs"
    ]
  },

  // ============================================================
  // 7. DASHBOARDS SPLUNK
  // ============================================================
  dashboards: {
    description: "Les dashboards Splunk sont des tableaux de bord interactifs qui visualisent les donnees en temps reel ou quasi-reel. Ils sont la vitrine du SOC et l'outil quotidien des analystes. Splunk propose deux modes de creation : Simple XML (classique, base sur du code XML) et Dashboard Studio (nouveau, interface drag-and-drop plus moderne).",
    components: [
      {
        composant: "Panels (Panneaux)",
        description: "Conteneurs individuels affichant une visualisation. Chaque panneau contient une recherche SPL et un type de visualisation. Les panneaux peuvent etre de type inline search (recherche integree), report (rapport sauvegarde), ou base search (recherche partagee entre panneaux)."
      },
      {
        composant: "Visualisations",
        description: "Types de graphiques disponibles : Table (tableau de donnees), Line Chart (courbe temporelle), Bar Chart (barres), Pie Chart (camembert), Single Value (valeur unique grande taille), Gauge (jauge), Map (carte geographique Choropleth ou Cluster), Bubble Chart, Scatter Plot, et plus. Chaque visualisation peut etre personnalisee (couleurs, axes, legende)."
      },
      {
        composant: "Drilldowns",
        description: "Actions declenchees quand un utilisateur clique sur un element du dashboard. Permet de naviguer vers une recherche detaillee, un autre dashboard, ou une URL externe. Exemple : cliquer sur une IP dans un tableau ouvre un dashboard de details pour cette IP. Les drilldowns rendent les dashboards interactifs et accelerent l'investigation."
      },
      {
        composant: "Tokens",
        description: "Variables dynamiques qui permettent de passer des valeurs entre les panneaux, les drilldowns et les inputs. Syntaxe : $token_name$. Les tokens alimentent les filtres dynamiques : un selecteur de temps, un champ de saisie IP, un menu deroulant de severite. Ils sont au coeur de l'interactivite des dashboards."
      },
      {
        composant: "Inputs (Filtres)",
        description: "Elements interactifs en haut du dashboard : Time Picker (selecteur de periode), Dropdown (menu deroulant), Text Input (champ de saisie), Radio, Checkbox, Multiselect. Ils alimentent des tokens utilises dans les recherches des panneaux. Permettent aux analystes de filtrer dynamiquement sans modifier les requetes."
      }
    ],
    socDashboards: [
      {
        nom: "Security Posture (ES)",
        description: "Vue d'ensemble de la securite de l'environnement. Affiche le nombre de Notable Events par severite, les tendances sur 24h/7j, les top sources et destinations, et le statut general. C'est le premier dashboard consulte par le SOC Manager chaque matin."
      },
      {
        nom: "Incident Review (ES)",
        description: "Dashboard principal de travail de l'analyste SOC dans Splunk ES. Affiche tous les Notable Events avec leur severite, urgence, statut, proprietaire. Permet de trier, filtrer, assigner et investiguer les incidents. Interface de type ticketing integree a Splunk."
      },
      {
        nom: "Threat Activity (ES)",
        description: "Visualise les menaces detectees par la Threat Intelligence. Affiche les IOC (Indicators of Compromise) matches, les sources de menaces, les types de menaces. Permet de voir quels IOC sont les plus actifs dans l'environnement."
      },
      {
        nom: "Access Anomalies",
        description: "Dashboard personnalise montrant les anomalies d'acces : connexions depuis des pays inhabituels, connexions hors horaires, comptes acces multiples simultanes, echecs de connexion massifs. Utilise souvent des timecharts et des cartes geographiques."
      },
      {
        nom: "Executive Summary",
        description: "Dashboard de synthese pour la direction. Metriques cles : nombre d'incidents, MTTD (Mean Time To Detect), MTTR (Mean Time To Respond), tendances mensuelles, top risques. Visualisations simples et impactantes (single values, gauges, trending)."
      }
    ]
  },

  // ============================================================
  // 8. SPLUNK ENTERPRISE SECURITY (ES)
  // ============================================================
  enterpriseSecurity: {
    description: "Splunk Enterprise Security (ES) est la solution SIEM premium de Splunk, construite au-dessus de la plateforme Splunk. C'est un produit additionnel (licence separee) qui transforme Splunk en une veritable plateforme SOC. ES utilise le CIM (Common Information Model) pour normaliser les donnees de toutes les sources et fournit des centaines de regles de detection pre-configurees alignees sur le framework MITRE ATT&CK.",
    features: [
      {
        feature: "Notable Events",
        description: "Evenements de securite significatifs generes par les Correlation Searches. Chaque Notable Event a : une severite (Info, Low, Medium, High, Critical), une urgence (calculee automatiquement en croisant severite et priorite de l'asset), un statut (New, In Progress, Pending, Resolved, Closed), un proprietaire (analyste assigne). Le workflow est : triage -> investigation -> remediation -> cloture."
      },
      {
        feature: "Correlation Searches",
        description: "Requetes SPL planifiees qui detectent les menaces et generent des Notable Events. Splunk ES inclut plus de 200 correlation searches pre-construites couvrant : brute force, malware, data exfiltration, insider threat, compliance violations, etc. On peut creer les siennes en SPL pur. Elles s'appuient sur les Data Models acceleres pour des performances optimales."
      },
      {
        feature: "Adaptive Response",
        description: "Framework d'actions automatisees declenchees par les Notable Events ou les Correlation Searches. Permet d'executer automatiquement des actions de remediation : bloquer une IP sur le firewall, desactiver un compte AD, isoler un endpoint, enrichir un IOC, creer un ticket ServiceNow. C'est le pont entre la detection et la reponse automatisee (avant SOAR)."
      },
      {
        feature: "Risk-Based Alerting (RBA)",
        description: "Approche moderne qui attribue des scores de risque aux entites (utilisateurs, machines) au lieu de generer des alertes individuelles. Chaque detection augmente le score de risque de l'entite concernee. Un Notable Event n'est genere que quand le score depasse un seuil. Avantage : reduit massivement les faux positifs et le volume d'alertes (reduction de 80-90% rapportee). Chaque analyste devrait comprendre le RBA."
      },
      {
        feature: "Threat Intelligence Framework",
        description: "Framework integre pour gerer les IOC (Indicators of Compromise). Supporte : upload CSV, STIX/TAXII (standards d'echange de threat intel), MISP, et sources personnalisees. Les IOC sont automatiquement correles avec les evenements. Types d'IOC : IP, domaine, URL, hash de fichier, email. Dashboard dedie pour visualiser les matches."
      },
      {
        feature: "Asset & Identity Framework",
        description: "Base de donnees des assets (machines, serveurs) et des identites (utilisateurs) de l'organisation. Permet d'enrichir les evenements avec le contexte business : departement, criticite, proprietaire, localisation. L'urgence d'un Notable Event est calculee en croisant la severite de la detection avec la priorite de l'asset/identite. Un brute force sur le serveur de paie (critical) sera plus urgent que sur un poste de test (low)."
      },
      {
        feature: "Investigation Workbench",
        description: "Interface d'investigation qui permet de pivoter sur des artefacts (IP, utilisateur, hash, domaine). Affiche la timeline des evenements lies, les associations entre entites, et le contexte threat intel. Facilite l'investigation en un seul endroit au lieu de lancer de multiples recherches manuelles."
      },
      {
        feature: "Content Updates (ESCU)",
        description: "Splunk publie regulierement des mises a jour de contenu via l'Enterprise Security Content Update (ESCU). Chaque mise a jour ajoute de nouvelles Correlation Searches, des analytic stories alignees sur MITRE ATT&CK, et des detection rules pour les dernieres menaces. C'est la threat intelligence de Splunk pour la detection."
      }
    ],
    workflow: "Workflow quotidien d'un analyste SOC avec Splunk ES :\n\n1. DEBUT DE SHIFT : Consulter le dashboard Security Posture pour avoir une vue d'ensemble. Verifier s'il y a des incidents critiques en cours. Lire les notes du shift precedent.\n\n2. TRIAGE (Incident Review) : Ouvrir le dashboard Incident Review. Trier les Notable Events par urgence/severite. Pour chaque alerte :\n   a. Lire le titre et la description de la detection\n   b. Examiner les champs cles (src, dest, user, action)\n   c. Decision rapide : True Positive, False Positive, ou Needs Investigation\n   d. Changer le statut et assigner si necessaire\n\n3. INVESTIGATION : Pour les alertes necessitant une investigation approfondie :\n   a. Utiliser l'Investigation Workbench ou lancer des recherches SPL manuelles\n   b. Pivoter sur les entites (IP source -> que fait-elle d'autre ? User -> quels autres evenements ?)\n   c. Verifier la Threat Intelligence (IOC matches)\n   d. Consulter l'Asset & Identity (cet asset est-il critique ?)\n   e. Correler avec d'autres alertes recentes (meme src, meme user)\n   f. Consulter les logs bruts si necessaire\n\n4. ESCALADE : Si l'incident est confirme :\n   a. Changer le statut en 'In Progress'\n   b. Documenter les findings dans les commentaires du Notable Event\n   c. Escalader au N2/N3 si necessaire\n   d. Declencher les Adaptive Response actions si applicable\n   e. Creer un ticket dans le systeme de ticketing (ServiceNow, Jira)\n\n5. REMEDIATION : Collaborer avec les equipes IT pour :\n   a. Contenir la menace (isoler l'hote, bloquer l'IP, desactiver le compte)\n   b. Eradiquer (supprimer le malware, corriger la vulnerabilite)\n   c. Recuperer (restaurer les systemes, changer les mots de passe)\n\n6. CLOTURE : Documenter l'incident complet, mettre a jour le Notable Event en 'Closed', ajouter les IOC decouverts dans la Threat Intelligence, et creer/modifier les regles de detection si necessaire.\n\n7. FIN DE SHIFT : Rediger les notes de passation, signaler les incidents en cours, et mettre a jour les metriques du SOC."
  },

  // ============================================================
  // 9. FICHIERS DE CONFIGURATION IMPORTANTS
  // ============================================================
  configFiles: {
    description: "Splunk est configure principalement via des fichiers .conf. Comprendre ces fichiers est essentiel pour un administrateur Splunk et utile pour un analyste SOC qui doit debugger des problemes d'ingestion de donnees.",
    files: [
      {
        nom: "inputs.conf",
        role: "Definit les sources de donnees : quels fichiers monitorer, quels ports ecouter, quels scripts executer. C'est le point d'entree des donnees dans Splunk.",
        exemple: "[monitor:///var/log/syslog]\ndisabled = false\nsourcetype = syslog\nindex = linux\n\n[udp://514]\nsourcetype = syslog\nindex = network"
      },
      {
        nom: "outputs.conf",
        role: "Configure ou les forwarders envoient les donnees (vers quels indexers). Definit le load balancing entre indexers et le chiffrement SSL.",
        exemple: "[tcpout]\ndefaultGroup = indexer_cluster\n\n[tcpout:indexer_cluster]\nserver = idx1:9997, idx2:9997, idx3:9997\nuseACK = true"
      },
      {
        nom: "props.conf",
        role: "Definit comment les donnees sont parsees : extraction du timestamp, line breaking, extraction de champs, transformations. Le fichier le plus complexe et le plus important pour la qualite des donnees.",
        exemple: "[custom_app_log]\nTIME_FORMAT = %Y-%m-%d %H:%M:%S\nTIME_PREFIX = ^\\d{4}\nLINE_BREAKER = ([\\r\\n]+)\\d{4}-\\d{2}-\\d{2}\nSHOULD_LINEMERGE = false"
      },
      {
        nom: "transforms.conf",
        role: "Definit les transformations complexes : routing vers des index specifiques, masquage de donnees sensibles, extractions de champs basees sur regex, lookups definitions.",
        exemple: "[mask_credit_card]\nREGEX = (\\d{4})\\d{8}(\\d{4})\nFORMAT = $1XXXXXXXX$2\nDEST_KEY = _raw"
      },
      {
        nom: "savedsearches.conf",
        role: "Contient toutes les recherches sauvegardees, alertes, rapports planifies. Chaque entree definit la requete SPL, le schedule, les actions et les parametres de l'alerte.",
        exemple: "[Brute Force Detection]\nsearch = index=security EventCode=4625 | stats count by src_ip | where count > 20\ncron_schedule = */5 * * * *\ndispatch.earliest_time = -10m\nalert.severity = 4\naction.email = 1"
      },
      {
        nom: "authorize.conf",
        role: "Definit les roles et les permissions. Controle quels index chaque role peut interroger, quelles commandes SPL sont accessibles, et les capacites de chaque role.",
        exemple: "[role_soc_analyst]\nimportRoles = user\nsrchIndexesAllowed = security;network;windows;linux\nsrchFilter = NOT sourcetype=hr_sensitive"
      },
      {
        nom: "server.conf",
        role: "Configuration globale du serveur Splunk : nom du serveur, clustering, SSL, replication.",
        exemple: "[general]\nserverName = SH01-PROD\npass4SymmKey = <encrypted_key>\n\n[clustering]\nmode = searchhead\nmaster_uri = https://cm:8089"
      }
    ],
    precedence: "Ordre de priorite des fichiers de configuration (du plus prioritaire au moins) :\n1. system/local/ (modifications locales - PLUS HAUTE PRIORITE)\n2. app/local/ (configuration locale de l'app)\n3. app/default/ (configuration par defaut de l'app)\n4. system/default/ (configuration par defaut de Splunk - NE JAMAIS MODIFIER)\n\nRegle d'or : ne jamais modifier les fichiers dans default/, toujours creer/modifier dans local/."
  },

  // ============================================================
  // 10. QUESTIONS FREQUENTES D'ENTRETIEN SPLUNK SOC
  // ============================================================
  interviewQuestions: [
    {
      question: "Comment fonctionne le flux de donnees dans Splunk, de la collecte a la recherche ?",
      answer: "Le flux de donnees Splunk suit ces etapes :\n1. COLLECTE : Les Universal Forwarders (ou Heavy Forwarders) collectent les logs sur les sources (serveurs, equipements reseau, applications)\n2. PARSING : Les donnees sont parsees (identification du sourcetype, extraction du timestamp, line breaking). En general fait par l'indexer, parfois par le Heavy Forwarder\n3. INDEXING : L'indexer segmente les donnees en evenements, extrait les champs par defaut, compresse et stocke dans des index (fichiers tsidx + rawdata dans des buckets)\n4. RECHERCHE : Le Search Head recoit la requete SPL de l'utilisateur, la distribue aux indexers concernes, chaque indexer execute la recherche sur ses donnees locales et renvoie les resultats au Search Head qui les fusionne et les presente"
    },
    {
      question: "Quelle est la difference entre 'stats' et 'eventstats' ?",
      answer: "'stats' agrege les resultats et SUPPRIME les evenements individuels. On obtient uniquement le tableau statistique. 'eventstats' calcule les memes statistiques mais les AJOUTE comme champs a chaque evenement original, permettant de comparer chaque evenement a la statistique globale. Exemple : eventstats permet de calculer la moyenne du trafic et de marquer chaque evenement comme 'au-dessus' ou 'en-dessous' de la moyenne. C'est essentiel pour la detection d'anomalies."
    },
    {
      question: "Comment detecteriez-vous un brute force dans Splunk ?",
      answer: "Je chercherais les evenements d'echec de connexion (EventCode 4625 pour Windows) groupes par IP source et fenetre temporelle. Requete : index=security EventCode=4625 | bin _time span=5m | stats count by _time, src_ip, Account_Name | where count > 10. Je completerais avec iplocation pour la geolocalisation, et je verifierais si les memes IPs ont reussi a se connecter apres (EventCode 4624) ce qui indiquerait un brute force reussi. En production, j'utiliserais une Correlation Search dans ES avec un seuil adapte a l'environnement."
    },
    {
      question: "Qu'est-ce que le CIM et pourquoi est-il important ?",
      answer: "Le CIM (Common Information Model) est un modele de normalisation des donnees dans Splunk. Il definit des noms de champs standards pour chaque categorie de donnees (Authentication, Network Traffic, Malware, etc.). Exemple : que les logs viennent de Windows, Linux, ou VPN, un echec de connexion aura toujours action=failure dans le CIM. L'importance : (1) Les requetes fonctionnent sur TOUTES les sources sans modification, (2) Splunk Enterprise Security s'appuie entierement sur le CIM, (3) Les dashboards et alertes sont portables entre environnements. Sans CIM, il faudrait ecrire une requete par source de logs."
    },
    {
      question: "Comment optimisez-vous les performances d'une requete SPL ?",
      answer: "Optimisations principales :\n1. TEMPS : Toujours specifier la fenetre temporelle la plus courte possible (earliest/latest)\n2. INDEX ET SOURCETYPE : Toujours specifier index= et sourcetype= en debut de requete pour limiter les donnees scannees\n3. CHAMPS : Utiliser 'fields' tot dans la requete pour ne garder que les champs necessaires\n4. FILTRAGE PRECOCE : Filtrer (where, search) AVANT les commandes couteuses (stats, join, transaction)\n5. STATS vs TRANSACTION : Preferer stats a transaction quand possible (10-100x plus rapide)\n6. TSTATS : Utiliser tstats avec les Data Models acceleres pour des recherches ultra-rapides\n7. EVITER : join (utiliser stats a la place), subsearch sur de gros volumes, wildcards en debut de champ (ex: *admin)\n8. MODE : Utiliser le mode Fast quand on n'a pas besoin de tous les champs"
    },
    {
      question: "Decrivez votre approche pour investiguer un Notable Event dans Splunk ES.",
      answer: "Mon approche :\n1. TRIAGE INITIAL : Lire le titre, la description, la severite. Examiner les champs cles (src, dest, user). Verifier si c'est un faux positif connu.\n2. CONTEXTE : Consulter l'Asset & Identity Framework (cet asset est-il critique ?). Verifier le score de risque de l'entite.\n3. PIVOT : A partir de l'IP/user suspect, chercher quels autres evenements sont associes dans les dernieres 24h. Utiliser l'Investigation Workbench.\n4. CORRELATION : Y a-t-il d'autres Notable Events lies (meme src, meme user) ? Y a-t-il des IOC matches dans la Threat Intelligence ?\n5. LOGS BRUTS : Si necessaire, descendre aux logs bruts pour comprendre exactement ce qui s'est passe.\n6. DECISION : True Positive (escalade), False Positive (documenter et fermer), ou Needs More Data (collecter plus de donnees).\n7. DOCUMENTATION : Tout documenter dans le Notable Event pour la tracabilite."
    },
    {
      question: "Quelle est la difference entre un Universal Forwarder et un Heavy Forwarder ?",
      answer: "L'Universal Forwarder (UF) est leger (~50 Mo), ne fait AUCUN parsing/transformation, et se contente de transmettre les donnees brutes. Il consomme tres peu de ressources et est deploye sur tous les endpoints. Le Heavy Forwarder (HF) est une installation Splunk complete qui peut parser, filtrer, router et transformer les donnees AVANT de les envoyer a l'indexer. Il est utilise quand on veut : masquer des donnees sensibles a la source, filtrer du bruit pour economiser la licence, aggreger des donnees de multiples sources, ou servir de proxy dans une DMZ. Le HF consomme significativement plus de ressources."
    },
    {
      question: "Comment creeriez-vous un dashboard SOC dans Splunk ?",
      answer: "Etapes :\n1. DEFINIR LES METRIQUES : Identifier les KPI du SOC (nombre d'alertes, MTTD, MTTR, top menaces)\n2. ECRIRE LES REQUETES : Developper et tester chaque requete SPL dans Search\n3. CREER LE DASHBOARD : Menu 'Dashboards' > 'Create New Dashboard'. Choisir Dashboard Studio ou Classic\n4. AJOUTER LES PANNEAUX : Pour chaque metrique, ajouter un panneau avec la visualisation appropriee (Single Value pour les KPI, Timechart pour les tendances, Table pour les details, Map pour la geolocalisation)\n5. AJOUTER DES FILTRES : Time picker, dropdown pour la severite, champ de saisie pour l'IP\n6. CONFIGURER LES DRILLDOWNS : Cliquer sur une IP dans le tableau ouvre les details\n7. OPTIMISER : Utiliser des base searches partagees entre panneaux, configurer le refresh automatique\n8. PARTAGER : Definir les permissions et publier dans l'app appropriee"
    },
    {
      question: "Qu'est-ce que le Risk-Based Alerting (RBA) dans Splunk ES ?",
      answer: "Le RBA est une approche qui remplace les alertes individuelles par un systeme de scoring de risque. Au lieu de generer une alerte pour chaque detection, chaque Correlation Search attribue un score de risque a l'entite concernee (user, host). Le score s'accumule dans un Risk Index. Un Notable Event n'est genere que quand le score total d'une entite depasse un seuil (ex: 100 points). Avantages : reduction massive du volume d'alertes (80-90%), correlation automatique de multiples indicateurs faibles en un seul incident fort, reduction de la fatigue des analystes, et meilleure priorisation. Exemple : un seul echec de connexion = +5 points (pas d'alerte). Un echec + PowerShell suspect + acces inhabituel pour le meme user = +5 +30 +25 = 60 points. Si le seuil est 50, une alerte est generee avec TOUT le contexte."
    },
    {
      question: "Comment Splunk gere-t-il les donnees a grande echelle (clustering) ?",
      answer: "Splunk utilise deux types de clusters :\n\n1. INDEXER CLUSTER : Plusieurs indexers geres par un Cluster Manager (ex-Master). Les donnees sont repliquees entre indexers selon deux facteurs :\n   - Replication Factor (RF) : nombre de copies des donnees brutes (ex: RF=3 = 3 copies)\n   - Search Factor (SF) : nombre de copies des donnees indexees/searchable (ex: SF=2)\n   Assure la haute disponibilite : si un indexer tombe, les donnees restent accessibles sur les autres.\n\n2. SEARCH HEAD CLUSTER (SHC) : Plusieurs Search Heads synchronisent leurs configurations (saved searches, dashboards, alertes) via un Captain elu. Le SHC Deployer pousse les apps et configurations. Load balancer en facade pour distribuer les utilisateurs.\n\nEn production SOC typique : 3-10+ indexers, 3+ search heads, 1 cluster manager, 1 license master, 1 deployment server, des centaines/milliers de forwarders."
    }
  ],

  // ============================================================
  // 11. RACCOURCIS ET ASTUCES SPL
  // ============================================================
  tips: [
    {
      tip: "Utiliser le mode 'Fast' pour les recherches exploratoires",
      detail: "En haut a droite de la barre de recherche, changer le mode de 'Smart' a 'Fast'. Splunk ne calculera pas tous les champs, ce qui accelere enormement les recherches. Utiliser 'Verbose' uniquement quand vous avez besoin de tous les champs."
    },
    {
      tip: "Ctrl+Shift+E pour ouvrir le time picker rapide",
      detail: "Raccourci clavier utile pour changer rapidement la fenetre temporelle sans cliquer."
    },
    {
      tip: "Utiliser le Job Inspector pour debugger les performances",
      detail: "Apres une recherche, cliquer sur 'Job' > 'Inspect Job'. Montre le temps passe a chaque etape de la requete. Identifie les goulots d'etranglement."
    },
    {
      tip: "Commencer par | pour les generating commands",
      detail: "Les commandes qui generent leurs propres donnees commencent par un pipe : | inputlookup, | tstats, | rest, | makeresults. Pas besoin de clause 'search' avant."
    },
    {
      tip: "Utiliser makeresults pour tester des requetes",
      detail: "| makeresults count=5 | eval test_ip=random()%256.\".\".(random()%256).\".\".(random()%256).\".\".(random()%256) permet de generer des donnees de test sans interroger un index."
    },
    {
      tip: "Le underscore _ designe les champs internes",
      detail: "Les champs commencant par _ sont des champs internes Splunk : _time (timestamp), _raw (evenement brut), _indextime (heure d'indexation), _serial (numero de serie). _time et _raw sont les plus utilises."
    },
    {
      tip: "Utiliser 'rename' avec des guillemets pour les espaces",
      detail: "| rename src_ip AS \"Adresse IP Source\" - Les guillemets permettent des noms de champs avec espaces pour des tableaux lisibles."
    },
    {
      tip: "Wildcards dans les noms de champs avec foreach",
      detail: "| foreach bytes_* [eval <<FIELD>>_mb=round(<<FIELD>>/1024/1024,2)] - Applique une transformation a tous les champs matchant le pattern."
    },
    {
      tip: "Macro pour les requetes repetitives",
      detail: "Definir une macro dans Settings > Advanced Search > Search Macros. Utilisation : `ma_macro(argument1, argument2)`. Les backticks sont obligatoires. Permet de reutiliser des fragments SPL complexes."
    },
    {
      tip: "Utiliser 'addinfo' pour acceder aux metadonnees de la recherche",
      detail: "| addinfo ajoute des champs avec les metadonnees de la recherche : info_min_time, info_max_time, info_search_time. Utile pour des calculs relatifs a la fenetre temporelle."
    }
  ],

  // ============================================================
  // 12. VOCABULAIRE CLE SPLUNK-SOC (GLOSSAIRE)
  // ============================================================
  glossary: [
    { terme: "SPL", definition: "Search Processing Language - Le langage de requete de Splunk, base sur un systeme de pipes (|) similaire au shell Unix." },
    { terme: "Notable Event", definition: "Alerte de securite generee par une Correlation Search dans Splunk Enterprise Security. Equivalent d'un incident ou d'un ticket d'alerte." },
    { terme: "Correlation Search", definition: "Requete planifiee dans Splunk ES qui detecte des menaces et genere des Notable Events." },
    { terme: "Data Model", definition: "Representation structuree et hierarchique des donnees indexees, normalisee via le CIM. Base des recherches accelerees et de Splunk ES." },
    { terme: "Bucket", definition: "Unite de stockage physique dans un index Splunk. Les buckets passent par les etats : Hot (ecriture) > Warm > Cold > Frozen." },
    { terme: "Forwarder", definition: "Agent Splunk installe sur les machines sources pour collecter et transmettre les logs vers les indexers." },
    { terme: "Knowledge Object", definition: "Terme generique pour tout objet de configuration enrichissant les donnees : saved searches, lookups, field extractions, tags, event types, macros." },
    { terme: "Lookup", definition: "Table de correspondance (souvent CSV) utilisee pour enrichir les evenements avec des donnees externes (asset info, threat intel, etc.)." },
    { terme: "Sourcetype", definition: "Identifiant du format des donnees qui determine comment Splunk parse les evenements (timestamp, line breaking, field extraction)." },
    { terme: "App", definition: "Package Splunk complet avec interface, dashboards et configurations. Distribuee via Splunkbase." },
    { terme: "Add-on (TA)", definition: "Technology Add-on - Package sans interface fournissant inputs, field extractions et knowledge objects pour une source de donnees specifique." },
    { terme: "ESCU", definition: "Enterprise Security Content Update - Mises a jour regulieres de regles de detection alignees sur MITRE ATT&CK pour Splunk ES." },
    { terme: "Adaptive Response", definition: "Framework de Splunk ES permettant de declencher des actions automatisees en reponse aux detections (bloquer IP, desactiver compte, etc.)." },
    { terme: "RBA", definition: "Risk-Based Alerting - Approche attribuant des scores de risque aux entites au lieu de generer des alertes individuelles." },
    { terme: "SmartStore", definition: "Architecture de stockage hybride utilisant du stockage distant (S3, Azure Blob) pour le tier Cold, reduisant les couts de stockage local." },
    { terme: "Summary Index", definition: "Index contenant des resultats pre-calcules par des scheduled searches, permettant des rapports rapides sur de longues periodes." },
    { terme: "tsidx", definition: "Time Series Index - Format de fichier interne de Splunk pour les donnees indexees. Base des recherches performantes." },
    { terme: "Search Peer", definition: "Un indexer vu du point de vue du Search Head. Le SH distribue les recherches a ses search peers." },
    { terme: "Distributed Search", definition: "Mecanisme par lequel un Search Head distribue une requete a plusieurs indexers et fusionne les resultats." }
  ]
};

// Export pour utilisation dans d'autres modules si necessaire
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { splunkData };
}
