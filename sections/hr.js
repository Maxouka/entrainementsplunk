// ============================================================================
// HR Interview Preparation - SOC Analyst @ Sopra Steria
// Candidat : Maxime LAUNOY
// Date d'entretien : 25 février 2026 à 16h00
// ============================================================================

const hrData = {

  // --------------------------------------------------------------------------
  // PITCH - Trois versions selon le temps imparti
  // --------------------------------------------------------------------------
  pitch: {
    short: `Bonjour, je suis Maxime Launoy, ingénieur diplômé de l'INSA en 2024. Depuis un an, je travaille en sécurité informatique chez Harvest, une fintech, où je gère la sécurité d'un parc de plus de mille machines : durcissement, conformité ISO 27001, gestion des vulnérabilités. J'ai aussi été exposé aux outils SIEM et EDR dans le cadre de mes reportings sécurité. Je souhaite aujourd'hui rejoindre le SOC de Sopra Steria pour passer à l'opérationnel pur : détection, analyse d'alertes, investigation, et monter en compétences sur Splunk et le threat hunting.`,

    medium: `Bonjour, je suis Maxime Launoy, ingénieur diplômé de l'INSA promotion 2024. Depuis un an, j'occupe un poste en sécurité informatique chez Harvest, une fintech spécialisée dans la gestion de patrimoine. Mon quotidien, c'est la sécurité opérationnelle d'un parc de plus de mille machines : j'administre Tanium pour le patch management et le durcissement, j'ai piloté le déploiement en urgence de BitLocker sur tout le parc suite à une crise de sécurité, et je gère la conformité ISO 27001 avec des reportings hebdomadaires au COMEX. J'ai aussi une exposition aux outils SIEM Rapid7 InsightIDR et EDR Cybereason, je compilais les statistiques de sécurité pour les rapports direction et j'ai participé au déploiement manuel des agents EDR sur les machines critiques. Avant cela, j'ai fait un stage de quatre mois en infrastructure chez Harvest, où j'ai automatisé des tâches avec Ansible et mis en place du monitoring PRTG. Ce qui me motive chez Sopra Steria, c'est de passer du côté opérationnel de la détection : travailler dans un vrai SOC structuré, monter en compétences sur Splunk et le framework MITRE ATT&CK, et être exposé à des environnements clients variés.`,

    long: `Bonjour, je suis Maxime Launoy, ingénieur diplômé de l'INSA en 2024. Je suis trilingue français, russe et anglais, avec un niveau C1 certifié au TOEIC, et j'ai aussi un bon niveau en espagnol. Mon parcours en cybersécurité a commencé chez Harvest, une fintech qui gère des solutions de gestion de patrimoine pour les banques et CGP. J'y ai d'abord effectué un stage de quatre mois en infrastructure et exploitation, pendant lequel j'ai automatisé des déploiements avec Ansible et mis en place une supervision PRTG, j'ai notamment monté un serveur PRTG de test en local de ma propre initiative, avec déploiement de sondes via API et Ansible sur des VM. Cette expérience m'a donné une compréhension solide des infrastructures, ce qui est essentiel quand on fait de la cybersécurité : il faut comprendre ce qu'on protège. Ensuite, j'ai été embauché sur un poste dédié sécurité informatique. Pendant un an, j'ai géré la sécurité opérationnelle d'un parc de plus de mille machines : administration de Tanium pour le patch management et le durcissement, gestion des vulnérabilités, conformité ISO 27001. Un moment fort a été le déploiement en urgence de BitLocker sur tout le parc après une alerte critique : j'ai dû coordonner les équipes, gérer la pression du COMEX, et livrer en un temps record. J'ai aussi été exposé aux outils SIEM et EDR, j'utilisais Rapid7 InsightIDR et Cybereason pour compiler les statistiques et KPI de sécurité dans mes rapports hebdomadaires au COMEX, et j'ai participé au déploiement manuel des agents EDR sur les machines critiques. Ce n'était pas du SOC à proprement parler, mais ça m'a donné le goût de l'opérationnel et l'envie d'aller plus loin dans la détection et l'investigation. En parallèle, je me forme en continu : je m'entraîne sur Splunk, j'étudie le framework MITRE ATT&CK, et je développe un projet personnel en Next.js et React qui montre ma capacité à apprendre vite. Ce qui m'attire chez Sopra Steria, c'est la possibilité de rejoindre un vrai SOC structuré, de passer à l'opérationnel (détection, analyse d'alertes, investigation), de monter en compétences sur Splunk qui est le standard du marché, et de m'inscrire dans une trajectoire de carrière ambitieuse en cybersécurité. Je sais aussi que d'anciens camarades de l'INSA y travaillent et m'en parlent très positivement, ce qui renforce ma motivation.`
  },

  // --------------------------------------------------------------------------
  // QUESTIONS HR - Minimum 17 questions personnalisées
  // --------------------------------------------------------------------------
  questions: [
    // ---- 1. Présentation ----
    {
      category: "Présentation",
      q: "Présentez-vous",
      answer: `Je suis Maxime Launoy, ingénieur INSA promotion 2024, actuellement en poste en sécurité informatique chez Harvest, une fintech. Je gère la sécurité opérationnelle d'un parc de plus de mille machines : Tanium pour le patch management, BitLocker que j'ai déployé en urgence sur tout le parc, conformité ISO 27001, et reportings sécurité hebdomadaires au COMEX. J'ai aussi été exposé aux outils SIEM et EDR (InsightIDR et Cybereason) pour les statistiques de sécurité et j'ai participé au déploiement des agents EDR sur les machines critiques. Mon parcours combine une base solide en infrastructure (grâce à mon stage où j'ai fait de l'automatisation Ansible et du monitoring PRTG) et une expérience concrète en sécurité opérationnelle. Je suis trilingue français-russe-anglais et j'ai un esprit très orienté amélioration continue. Aujourd'hui, je souhaite rejoindre le SOC de Sopra Steria pour passer à l'opérationnel de détection et d'investigation, monter en compétences sur Splunk et le threat hunting, et construire une carrière ambitieuse en cybersécurité.`,
      tips: "Adapter la longueur selon le contexte. Si on dit 'en 2 minutes', utiliser le pitch long. Si 'brièvement', le pitch court. Toujours terminer par la motivation pour le poste."
    },

    // ---- 2. Pourquoi Sopra Steria ----
    {
      category: "Motivation entreprise",
      q: "Pourquoi Sopra Steria ?",
      answer: `Plusieurs raisons convergent. Premièrement, Sopra Steria est un acteur européen majeur de la cybersécurité avec une division dédiée qui travaille pour des clients grands comptes, c'est un environnement où je pourrai voir des problématiques variées et complexes, contrairement à un poste en interne où on est limité à un seul périmètre. Deuxièmement, la dimension ESN me permettra de monter en compétences rapidement en étant exposé à différents contextes, différents SIEM, différentes architectures. Troisièmement, j'ai des amis de l'INSA qui travaillent dans les équipes SOC de Sopra Steria et qui m'en parlent très positivement, notamment sur la qualité du management et les possibilités d'évolution. Enfin, Sopra Steria investit sérieusement dans la cybersécurité, c'est un axe stratégique du groupe, pas juste un département secondaire, et ça se voit dans les certifications, les partenariats technologiques et les offres proposées aux clients.`,
      tips: "Montrer qu'on a fait ses recherches. Citer des éléments concrets : la division cybersécurité, le statut d'acteur européen, la variété des clients. Mentionner les amis INSA de manière naturelle."
    },

    // ---- 3. Pourquoi la cybersécurité / le SOC ----
    {
      category: "Motivation métier",
      q: "Pourquoi la cybersécurité et pourquoi le SOC en particulier ?",
      answer: `La cybersécurité m'a attiré dès mes études parce que c'est un domaine où l'impact est concret et immédiat, on protège des données, des personnes, des entreprises. Chez Harvest, une fintech qui gère les données patrimoniales de millions de clients, j'ai mesuré à quel point les enjeux sont réels. Le SOC en particulier me passionne parce que c'est la ligne de front : on est dans l'opérationnel, on détecte, on analyse, on réagit. J'aime cette adrénaline et cette rigueur. Quand j'ai géré la crise BitLocker chez Harvest, j'ai vraiment compris que c'est dans ces moments-là que je donne le meilleur de moi-même. Le SOC, c'est aussi un formidable accélérateur de compétences : on touche au réseau, aux endpoints, au cloud, à la threat intelligence, au MITRE ATT&CK. C'est exactement la trajectoire que je veux pour ma carrière.`,
      tips: "Être passionné mais pas naïf. Montrer qu'on connaît la réalité du SOC (horaires, alertes, pression) et qu'on l'accepte."
    },

    // ---- 4. Vos forces ----
    {
      category: "Qualités",
      q: "Quelles sont vos principales forces ?",
      answer: `Ma première force, c'est ma capacité d'apprentissage rapide. En un an chez Harvest, je suis passé de stagiaire infrastructure à référent cybersécurité qui reporte au COMEX. Je me forme actuellement à Splunk en autonomie alors que ce n'est pas l'outil qu'on utilise chez Harvest, ça montre que je n'attends pas qu'on me donne les moyens, j'anticipe. Deuxième force : ma rigueur opérationnelle. Gérer la conformité ISO 27001, le suivi des vulnérabilités sur plus de mille VM, les reportings direction, ça demande de la méthode et de la constance. Troisième force : mon profil multiculturel et multilingue. Je parle couramment français, russe et anglais, avec un niveau B2 en espagnol. Dans un SOC qui traite des menaces internationales, c'est un vrai atout pour analyser des indicateurs de compromission, lire de la documentation technique variée, ou communiquer avec des équipes internationales. Enfin, j'ai une double compétence infrastructure et sécurité qui me permet de comprendre en profondeur ce que je protège.`,
      tips: "Chaque force doit être illustrée par un exemple concret. Ne pas être modeste à l'excès, c'est le moment de se vendre."
    },

    // ---- 5. Vos faiblesses ----
    {
      category: "Axes d'amélioration",
      q: "Quelles sont vos faiblesses ?",
      answer: `J'ai tendance à vouloir trop approfondir les sujets, ce qui peut parfois me faire passer plus de temps que nécessaire sur un sujet technique. Chez Harvest, quand je creuse une problématique de sécurité, je veux comprendre la cause racine plutôt que de juste traiter le symptôme. C'est une qualité, mais j'apprends à mieux prioriser. Ma principale faiblesse, c'est que je n'ai pas encore d'expérience opérationnelle en SOC pur : chez Harvest, mon rôle était centré sur la sécurité d'infrastructure et la conformité, pas sur la détection et l'investigation d'incidents au quotidien. Mais c'est précisément pour ça que ce poste m'attire et que je me forme activement sur Splunk. Mon expérience directe avec Splunk est en construction, mais les concepts SIEM sont transférables. Enfin, étant donné que je n'ai qu'un an d'expérience en cyber, je suis conscient qu'il me reste beaucoup à apprendre en matière de threat hunting et d'analyse de malware, mais j'ai la base solide et la motivation pour progresser rapidement.`,
      tips: "Toujours transformer la faiblesse en qualité ou en axe de progression actif. Ne jamais dire 'je suis perfectionniste' de manière générique, être spécifique avec des exemples."
    },

    // ---- 6. Défi surmonté (BitLocker) ----
    {
      category: "Expérience - Gestion de crise",
      q: "Racontez-moi un défi que vous avez surmonté",
      answer: `Le meilleur exemple, c'est le déploiement en urgence de BitLocker chez Harvest. Suite à une alerte de sécurité critique, la direction a exigé que l'intégralité du parc (plus de mille postes) soit chiffré avec BitLocker dans un délai très serré. C'était un vrai défi parce que ça touchait tous les collaborateurs, il fallait gérer les cas particuliers (machines anciennes, TPM non activés, postes distants) et surtout ne pas impacter la production d'une fintech où chaque minute d'indisponibilité coûte cher. J'ai structuré le projet en phases : d'abord un inventaire technique via Tanium pour identifier les machines compatibles et les cas problématiques, ensuite un déploiement par vagues avec des scripts automatisés, et en parallèle une communication aux utilisateurs pour minimiser les appels au support. J'ai coordonné avec l'équipe IT, le RSSI et le COMEX qui suivait l'avancement quotidiennement. Le résultat : on a atteint 100% de couverture dans les délais, avec un taux d'incident inférieur à 2%. Cette expérience m'a appris à garder la tête froide sous pression, à structurer un plan d'action rapidement, et à communiquer efficacement avec tous les niveaux de l'organisation.`,
      tips: "Utiliser la méthode STAR : Situation, Tâche, Action, Résultat. Insister sur les chiffres (1000+ postes, 100% couverture, <2% incidents). Montrer le leadership."
    },

    // ---- 7. Travail en équipe ----
    {
      category: "Soft skills",
      q: "Comment travaillez-vous en équipe ?",
      answer: `Je suis quelqu'un de naturellement collaboratif. Chez Harvest, je travaille au quotidien avec l'équipe IT pour les déploiements et les incidents, avec le RSSI pour la stratégie de sécurité, et avec la direction pour les reportings. Pendant la crise BitLocker, j'ai dû coordonner plusieurs équipes sous pression, ce qui m'a appris l'importance de la communication claire et régulière. Je crois beaucoup au partage de connaissances : quand je découvre une nouvelle technique d'attaque ou une bonne pratique, je la documente et la partage avec les collègues. Dans un SOC, le travail d'équipe est fondamental, on fait des passations de poste, on escalade les incidents, on partage les IOC. J'ai aussi l'expérience du travail en équipe projet à l'INSA, notamment sur mon projet TeachMe où j'ai travaillé avec d'autres développeurs en méthodologie agile. Je m'adapte facilement aux différents styles de travail et je suis aussi à l'aise en pair-working qu'en autonomie.`,
      tips: "Donner des exemples concrets de collaboration. Montrer qu'on comprend la dynamique spécifique d'un SOC (shifts, passations, escalades)."
    },

    // ---- 8. Gestion du stress ----
    {
      category: "Soft skills",
      q: "Comment gérez-vous le stress et la pression ?",
      answer: `Le stress fait partie intégrante de la cybersécurité, et j'ai appris à en faire un moteur plutôt qu'un frein. Chez Harvest, quand le COMEX demande un reporting urgent suite à une vulnérabilité critique publiée, ou quand il faut coordonner un déploiement d'urgence en parallèle du quotidien, j'ai développé un réflexe : je prends 30 secondes pour structurer ma réponse avant d'agir. Pendant la crise BitLocker, le stress était maximal, pression de la direction, deadline serrée, impact sur tous les collaborateurs, et c'est justement dans ces moments que je suis le plus concentré et efficace. Ma méthode : je décompose le problème en étapes, je priorise, et j'avance étape par étape sans me laisser paralyser par la vue d'ensemble. En dehors du travail, je maintiens un équilibre avec le sport et des activités qui me permettent de décompresser. Je suis aussi conscient que dans un SOC, il y a des pics d'activité et des périodes plus calmes, j'utilise les périodes calmes pour me former, améliorer les processus et préparer les périodes intenses.`,
      tips: "Ne pas dire qu'on ne stresse jamais (pas crédible). Montrer qu'on a une méthode de gestion et que le stress nous rend plus performant."
    },

    // ---- 9. Vision à 5 ans ----
    {
      category: "Projection",
      q: "Où vous voyez-vous dans 5 ans ?",
      answer: `Dans 5 ans, je me vois comme un analyste SOC senior ou un team lead SOC chez Sopra Steria. Mon plan : la première année, je monte en compétences sur Splunk, le framework MITRE ATT&CK, et les environnements clients spécifiques à Sopra Steria. Les années 2 et 3, je me spécialise, idéalement en threat hunting ou en création de use cases de détection avancés, et j'obtiens des certifications comme le CySA+ ou le GCIA. Années 4 et 5, j'évolue vers un rôle de référent technique ou de lead, où je peux encadrer des analystes juniors et contribuer à la stratégie de détection. Ce qui m'intéresse chez Sopra Steria, c'est que cette trajectoire est possible grâce à la diversité des missions et à la taille du groupe. Je ne me vois pas rester statique, je veux sans cesse progresser et apporter plus de valeur. À terme, je pourrais aussi envisager de m'orienter vers la réponse aux incidents ou le consulting en cybersécurité, mais toujours avec cette base SOC solide.`,
      tips: "Montrer de l'ambition mais rester réaliste. Aligner sa vision avec ce que Sopra Steria peut offrir. Ne pas dire qu'on veut monter sa boîte dans 5 ans."
    },

    // ---- 10. Pourquoi vous recruter ----
    {
      category: "Argumentaire",
      q: "Pourquoi devrions-nous vous recruter ?",
      answer: `Vous devriez me recruter pour trois raisons. Premièrement, j'apporte une expérience concrète en sécurité opérationnelle. Depuis un an chez Harvest, je gère la sécurité d'un parc de plus de mille machines : durcissement, Tanium, BitLocker, conformité ISO 27001, reportings au COMEX. J'ai touché au SIEM et à l'EDR pour les statistiques et le déploiement, ce qui me donne une base pour évoluer vers l'opérationnel SOC. Deuxièmement, j'ai un profil qui combine infrastructure et sécurité. Mon stage en exploitation m'a donné une compréhension des systèmes que je protège (réseaux, serveurs, Active Directory), ce qui me rendra plus efficace en tant qu'analyste SOC. Troisièmement, j'ai un potentiel de croissance rapide. En un an, je suis passé de stagiaire à référent sécurité qui reporte au COMEX. Je me forme déjà à Splunk en autonomie. Je suis trilingue, ce qui est un atout pour un SOC qui traite des menaces internationales. Et surtout, je suis motivé, je veux passer à l'opérationnel de détection et d'investigation, c'est une vraie envie, pas juste un plan de carrière. Je suis prêt à m'investir pleinement et à apporter de la valeur dès le premier jour.`,
      tips: "Être affirmatif et confiant. Structurer en points clairs. Terminer sur la motivation et l'engagement."
    },

    // ---- 11. Prétentions salariales ----
    {
      category: "Rémunération",
      q: "Quelles sont vos prétentions salariales ?",
      answer: `Sur la base de mon profil, ingénieur INSA avec un an d'expérience en sécurité informatique, trilingue, et compte tenu du marché actuel pour un analyste SOC en région, je me positionne sur une fourchette de 38 000 à 42 000 euros brut annuel. C'est une fourchette que j'ai établie en tenant compte de la grille Sopra Steria pour les profils juniors et du fait que j'apporte une base solide en infrastructure et sécurité, même si le SOC sera un nouvel environnement pour moi. Cela dit, la rémunération n'est pas mon critère principal : ce qui compte le plus pour moi, c'est la qualité des missions, les possibilités de formation et de certification, et la trajectoire d'évolution. Je suis ouvert à la discussion sur le package global, fixe, variable, avantages.`,
      tips: "Donner une fourchette, pas un chiffre fixe. Justifier par des éléments objectifs. Relativiser en montrant que la mission compte plus. Ne jamais donner son salaire actuel en premier."
    },

    // ---- 12. Parlez d'un échec ----
    {
      category: "Expérience - Résilience",
      q: "Parlez-moi d'un échec professionnel",
      answer: `Au début de mon poste en cybersécurité chez Harvest, j'ai voulu mettre en place une politique de durcissement des mots de passe très agressive : longueur minimale élevée, complexité maximale, rotation fréquente. Sur le papier, c'était la bonne pratique de sécurité. En réalité, ça a généré une avalanche de tickets au support, des utilisateurs qui notaient leurs mots de passe sur des post-it, et finalement un recul en termes de sécurité réelle. J'ai dû faire marche arrière et adopter une approche plus pragmatique avec des passphrases plus longues mais plus simples à retenir, combinées avec du MFA. Ce que j'ai appris : en cybersécurité, la meilleure politique technique du monde ne vaut rien si elle ne prend pas en compte le facteur humain. Depuis, j'intègre toujours la dimension utilisateur dans mes recommandations. C'est une leçon que j'applique quotidiennement et qui fait de moi un meilleur professionnel de la sécurité.`,
      tips: "Choisir un échec réel mais pas catastrophique. Toujours montrer ce qu'on en a appris. Ne jamais blâmer les autres."
    },

    // ---- 13. Gestion des conflits ----
    {
      category: "Soft skills",
      q: "Comment gérez-vous les conflits au travail ?",
      answer: `En cybersécurité, les « conflits » sont souvent des tensions entre sécurité et productivité, quand on veut restreindre un accès ou imposer une mesure que les métiers trouvent contraignante. Chez Harvest, j'ai régulièrement eu ces discussions, notamment pour le déploiement de BitLocker qui impactait les habitudes de travail de tout le monde. Ma méthode : j'écoute d'abord pour comprendre le point de vue de l'autre partie. Ensuite, j'explique le « pourquoi » de la mesure de sécurité en termes business, pas en jargon technique, par exemple, « si on ne chiffre pas les disques, une clé USB perdue dans le train peut exposer les données patrimoniales de nos clients et entraîner une amende RGPD de plusieurs millions ». Enfin, je cherche un compromis qui satisfait la sécurité sans être excessivement contraignant. Si un vrai conflit interpersonnel se présentait, je privilégie toujours le dialogue direct et factuel, en privé, avant d'escalader. L'objectif est de résoudre le problème, pas de gagner le débat.`,
      tips: "Montrer qu'on est diplomate mais ferme sur les enjeux de sécurité. Utiliser des exemples concrets. Ne jamais paraître conflictuel."
    },

    // ---- 14. Pourquoi quitter / chercher ailleurs ----
    {
      category: "Motivation changement",
      q: "Pourquoi quittez-vous votre poste actuel ? / Pourquoi chercher ailleurs ?",
      answer: `Je tiens à préciser que je ne quitte pas Harvest par insatisfaction, j'ai beaucoup appris et l'environnement est bon. Mais après un an, j'arrive à un point où j'ai fait le tour de ce que le poste peut m'offrir en termes de progression technique. Chez Harvest, je suis le seul professionnel dédié cybersécurité, ce qui m'a donné beaucoup d'autonomie et de responsabilités, mais ça signifie aussi que je n'ai pas de mentor technique senior pour m'aider à progresser, et que les outils et budgets sont limités. Ce que je cherche chez Sopra Steria, c'est un environnement SOC structuré avec des experts dont je peux apprendre, une exposition à Splunk qui est le standard du marché, une diversité de clients et d'environnements qui va accélérer ma montée en compétences, et une trajectoire de carrière claire dans un grand groupe. C'est une démarche positive de progression, pas une fuite.`,
      tips: "Ne JAMAIS critiquer l'employeur actuel. Toujours cadrer le départ comme une recherche de progression. Mettre en avant ce que Sopra Steria offre de plus."
    },

    // ---- 15. Télétravail et mobilité ----
    {
      category: "Organisation",
      q: "Quelle est votre position sur le télétravail et la mobilité ?",
      answer: `Je suis basé dans les Alpes-Maritimes et je suis mobile sur l'ensemble de la France, y compris pour une relocalisation si le poste l'exige. Concernant le télétravail, je suis pragmatique : dans un SOC, certaines tâches nécessitent une présence sur site, accès à des environnements sécurisés, gestion d'incidents critiques, coordination d'équipe, et d'autres peuvent se faire à distance comme l'analyse d'alertes de routine ou la rédaction de documentation. Je m'adapte à la politique de l'entreprise et du client. L'essentiel pour moi, c'est de pouvoir contribuer efficacement à l'équipe. Si Sopra Steria a une politique hybride, ça me convient parfaitement. Et si certaines missions exigent du full présentiel, je suis prêt aussi.`,
      tips: "Être flexible et pragmatique. Ne pas exiger du full remote pour un poste SOC. Montrer qu'on comprend les contraintes de sécurité."
    },

    // ---- 16. Veille cybersécurité ----
    {
      category: "Formation continue",
      q: "Comment restez-vous à jour en cybersécurité ?",
      answer: `J'ai plusieurs canaux de veille. Au quotidien, je suis les feeds Twitter/X de chercheurs en sécurité comme ceux de The DFIR Report, je lis les bulletins CERT-FR et les advisories des éditeurs. Pour la formation technique, je m'entraîne sur Splunk, d'où le projet d'entraînement que j'ai monté, et j'explore les labs Hack The Box et TryHackMe. Je suis aussi la base MITRE ATT&CK pour comprendre les nouvelles techniques d'attaque documentées. Côté actualités, je lis régulièrement Bleeping Computer, The Hacker News et je suis abonné aux newsletters SANS. J'utilise aussi des outils d'IA comme ChatGPT et Claude pour accélérer ma compréhension de concepts techniques complexes, je considère que maîtriser ces outils fait partie des compétences d'un analyste moderne. Enfin, j'ai un intérêt pour la blockchain et le Web3, ce qui me donne une perspective sur les nouvelles surfaces d'attaque liées aux crypto-actifs et aux smart contracts. Je prévois aussi de passer des certifications comme le CySA+ de CompTIA dans les prochains mois.`,
      tips: "Montrer qu'on est proactif et passionné. Citer des sources précises (pas juste 'je lis des articles'). Mentionner les projets personnels de formation."
    },

    // ---- 17. Connaissance de Sopra Steria ----
    {
      category: "Connaissance entreprise",
      q: "Que savez-vous de Sopra Steria ?",
      answer: `Sopra Steria est un leader européen du conseil, des services numériques et de l'édition de logiciels, né de la fusion de Sopra Group et Steria en 2014. Le groupe emploie environ 56 000 collaborateurs et réalise un chiffre d'affaires de plus de 5,8 milliards d'euros. En cybersécurité, Sopra Steria dispose d'une division dédiée qui est un acteur majeur du marché français et européen, avec des SOC qui protègent des clients grands comptes dans la défense, la banque, l'industrie et le secteur public. Le groupe a d'ailleurs lui-même vécu une cyberattaque par le ransomware Ryuk en 2020, ce qui lui donne une compréhension concrète des enjeux de cybersécurité, ils savent de quoi ils parlent quand ils protègent leurs clients. Sopra Steria est coté au SBF 120, est engagé dans une démarche RSE forte, et investit significativement dans l'innovation, notamment sur l'IA et le cloud souverain. C'est une entreprise qui a les moyens de ses ambitions en cybersécurité, et c'est ce qui m'attire.`,
      tips: "Connaître les chiffres clés. Mentionner la cyberattaque Ryuk de 2020 montre qu'on a fait ses devoirs. Ne pas réciter comme un Wikipedia, montrer qu'on comprend ce que ça implique."
    },

    // ---- 18. Expérience avec les outils SIEM (question technique légère) ----
    {
      category: "Compétences techniques",
      q: "Vous utilisez Rapid7 InsightIDR et le poste demande Splunk. Comment comptez-vous combler cet écart ?",
      answer: `C'est une très bonne question et j'y ai déjà réfléchi. Chez Harvest, j'ai été exposé à InsightIDR principalement pour les statistiques et les reportings sécurité, je ne faisais pas d'analyse SOC au quotidien, mais j'ai compris la logique SIEM : collecte de logs, corrélation, alerting. Les concepts fondamentaux sont transférables entre tous les SIEM, ce qui change c'est la syntaxe de requête et l'interface. Pour Splunk spécifiquement, j'ai déjà commencé à me former en autonomie : j'ai monté un environnement d'entraînement personnel où je pratique le SPL, le langage de requête Splunk, avec des jeux de données réalistes. Je travaille sur les dashboards, les alertes, les lookups, et je me familiarise avec l'écosystème Splunk Enterprise Security. En parallèle, j'étudie la documentation officielle Splunk et les ressources BOTSv. Ma compréhension de l'infrastructure, réseau, Active Directory, endpoints, est un atout pour un analyste SOC, et combinée à ma formation proactive sur Splunk, je suis confiant de pouvoir être opérationnel rapidement.`,
      tips: "Montrer qu'on est proactif et qu'on n'attend pas d'avoir le poste pour se former. Insister sur la transférabilité des compétences SIEM."
    },

    // ---- 19. Travail en horaires décalés ----
    {
      category: "Organisation",
      q: "Le SOC implique parfois des astreintes ou des horaires décalés. Ça vous convient ?",
      answer: `Oui, tout à fait. Je suis conscient que la cybersécurité ne s'arrête pas à 18h, les attaquants ne respectent pas les heures de bureau. Chez Harvest, il m'est déjà arrivé de gérer des urgences de sécurité en dehors des heures normales, notamment pendant la crise BitLocker où j'ai dû travailler le week-end. Je considère que c'est inhérent au métier d'analyste SOC et c'est aussi ce qui rend ce métier stimulant. Je n'ai pas de contraintes personnelles majeures qui m'empêcheraient de faire des astreintes ou de travailler en horaires décalés. L'essentiel, c'est que le système de rotation soit bien organisé et équitable, ce qui est généralement le cas dans les SOC structurés comme celui de Sopra Steria.`,
      tips: "Être honnête et positif. Ne pas dire qu'on adore travailler la nuit si ce n'est pas vrai. Montrer qu'on comprend la réalité du métier."
    },

    // ---- 20. Gestion de la routine ----
    {
      category: "Soft skills",
      q: "Le SOC peut être répétitif, traitement d'alertes similaires chaque jour. Comment gérez-vous la routine ?",
      answer: `Je comprends que le traitement d'alertes peut sembler répétitif vu de l'extérieur, mais chaque alerte est potentiellement unique, c'est souvent dans le bruit que se cache une vraie menace. Chez Harvest, même si mon rôle n'était pas du SOC pur, j'avais des tâches récurrentes, reportings hebdomadaires, suivi des vulnérabilités, conformité, et mon réflexe face à la répétition, c'est d'automatiser ou d'optimiser. Par exemple, j'ai structuré mes rapports de sécurité pour le COMEX de manière à les rendre plus efficaces à produire tout en étant plus lisibles. J'utilise aussi les périodes plus calmes pour me former et améliorer les processus. Dans un SOC, je sais qu'on n'est jamais vraiment dans la routine si on cherche constamment à réduire les faux positifs, améliorer les règles de détection, et documenter les procédures. C'est cette mentalité d'amélioration continue qui me caractérise.`,
      tips: "Montrer qu'on ne subit pas la routine mais qu'on la transforme en opportunité d'amélioration. Mentionner l'automatisation."
    }
  ],

  // --------------------------------------------------------------------------
  // QUESTIONS À POSER AU RECRUTEUR
  // --------------------------------------------------------------------------
  questionsToAsk: [
    {
      q: "Comment est structurée l'équipe SOC chez Sopra Steria ? Combien d'analystes, quels niveaux (L1, L2, L3) ?",
      why: "Montre qu'on comprend la hiérarchie SOC et qu'on veut savoir où on se positionne."
    },
    {
      q: "Quels sont les principaux outils utilisés dans le SOC en plus de Splunk ? (SOAR, threat intelligence, EDR...)",
      why: "Question technique pertinente qui montre un intérêt pour l'écosystème complet."
    },
    {
      q: "Quel est le parcours de montée en compétences prévu pour un analyste qui rejoint l'équipe ? Y a-t-il un plan de formation ou de certification ?",
      why: "Montre une volonté de progression et d'investissement long terme."
    },
    {
      q: "Pour quels types de clients travaille le SOC ? Plutôt secteur public, bancaire, industriel ?",
      why: "Montre une curiosité pour le métier et permet de se projeter dans les missions."
    },
    {
      q: "Comment se passe l'intégration d'un nouvel analyste ? Y a-t-il un système de mentorat ou de binôme ?",
      why: "Question pragmatique qui montre qu'on pense déjà à son arrivée et qu'on veut être opérationnel vite."
    },
    {
      q: "Quels sont les plus grands défis actuels de l'équipe SOC ?",
      why: "Question stratégique qui montre qu'on veut comprendre les enjeux et contribuer à les résoudre."
    },
    {
      q: "Y a-t-il des opportunités de participer à la création de use cases de détection ou à l'amélioration des playbooks ?",
      why: "Montre une ambition au-delà du simple traitement d'alertes, on veut créer de la valeur."
    },
    {
      q: "Quelles sont les prochaines étapes du processus de recrutement et quel est le calendrier envisagé ?",
      why: "Question classique mais essentielle pour connaître la suite et montrer son intérêt."
    }
  ],

  // --------------------------------------------------------------------------
  // CONSEILS POUR MENTIONNER SON RÉSEAU INSA
  // --------------------------------------------------------------------------
  networkTips: {
    howToMention: "Mentionner les amis INSA de manière naturelle, comme un élément parmi d'autres dans la motivation. Ne jamais en faire l'argument principal. L'idéal est de le glisser dans la réponse à 'Pourquoi Sopra Steria ?' ou 'Comment avez-vous connu le poste ?'. Le réseau doit renforcer la motivation, pas la remplacer.",
    phrases: [
      "J'ai d'anciens camarades de l'INSA qui travaillent dans vos équipes SOC et qui m'en ont parlé très positivement.",
      "Des amis de ma promo à l'INSA m'ont confirmé la qualité de l'environnement technique et du management dans la division cybersécurité.",
      "C'est d'ailleurs par mon réseau INSA que j'ai découvert l'opportunité, les retours que j'ai eus sur l'ambiance et les projets m'ont motivé à postuler.",
      "Sans entrer dans les détails, des personnes de confiance que j'ai à l'INSA et qui travaillent chez vous m'ont décrit un environnement stimulant et bienveillant."
    ],
    doNots: [
      "Ne jamais donner de noms sans leur accord préalable.",
      "Ne pas dire 'mon ami peut confirmer que je suis bon', ça fait pistonné.",
      "Ne pas laisser entendre qu'on attend un traitement de faveur grâce au réseau.",
      "Ne pas insister si le recruteur ne relève pas, une mention suffit.",
      "Ne pas mentionner le réseau plus de deux fois dans tout l'entretien.",
      "Ne pas dire 'ils m'ont dit que c'était facile d'être embauché' ou toute information interne confidentielle."
    ]
  },

  // --------------------------------------------------------------------------
  // CONSEILS SALAIRE
  // --------------------------------------------------------------------------
  salaryAdvice: {
    range: "38 000 – 42 000 € brut annuel",
    justification: "Fourchette basée sur : profil ingénieur INSA (école reconnue), 1 an d'expérience opérationnelle en cybersécurité (pas juste un stage), compétences SIEM/EDR directement opérationnelles, trilinguisme, marché tendu en cybersécurité où la demande dépasse l'offre. La fourchette tient aussi compte du fait que Sopra Steria est une ESN (grilles généralement un peu en dessous du marché final) mais que le poste est en cybersécurité (prime sectorielle). En région PACA, les salaires sont légèrement inférieurs à l'Île-de-France.",
    phrases: [
      "Je me positionne sur une fourchette de 38 à 42k€ brut annuel, en cohérence avec mon profil et le marché.",
      "La rémunération est importante, mais ce qui me motive avant tout c'est la qualité de la mission et les perspectives d'évolution.",
      "Je suis ouvert à discuter du package global, fixe, primes, avantages, plan de formation.",
      "Avant de parler chiffres, j'aimerais mieux comprendre le périmètre exact du poste et les avantages proposés.",
      "Si vous avez une grille, je suis curieux de voir comment mon profil s'y positionne."
    ]
  },

  // --------------------------------------------------------------------------
  // CONSEILS GÉNÉRAUX POUR L'ENTRETIEN
  // --------------------------------------------------------------------------
  generalTips: [
    "Arriver 10 minutes en avance, ni plus, ni moins. Si c'est en visio, se connecter 5 minutes avant et tester micro/caméra.",
    "Préparer un verre d'eau à portée de main pour éviter la gorge sèche.",
    "Habillé smart casual : chemise ou polo propre, pas de costume cravate pour un entretien SOC, mais pas non plus un t-shirt.",
    "Imprimer 2 copies de son CV au cas où, même pour un entretien visio (pour l'avoir sous les yeux).",
    "Commencer par une poignée de main ferme (en présentiel) et un sourire naturel.",
    "Écouter la question COMPLÈTEMENT avant de commencer à répondre. Prendre 2-3 secondes de réflexion, c'est normal et ça montre la maturité.",
    "Utiliser la méthode STAR pour toutes les questions comportementales : Situation, Tâche, Action, Résultat.",
    "Maintenir le contact visuel, pas fixement, mais régulièrement. En visio, regarder la caméra, pas l'écran.",
    "Si on ne comprend pas une question, demander de la reformuler. C'est un signe d'intelligence, pas de faiblesse.",
    "Ne jamais mentir ou exagérer, les recruteurs vérifient et les techniciens repèrent les incohérences.",
    "Garder au moins 2-3 questions à poser à la fin. Ne jamais dire 'non, je n'ai pas de questions'.",
    "Prendre des notes pendant l'entretien, ça montre de l'intérêt et de la rigueur.",
    "Si le recruteur mentionne un sujet technique qu'on ne maîtrise pas, être honnête : 'Je n'ai pas encore travaillé dessus directement, mais voilà comment je m'y formerais...'",
    "Envoyer un email de remerciement dans les 24h suivant l'entretien. Court, professionnel, personnalisé avec un élément de la conversation.",
    "Se rappeler que l'entretien est un échange, pas un interrogatoire. Le recruteur aussi cherche à vérifier un fit mutuel.",
    "Avoir en tête 3 chiffres clés de son expérience : 1000+ machines gérées, 100% de couverture BitLocker, conformité ISO 27001.",
    "Ne pas oublier de sourire et d'être humain, les recruteurs embauchent des personnes, pas des robots techniques.",
    "Préparer un 'plan B' mental : si on sent que l'entretien tourne mal sur un sujet, avoir un pivot pour revenir sur un terrain favorable (ex: revenir sur l'expérience Harvest)."
  ],

  // --------------------------------------------------------------------------
  // QUESTIONS INSIDER, Leakées par un analyste SOC actuel chez Sopra Steria
  // CE SONT LES VRAIES QUESTIONS DU RH. À CONNAÎTRE PAR CŒUR.
  // --------------------------------------------------------------------------
  insiderQuestions: [
    {
      number: 1,
      q: "Qu'avez-vous appris par vous-même lors de vos différentes missions, sans que cela soit demandé par votre management ?",
      why: "Ils testent ton INITIATIVE et ta CURIOSITÉ. C'est LA question qui sépare les passionnés des exécutants. Ils veulent voir que tu ne fais pas juste ce qu'on te demande.",
      answer: `Ce que j'ai le plus appris par moi-même, c'est à prendre des initiatives quand une tâche peut être optimisée.

Exemple concret : on m'a demandé d'installer manuellement des sondes PRTG sur des machines virtuelles hors couverture de monitoring. C'était une tâche répétitive sur plus de 100 VM. Plutôt que de le faire à la main, j'ai pris le temps d'apprendre Ansible par moi-même pour automatiser le déploiement. J'ai scripté en PowerShell via l'API de PRTG pour déposer les sondes, et utilisé Ansible pour modifier les configurations sur chaque machine au préalable.

Et surtout, comme je débutais sur ces outils, j'ai eu le réflexe de monter un environnement de test en local : un serveur PRTG de test, des VM de test, pour valider ma solution avant de la proposer. La solution a été retenue et utilisée en production.

L'autre chose que j'ai apprise par curiosité, c'est la prise en main du SIEM. Mon poste était orienté sécurité opérationnelle : hardening, conformité ISO 27001, veille, patch management. Mais on travaillait en proximité avec la SSI qui gérait le SIEM. J'ai demandé à avoir accès, ils nous ont formés et laissé traiter des alertes non complexes. C'est cette curiosité pour le côté investigation qui m'a donné envie d'en faire mon métier.`,
      tips: "Commence par l'exemple Ansible/PRTG (c'est le plus fort), le SIEM garde-le plus court comme deuxième couche. Ne dis pas 'monotone/chiant', dis 'répétitif' ou 'optimisable'. Structure naturelle : initiative + rigueur (env de test) + curiosité (SIEM).",
      keyPoints: [
        "Ansible + PRTG + API sur 100+ VM = initiative concrète avec chiffres",
        "Environnement de test en local = rigueur et prudence",
        "Solution retenue et utilisée en production = résultat tangible",
        "SIEM par curiosité = transition naturelle vers le SOC",
        "Tout est VRAI et vérifiable"
      ]
    },
    {
      number: 2,
      q: "Si on vous avait donné carte blanche, quel est le premier point que vous auriez amélioré dans votre dernière mission ?",
      why: "Ils testent ta VISION CRITIQUE et ta capacité à prendre du recul. Attention : ne pas taper sur l'ex-employeur, mais montrer une réflexion constructive.",
      answer: `Si j'avais eu carte blanche, j'aurais automatisé le processus de veille vulnérabilités.

Chaque semaine, je devais passer plusieurs heures à éplucher manuellement les bulletins du CERT, vérifier pour chaque CVE si elle concernait un outil de notre parc, comparer les versions pour savoir si on était impacté, puis créer les fiches Jira une par une. Tout ça alimentait un rapport hebdomadaire présenté au COMEX et au comité de sécurité.

Ce que j'aurais aimé construire, c'est un système qui croise automatiquement les bulletins CERT avec notre inventaire d'assets et de versions. A chaque nouvelle publication, il détecte ce qui nous concerne, flag les versions impactées, et pré-génère les fiches. Le rapport serait alimenté automatiquement avec les données complémentaires comme l'état des sauvegardes.

Aujourd'hui avec l'IA et les outils disponibles, c'est tout à fait faisable. C'est le genre de tâche répétitive à forte valeur ajoutée qui mérite d'être automatisée pour que l'analyste se concentre sur l'analyse et la remédiation plutôt que sur la collecte.`,
      tips: "Ne dis pas 'c'était relou', dis 'chronophage' ou 'ça prenait un temps disproportionné par rapport à la valeur'. Insiste sur le fait que tu aurais voulu le faire mais le temps manquait, ça montre de la frustration constructive. Tu montres un vrai pain point opérationnel, pas un truc vague.",
      keyPoints: [
        "Veille CERT manuelle = pain point concret et identifiable",
        "Chaîne complète : CERT → CVE → versions → Jira → rapport COMEX",
        "Solution proposée réaliste : croisement automatique assets/bulletins",
        "Mention de l'IA pertinente et naturelle ici",
        "Mindset d'optimisation = exactement ce qu'un SOC recherche"
      ]
    },
    {
      number: 3,
      q: "Pourquoi avez-vous choisi la cybersécurité ? Qu'est-ce qui vous motive dans ce domaine ?",
      why: "ATTENTION : ils vont CHALLENGER ta sincérité. Si tu dis 'je suis passionné', ils vont creuser avec des exemples concrets (CTF, projets perso, veille, etc.). Sois AUTHENTIQUE. Ne surjoue pas la passion, reste naturel.",
      answer: `J'ai grandi dans le numérique et les jeux vidéo, donc l'informatique c'était le chemin naturel. C'est à l'INSA pendant les cours de cybersécurité que le déclic s'est fait.

Ce qui me motive, c'est plusieurs choses. D'abord le côté investigation. Quand j'ai pu toucher au SIEM chez Harvest par curiosité, j'ai retrouvé ce que j'aime : comprendre ce qui s'est passé, remonter un fil, c'est comme un escape game ou une enquête. C'est stimulant intellectuellement. Et c'est justement ce que je ne retrouvais pas assez dans mon rôle précédent qui était plus orienté conformité.

Ensuite, c'est un domaine qui ne stagne jamais. L'intersection avec l'IA par exemple me fascine autant qu'elle m'inquiète. On voit que les attaques évoluent, que les fuites de données deviennent régulières, et je trouve qu'il y a un vrai sens à protéger les gens dans ce contexte.

Pour être honnête, je ne suis pas un acharné de CTF. J'en fais quand le thème m'accroche, par exemple un CTF sur le thème Resident Evil, c'est fun. Mais ce qui me drive au quotidien c'est plus le côté défense et utilité concrète que le côté compétition.`,
      tips: "C'est ta VRAIE histoire : jeux vidéo → INSA → déclic → investigation. L'honnêteté sur les CTF est ta meilleure arme. Si le recruteur challenge ('mais vous faites quoi en CTF ?'), réponds : 'Mon côté investigation, je le pratique autrement : en crypto je trace des wallets sur Solscan et Etherscan, c'est de l'OSINT blockchain. Et chez Harvest j'ai demandé à accéder au SIEM par curiosité.' C'est le moment de glisser l'OSINT naturellement.",
      keyPoints: [
        "Parcours naturel : jeux vidéo → INSA → déclic cyber",
        "Investigation = escape game, stimulant intellectuellement",
        "Harvest trop orienté conformité, veut du dynamique",
        "IA x cyber = intersection qui fascine et inquiète",
        "CTF assumé : pas un acharné mais curieux quand le thème accroche",
        "Si challenge CTF → pivoter sur crypto/OSINT blockchain (Solscan, Etherscan)"
      ]
    },
    {
      number: 4,
      q: "Question technique : lecture de logs, décrire succinctement ce qui se passe et quels pivots vous feriez.",
      why: "C'est le TEST PRATIQUE. Ils vont te montrer un extrait de log (Windows, Sysmon, ou réseau) et tu dois analyser en direct. Pas besoin d'être parfait, mais montrer ta MÉTHODOLOGIE.",
      answer: `══════════════════════════════════════════
C'EST QUOI UN PIVOT ?
══════════════════════════════════════════

Le pivot c'est LE concept central du travail d'analyste SOC. C'est la technique qui consiste à PARTIR D'UN INDICE ET REBONDIR DESSUS POUR EN TROUVER D'AUTRES, comme un enquêteur qui tire un fil.

Exemple concret :
1. Tu reçois une alerte : connexion suspecte depuis l'IP 185.220.101.34
2. Tu PIVOTES sur l'IP → tu cherches tous les hôtes qui ont communiqué avec cette IP
3. Tu trouves que la machine PC-MARTIN a contacté cette IP
4. Tu PIVOTES sur le hostname PC-MARTIN → tu cherches tout ce que cette machine a fait récemment
5. Tu trouves qu'un fichier update.exe a été exécuté
6. Tu PIVOTES sur le hash du fichier → tu le cherches sur VirusTotal et dans tout le parc
7. Tu trouves 3 autres machines avec le même fichier
→ Chaque indice ouvre une nouvelle porte.

Les champs de pivot les plus courants :
• IP → quelles machines communiquent avec
• Hostname → toute l'activité de cette machine
• Username → tout ce que cet utilisateur a fait
• Hash (MD5/SHA256) → où ce fichier existe dans le parc
• Process name → quelles machines l'ont exécuté
• Domain/URL → qui a visité ce site

QUAND PARLER DE PIVOT EN ENTRETIEN :
→ L'interviewer te montre des logs et demande "Qu'est-ce que tu vois ?"
→ Tu décris factuellement (30 sec)
→ Puis IL VA demander "Et ensuite tu fais quoi ?"
→ C'est LÀ que tu parles de pivot : "Je pivote sur l'IP source pour voir si elle a ciblé d'autres comptes, puis sur le hostname pour voir ce qui s'est passé après la compromission..."
→ Si on ne te le demande pas, amène-le TOI-MÊME après ton analyse.

══════════════════════════════════════════
MÉTHODOLOGIE EN 3 ÉTAPES
══════════════════════════════════════════

ÉTAPE 1, LIRE les champs clés
→ QUAND : timestamp
→ QUI : utilisateur (Account_Name)
→ OÙ : machine/IP (src_ip, dest_ip, hostname)
→ QUOI : action (EventCode, le message à côté te dit ce que c'est)
→ COMMENT : détails (CommandLine, ParentImage, LogonType)

ÉTAPE 2, DÉCRIRE en une phrase
→ "Je vois X échecs de login suivis d'un succès, depuis la même IP, en quelques secondes. C'est un brute force réussi."

ÉTAPE 3, PIVOTER (c'est LÀ qu'ils jugent ton niveau)
→ "À partir de là, je pivoterais sur l'IP source pour voir si elle a ciblé d'autres comptes, sur le hostname pour voir ce qui s'est passé après le login, et je vérifierais l'IP sur VirusTotal."

══════════════════════════════════════════
LES 5 EVENT CODES À CONNAÎTRE
══════════════════════════════════════════

• 4624 = Login OK
• 4625 = Login ÉCHOUÉ (brute force si en rafale)
• 4672 = Droits admin utilisés
• 7045 = Service installé (= persistance)
• 1102 = Quelqu'un a effacé les logs

Si tu ne reconnais pas un code → le MESSAGE à côté te dit ce que c'est. Dis : "Je ne connais pas ce code par cœur, mais je vois dans le message qu'il s'agit de [lire la description]. En situation réelle, je vérifierais dans la documentation."

══════════════════════════════════════════
EXEMPLE COMPLET, CE QUE TU DIS EN ENTRETIEN
══════════════════════════════════════════

Si on te montre :
  EventCode=4625 Account_Name=j.martin Src_IP=185.220.101.34 (×4)
  EventCode=4624 Account_Name=j.martin Src_IP=185.220.101.34

Tu dis :
"Je vois 4 événements 4625, des échecs d'authentification, sur le compte j.martin, suivis d'un 4624, un login réussi, le tout depuis la même IP externe en quelques secondes. C'est un brute force réussi.

À partir de là je pivoterais sur 3 axes :
1. Sur l'IP source, est-ce qu'elle a ciblé d'autres comptes ?
2. Sur le hostname cible, qu'est-ce qui s'est passé sur cette machine après le login ?
3. Threat intel, je vérifierais cette IP sur VirusTotal ou AbuseIPDB."

Note : les logs dans un SIEM comme Splunk ne sont PAS brutes, elles sont parsées avec des champs nommés (src_ip, Account_Name, etc.). Tu travailles avec un tableau propre, pas du XML illisible.

══════════════════════════════════════════
CAS CONCRET 2 : SQL INJECTION (logs web)
══════════════════════════════════════════

185.43.12.8 - - [25/Feb/2026:14:22:01] "GET /search?q=test' OR 1=1-- HTTP/1.1" 200 4532
185.43.12.8 - - [25/Feb/2026:14:22:03] "GET /search?q=test' UNION SELECT username,password FROM users-- HTTP/1.1" 200 8921
185.43.12.8 - - [25/Feb/2026:14:22:05] "GET /search?q=test' UNION SELECT credit_card,cvv FROM payments-- HTTP/1.1" 200 12340

Tu dis :
"Je vois des requêtes GET depuis la même IP avec des payloads SQL injection dans le paramètre de recherche. Le premier test avec OR 1=1 c'est une vérification classique que l'injection fonctionne. Ensuite l'attaquant tente des UNION SELECT pour exfiltrer la table users puis payments.

Ce qui m'inquiète c'est que les réponses retournent des tailles croissantes (4K, 8K, 12K), ce qui suggère que l'injection fonctionne et que des données sont retournées.

Pivots : je vérifie cette IP source, je regarde tous les endpoints qu'elle a ciblés, je contacte l'équipe applicative pour confirmer la vulnérabilité et bloquer l'IP au WAF. Je vérifie aussi si les données exfiltrées contiennent de vrais records (incident data breach potentiel)."

Requête Splunk :
index=web sourcetype=access_combined src_ip="185.43.12.8"
| where like(uri_query, "%UNION%") OR like(uri_query, "%OR 1=1%")
| table _time, src_ip, uri_path, uri_query, status, bytes

══════════════════════════════════════════
CAS CONCRET 3 : EXÉCUTION SUSPECTE WINDOWS (Sysmon/EDR)
══════════════════════════════════════════

EventCode=1 ParentImage="C:\\Windows\\System32\\cmd.exe"
Image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
CommandLine="powershell -enc aQBlAHgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAA..."
User="CORP\\j.dupont"

EventCode=3 Image="powershell.exe"
DestinationIp="91.234.56.78" DestinationPort=443

Tu dis :
"Je vois un événement Sysmon de création de processus : cmd.exe lance PowerShell avec un argument encodé en base64 (-enc). C'est un indicateur classique d'exécution malveillante, les attaquants encodent pour bypasser la détection.

Juste après, ce même PowerShell établit une connexion sortante vers une IP externe sur le port 443. Ca ressemble fortement à du téléchargement de payload ou à une communication C2 (Command & Control).

Pivots : je décode le base64 pour voir la commande réelle. Je vérifie la réputation de l'IP 91.234.56.78. Je pivote sur le user j.dupont pour comprendre comment il en est arrivé là (phishing ? document malveillant ?). Je cherche le parent process de cmd.exe pour remonter la chaîne. Et je vérifie si d'autres machines contactent cette même IP."

Requête Splunk :
index=windows sourcetype=sysmon EventCode=1 CommandLine="*powershell*-enc*"
| table _time, Computer, User, ParentImage, Image, CommandLine

══════════════════════════════════════════
VOCABULAIRE CLÉ À PLACER NATURELLEMENT
══════════════════════════════════════════

• IOC (Indicator of Compromise) : IP, hash, domaine, URL malveillante
• Pivoter : partir d'un élément pour en découvrir d'autres liés
• Chaîne d'exécution (process tree) : qui a lancé quoi
• Mouvement latéral : l'attaquant se déplace d'une machine à une autre
• C2 (Command & Control) : communication entre malware et serveur attaquant
• LOLBins : outils légitimes Windows utilisés par les attaquants (powershell, certutil, mshta)
• TTPs : Tactiques, Techniques, Procédures (référence MITRE ATT&CK)
• Triage : évaluer rapidement la criticité d'une alerte`,
      tips: "Le PIVOT est plus important que la lecture initiale, c'est ce qui sépare un junior qui fait du bruit d'un analyste qui investigue. Même si tu ne reconnais pas un EventCode, montre ta méthodologie de pivot. Utilise les mots : 'pivoter sur', 'corréler', 'timeline', 'threat intel'. Si tu ne sais pas, dis-le honnêtement et montre comment tu chercherais. Prends 5 secondes pour observer avant de parler.",
      keyPoints: [
        "PIVOT = rebondir d'indice en indice (IP → hostname → user → hash)",
        "Parler de pivot APRÈS la description des logs ('et ensuite je pivoterais sur...')",
        "5 codes : 4624 (login OK), 4625 (échec), 4672 (admin), 7045 (service), 1102 (logs effacés)",
        "3 cas concrets : Brute Force SSH, SQL Injection, Sysmon C2",
        "Vocabulaire : IOC, pivoter, chaîne d'exécution, mouvement latéral, C2, LOLBins, TTPs, triage",
        "Si tu connais pas le code, lis le message à côté, c'est pas grave",
        "Toujours proposer au moins 3 pivots concrets"
      ]
    },
    {
      number: 5,
      q: "Quel est votre point de vue sur l'IA et l'utilisez-vous aujourd'hui ? Si oui, pourquoi ?",
      why: "Question moderne et clivante. Ils veulent voir si tu es un early adopter pragmatique, pas un hater ni un fanboy. PARFAIT pour ton profil, tu utilises Claude Code quotidiennement et tu as des projets concrets !",
      answer: `Je suis très favorable à l'IA et je l'utilise au quotidien. Pour moi c'est un amplificateur : gain de temps, gain de créativité, et surtout un accélérateur d'apprentissage. Evidemment avec des précautions, notamment en contexte professionnel, ne jamais y injecter de données confidentielles, privilégier des modèles locaux quand c'est nécessaire. Le facteur humain reste central, l'IA assiste mais ne remplace pas.

Concrètement, j'utilise des outils comme Claude Code au quotidien et je fais beaucoup de veille sur les nouveaux modèles et les nouvelles pratiques pour en tirer le maximum.

Pour donner des exemples concrets de ce que ça m'a permis de réaliser :

D'abord un SaaS complet, trouverunprof.com, une plateforme de mise en relation entre professeurs et étudiants. Ma fiancée donne des cours particuliers via une plateforme qui prend des frais excessifs, donc j'ai construit une alternative de A à Z : système d'authentification multi-rôles (parent, élève, professeur), calendrier de réservation, notifications et rappels, et même l'intégration d'un système de paiement par carte bancaire avec un système de crédits. Le tout en faisant attention à la sécurisation des données et des transactions.

Ensuite, plus récemment, un outil d'automatisation de recherche d'emploi en local : scraping d'offres, analyse de compatibilité intelligente, génération de CV adaptés non pas sur le contenu mais sur l'angle d'approche et les mots-clés mis en avant, et un tableau de suivi avec filtres. J'en ai d'ailleurs fait un case study documenté si ça vous intéresse.

Pour le lien avec la cybersécurité, c'est ce qui me passionne : l'intersection IA et cyber. Côté attaquant, l'IA va permettre des attaques plus sophistiquées et surtout massifiées. Côté défenseur, on n'aura pas le choix, il faudra utiliser l'IA pour détecter les patterns et anticiper. C'est un sujet sur lequel je compte me former activement.`,
      tips: "Ne mentionne PAS le prix (100$/mois), c'est un détail inutile. Le case study PDF, propose-le naturellement mais ne force pas. Le mot 'amplificateur' est clé : ça montre que TU restes maître. Si le recruteur demande 'mais ça ne vous fait pas peur pour l'emploi ?' : 'Au contraire, ceux qui maîtrisent l'IA auront un avantage, c'est pour ça que j'investis du temps dessus.'",
      keyPoints: [
        "Amplificateur, pas remplacement, le facteur humain reste central",
        "Précaution données confidentielles = réflexe sécu parfait pour le poste",
        "SaaS trouverunprof.com = projet concret livré (auth, paiement, calendrier)",
        "Outil recherche d'emploi = mindset d'automatisation (ce qu'un SOC veut)",
        "Vision IA x cyber = réflexion stratégique sur le futur du métier",
        "Case study disponible si le recruteur veut creuser"
      ]
    },
    {
      number: 6,
      q: "Avez-vous des hobbies ou activités personnelles qui vous servent dans votre travail ? Pouvez-vous donner un exemple ?",
      why: "Ils veulent voir ta PERSONNALITÉ et si ta passion dépasse le cadre pro. C'est aussi un test de communication. C'est LE moment de parler crypto/OSINT naturellement pour connecter avec le recruteur OSINT.",
      answer: `Mon principal hobby c'est de construire des solutions concrètes pour résoudre des problèmes autour de moi. Je vais voir mes proches, je leur demande quel problème ils aimeraient automatiser, et je le construis. C'est comme ça qu'est né trouverunprof.com pour ma fiancée, ou l'outil de recherche d'emploi. C'est un hobby qui rejoint directement le métier : identifier un besoin, concevoir une solution, la livrer.

L'autre activité qui me sert énormément, c'est la blockchain et la DeFi. Je suis très actif dans cet écosystème et honnêtement, c'est un terrain d'entraînement à la sécurité en conditions réelles. En DeFi, les tentatives d'attaque sont permanentes : drains de wallets, phishing ciblé, faux smart contracts. Les gens attaquent pour accéder directement à ton argent, donc l'enjeu est immédiat. Ca m'a rendu très vigilant sur tout ce que j'approuve, chaque transaction, chaque signature. D'ailleurs je stocke mes cryptos sur des cold wallets physiques. En DeFi, la sécurité de ses propres assets c'est la base : clés privées hors ligne, séparation des wallets, vérification de chaque transaction avant signature. C'est de la hygiène de sécurité appliquée à mes propres finances.

Concrètement ça m'amène à tracer des wallets sur Solscan et Etherscan, suivre des flux de transactions, et parfois quand j'ai besoin de savoir à qui appartient un portefeuille, je fais de la corrélation entre des comptes Twitter et des adresses crypto. C'est de l'OSINT appliqué à la blockchain.

L'état d'esprit c'est exactement le même qu'en SOC : être vigilant en permanence, analyser ce qu'on voit, pivoter d'un élément à l'autre pour remonter une piste. Sauf qu'en DeFi, c'est mon propre argent qui est en jeu, donc la motivation à être rigoureux est maximale.

Sinon côté physique, la musculation régulièrement, ça aide à garder la clarté mentale pour un travail d'analyse.`,
      tips: "N'oublie JAMAIS la crypto, c'est ta réponse la plus puissante. 'Terrain d'entraînement en conditions réelles' transforme un hobby en expérience de sécurité. La corrélation Twitter/wallet = OSINT que le recruteur va adorer. 'C'est mon propre argent' prouve que ta vigilance est sincère. Si le recruteur rebondit sur l'OSINT : 'En DeFi on fait de l'OSINT en permanence sans forcément le nommer. Tracer un wallet, corréler une adresse avec une identité, c'est le même réflexe que d'enrichir un IOC en SOC.'",
      keyPoints: [
        "Builder = profil proactif et débrouillard (trouverunprof.com, outil emploi)",
        "Blockchain/DeFi = terrain d'entraînement sécurité en conditions réelles",
        "Cold wallet physique = hygiène de sécurité appliquée à soi-même",
        "Traçabilité wallets + corrélation Twitter = OSINT blockchain naturel",
        "Vocabulaire SOC naturel : pivoter, remonter une piste, investigation",
        "Si rebond OSINT → 'enrichir un IOC en SOC = même démarche'",
        "Musculation = clarté mentale pour l'analyse"
      ]
    }
  ],

  // --------------------------------------------------------------------------
  // INTEL INSIDER : Le SOC utilise Splunk (confirmé par le contact interne)
  // --------------------------------------------------------------------------
  insiderIntel: {
    siem: "Splunk (confirmé par le contact interne, cohérent avec l'offre)",
    advice: "Le SOC utilise bien Splunk. Ta formation en autonomie est donc directement pertinente. En entretien, montre que tu t'y es déjà formé proactivement, c'est un signal fort d'initiative.",
    doNot: "NE JAMAIS mentionner que tu as eu des informations d'un employé actuel sur les questions d'entretien. C'est un avantage, pas quelque chose à révéler."
  }
};

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { hrData };
}
