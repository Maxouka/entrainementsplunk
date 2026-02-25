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
      answer: `Le plus gros exemple, c'est l'environnement de test PRTG. Chez Harvest on avait PRTG en production avec des milliers de sondes sur plus de 1000 machines, mais il n'y avait aucun environnement de test. Quand il fallait déployer de nouvelles sondes ou tester des configurations, on le faisait directement en prod, ce qui était risqué. De ma propre initiative, j'ai installé un serveur PRTG de test en local, j'ai monté des VMs de test qui n'existaient pas, et j'ai développé et validé des déploiements de sondes via l'API PRTG et Ansible avant de les pousser en production. Personne ne me l'avait demandé, j'ai juste vu que ça manquait et que ça nous faisait prendre des risques inutiles.

Deuxième exemple : pendant le déploiement BitLocker en urgence après le vol du PC d'un cadre, j'ai découvert que les clés de récupération du disque D ne remontaient pas dans l'Active Directory. Ça bloquait les utilisateurs et personne n'avait de solution immédiate. J'ai pris l'initiative de développer un script PowerShell d'auto-unlock et de récupérer manuellement les clés dans les logs Tanium pour dépanner les utilisateurs bloqués. C'était pas prévu, j'ai vu le problème en cours de route et j'ai agi.

Et aujourd'hui, je me forme à Splunk en autonomie complète alors que chez Harvest j'utilisais Rapid7 InsightIDR. J'ai construit un environnement d'entraînement avec des exercices SPL, des scénarios de lecture de logs, des quiz techniques. Personne ne me le demande, je le fais parce que je sais que Splunk est le standard en SOC et que c'est ce que vous utilisez ici.`,
      tips: "3 exemples avec la structure Constat → Initiative → Résultat. Le PRTG de test est le meilleur : il montre que tu améliores les process. Le BitLocker montre que tu gères la pression. Le Splunk montre que tu anticipes ta carrière. Les 3 ensemble = profil complet.",
      keyPoints: [
        "Env de test PRTG + Ansible + API = initiative process la plus forte",
        "Script auto-unlock BitLocker = résolution sous pression",
        "Splunk en auto-formation = anticipation concrète du poste visé",
        "Structure : Constat → Initiative → Résultat pour chaque exemple",
        "Tout est VRAI et vérifiable"
      ]
    },
    {
      number: 2,
      q: "Si on vous avait donné carte blanche, quel est le premier point que vous auriez amélioré dans votre dernière mission ?",
      why: "Ils testent ta VISION CRITIQUE et ta capacité à prendre du recul. Attention : ne pas taper sur l'ex-employeur, mais montrer une réflexion constructive.",
      answer: `Le premier point, c'est la centralisation de la supervision sécurité. Chez Harvest, on avait plusieurs outils en parallèle (InsightIDR comme SIEM, Cybereason en EDR, PRTG pour le monitoring infra, et les alertes Waycom) mais il n'y avait pas de corrélation réelle entre ces sources. Chaque outil remontait ses alertes dans son coin. Si j'avais eu carte blanche, j'aurais poussé pour centraliser tout ça dans un SIEM unique avec des règles de corrélation. Par exemple, quand PRTG détecte un pic CPU anormal sur un serveur ET que Cybereason remonte un processus suspect sur le même serveur, aujourd'hui ce sont deux alertes séparées. Corrélées, c'est un incident.

Le deuxième point, c'est l'automatisation de la conformité. Une grosse partie de mon travail (vérifier les mots de passe expirés dans l'AD, identifier les machines sans BitLocker, lister les protocoles obsolètes) je le faisais avec des scripts PowerShell et des exports CSV manuels. Si j'avais eu carte blanche, j'aurais mis en place un dashboard de conformité en temps réel qui remonte automatiquement l'état du parc : couverture BitLocker, état des patchs, protocoles obsolètes restants. Ça aurait transformé le rapport COMEX hebdomadaire en quelque chose de dynamique plutôt que des fichiers Excel compilés à la main.

Et enfin, la documentation des procédures de réponse. On avait des connaissances dans les têtes de chacun, mais pas assez de procédures écrites et formalisées. Quand j'étais d'astreinte le week-end et que je tombais sur un type d'alerte que je n'avais pas encore vu, je devais appeler un collègue. Des playbooks documentés (même basiques) auraient accéléré le traitement.`,
      tips: "Rester HONNÊTE : tu ne faisais pas du SOC pur, tu faisais de l'infra sécurité et de la conformité. Mais tu peux quand même montrer de la vision. Le mot 'corrélation' et 'centralisation' montrent que tu comprends la logique SOC même si tu ne l'as pas pratiquée au quotidien.",
      keyPoints: [
        "Centralisation des alertes multi-outils = vision SOC réaliste",
        "Dashboard de conformité temps réel = amélioration de ce que tu faisais VRAIMENT",
        "Playbooks documentés = besoin réel vécu lors des astreintes week-end",
        "Pas de critique, du constructif basé sur le vécu",
        "Tout est ancré dans ton VRAI travail, pas inventé"
      ]
    },
    {
      number: 3,
      q: "Pourquoi avez-vous choisi la cybersécurité ? Qu'est-ce qui vous motive dans ce domaine ?",
      why: "ATTENTION : ils vont CHALLENGER ta sincérité. Si tu dis 'je suis passionné', ils vont creuser avec des exemples concrets (CTF, projets perso, veille, etc.). Sois AUTHENTIQUE. Si tu ne fais pas de CTF, ne mens pas, parle de ce que tu fais vraiment.",
      answer: `Ce qui m'a amené à la cybersécurité, c'est un chemin assez naturel. Je suis très actif dans l'écosystème crypto et blockchain (Solana, DeFi, trading on-chain) et c'est là que j'ai compris viscéralement ce que c'est la cybersécurité. En crypto, le facteur d'attaque numéro 1 c'est l'humain. Exactement comme en cybersécurité d'entreprise. Les gens se font drain leur wallet pas par une faille technique dans la blockchain, mais par du social engineering : un faux site de mint, un lien Discord malveillant, une approval de smart contract piégée. C'est du phishing, c'est de la manipulation. C'est exactement les mêmes mécaniques qu'on retrouve dans les alertes d'un SOC. Le vecteur change, mais l'attaque est la même : exploiter la confiance humaine.

Et ça m'a appris à analyser des transactions, tracer des flux, identifier des patterns suspects. C'est fondamentalement le même travail qu'un analyste SOC qui lit des logs et pivote d'un indice à l'autre. En crypto tu traces un wallet malveillant à travers les transactions, en SOC tu traces une IP suspecte à travers les logs. La logique d'investigation est identique.

Ensuite, chez Harvest, j'ai découvert l'autre côté : la sécurité opérationnelle à l'échelle d'une entreprise. Sécuriser 1000 machines, déployer BitLocker en urgence après un vol de PC, préparer un audit ISO 27001, rédiger des rapports de vulnérabilités pour le COMEX. C'est une base solide en hardening et conformité, et maintenant je veux aller vers la détection et l'investigation, c'est pour ça que je vise un poste SOC.

L'autre sujet qui me passionne et sur lequel je fais une veille très active, c'est l'intersection entre cybersécurité et IA. C'est en train de tout changer. Côté attaquant : du phishing généré par IA quasi indétectable, du malware polymorphe qui se réécrit à chaque exécution, de la reconnaissance automatisée. Côté défense : l'IA va accélérer le triage des alertes, la corrélation, la détection comportementale. Pour un SOC, ça veut dire que les règles de détection statiques ne suffiront plus, il faudra de l'analyse comportementale. Et moi j'utilise déjà l'IA au quotidien comme outil de productivité. Claude Code pour me former à Splunk, comprendre des techniques d'attaque, monter en compétences.

Je fais pas de CTF le week-end, je ne vais pas mentir. Mais ma passion pour la crypto et l'IA me pousse naturellement à comprendre les mécaniques d'attaque, à analyser des flux, à faire de la veille sur les nouvelles menaces. C'est pas du SOC sur mon temps libre, mais c'est la même curiosité et le même réflexe d'investigation, et c'est ce qui me motive à faire ce métier.`,
      tips: "C'est ta VRAIE histoire, crypto → cyber → SOC. Le lien social engineering crypto/phishing SOC est puissant et original. L'IA c'est ta deuxième passion. Et tu assumes de pas faire de CTF, c'est honnête et ça tient la route parce que tu as d'autres activités concrètes qui prouvent ta curiosité.",
      keyPoints: [
        "Crypto : facteur d'attaque #1 = l'humain (comme en cyber entreprise)",
        "Tracer un wallet malveillant ≈ pivoter sur une IP suspecte dans un SIEM",
        "Harvest = base solide en infra sécurité, maintenant transition vers SOC",
        "Veille IA + cyber = passion authentique, pas du bluff",
        "IA offensive (phishing, polymorphe) et défensive (triage, comportemental)",
        "Utilisation concrète de l'IA (Claude Code) au quotidien",
        "Pas de CTF et c'est assumé, la crypto et l'IA = sa vraie curiosité"
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

Note : les logs dans un SIEM comme Splunk ne sont PAS brutes, elles sont parsées avec des champs nommés (src_ip, Account_Name, etc.). Tu travailles avec un tableau propre, pas du XML illisible.`,
      tips: "Le PIVOT est plus important que la lecture initiale, c'est ce qui sépare un junior qui fait du bruit d'un analyste qui investigue. Même si tu ne reconnais pas un EventCode, montre ta méthodologie de pivot. Utilise les mots : 'pivoter sur', 'corréler', 'timeline', 'threat intel'. Si tu ne sais pas → dis-le honnêtement et montre comment tu chercherais.",
      keyPoints: [
        "PIVOT = rebondir d'indice en indice (IP → hostname → user → hash)",
        "Parler de pivot APRÈS la description des logs ('et ensuite je pivoterais sur...')",
        "5 codes : 4624 (login OK), 4625 (échec), 4672 (admin), 7045 (service), 1102 (logs effacés)",
        "Si tu connais pas le code → lis le message à côté, c'est pas grave",
        "Les logs SIEM sont parsées, pas brutes, tu lis des champs nommés",
        "Toujours proposer au moins 3 pivots concrets"
      ]
    },
    {
      number: 5,
      q: "Quel est votre point de vue sur l'IA et l'utilisez-vous aujourd'hui ? Si oui, pourquoi ?",
      why: "Question moderne et clivante. Ils veulent voir si tu es un early adopter pragmatique, pas un hater ni un fanboy. PARFAIT pour ton profil, tu utilises Claude Code quotidiennement !",
      answer: `Oui, j'utilise l'IA au quotidien et je pense que c'est un levier énorme pour un analyste SOC, à condition de l'utiliser intelligemment.

Concrètement, j'utilise Claude Code (l'assistant IA d'Anthropic) comme outil de développement et d'apprentissage technique. Par exemple, quand je me forme à Splunk, je l'utilise pour comprendre des requêtes SPL complexes, me faire expliquer des concepts d'architecture, ou valider ma compréhension d'une technique d'attaque. C'est comme avoir un collègue senior disponible 24h/24 pour du pair-learning.

Pour la cybersécurité spécifiquement, je vois l'IA comme un multiplicateur de force à plusieurs niveaux :

En défense, l'IA peut accélérer le triage des alertes. Imaginez un premier filtre intelligent qui pré-qualifie les alertes en enrichissant automatiquement le contexte, qui corrèle avec la threat intelligence, et qui priorise pour l'analyste. Ça ne remplace pas le jugement humain, mais ça réduit considérablement le temps de traitement des faux positifs.

En investigation, l'IA aide à analyser rapidement de gros volumes de logs, détecter des patterns anormaux qu'un humain mettrait des heures à repérer, ou résumer un incident complexe pour le reporting.

Côté attaquants, il faut être lucide : l'IA est aussi utilisée pour générer du phishing plus convaincant, automatiser la reconnaissance, ou créer du code malveillant polymorphe. C'est une course aux armements.

Mon point de vue : un analyste SOC qui n'utilise pas l'IA en 2026 se prive d'un avantage compétitif. Mais l'IA ne remplace pas la compréhension fondamentale, il faut d'abord comprendre les concepts pour pouvoir évaluer et challenger ce que l'IA propose. C'est un copilote, pas un autopilote.`,
      tips: "Être enthousiaste mais nuancé. Montrer une utilisation CONCRÈTE (Claude Code, pas juste ChatGPT pour des résumés). Montrer qu'on comprend les implications offensives et défensives. Le mot-clé : 'multiplicateur de force'. Ne pas avoir peur de dire qu'on l'utilise, c'est un PLUS en 2026.",
      keyPoints: [
        "Utilisation quotidienne concrète (Claude Code pour le dev et l'apprentissage)",
        "Application SOC : triage, corrélation, analyse de volumes",
        "Conscience du côté offensif (phishing IA, malware polymorphe)",
        "Nuance : copilote, pas autopilote, le jugement humain reste essentiel",
        "Power user = early adopter = profil moderne et adaptable"
      ]
    },
    {
      number: 6,
      q: "Avez-vous des hobbies ou activités personnelles qui vous servent dans votre travail ? Pouvez-vous donner un exemple ?",
      why: "Ils veulent voir ta PERSONNALITÉ et si ta passion dépasse le cadre pro. C'est aussi un test de communication, arrive-t-on à rendre un hobby intéressant dans un contexte pro ?",
      answer: `Oui, clairement. Mon intérêt pour la blockchain et l'écosystème Solana, par exemple, m'a apporté des compétences directement transférables en cybersécurité.

Depuis plusieurs années, je suis actif dans l'écosystème DeFi, les échanges décentralisés, le trading on-chain, les NFTs. Ça peut sembler éloigné du SOC, mais en pratique ça m'a obligé à comprendre en profondeur les mécanismes de sécurité des transactions, les attaques sur les smart contracts, les techniques de MEV (extraction de valeur par manipulation de l'ordre des transactions). J'ai même développé un toolkit en Rust et TypeScript pour analyser des transactions Solana.

Ce que ça m'apporte concrètement en cybersécurité : une compréhension fine des protocoles, une habitude d'analyser des transactions et des flux de données, qui est exactement ce qu'on fait avec des logs, et une sensibilité aux nouvelles surfaces d'attaque liées aux crypto-actifs. Aujourd'hui, beaucoup d'entreprises ont des actifs numériques ou des employés qui utilisent des wallets, et c'est un vecteur d'attaque de plus en plus exploité.

L'autre hobby, c'est le développement. Mon projet TeachMe, une marketplace de cours particuliers que j'ai construite seul, me sert au quotidien. En développant une application complète avec authentification, paiements Stripe, messagerie temps réel, j'ai dû penser sécurité à chaque étape : protection CSRF, Content Security Policy, validation côté serveur, gestion des sessions. Quand j'analyse une alerte web en SOC, je comprends ce qui se passe côté applicatif parce que je l'ai construit moi-même.

Et enfin, le sport m'aide à gérer le stress et à rester concentré sur de longues sessions d'investigation. C'est basique mais c'est réel.`,
      tips: "Rendre le hobby CONCRET et lié au métier. La blockchain est un super différenciateur, très peu d'analystes SOC ont cette compétence. Le dev comme hobby montre la polyvalence. Le sport = gestion du stress = pertinent pour le SOC. Être authentique et passionné.",
      keyPoints: [
        "Blockchain/Solana = compréhension des protocoles et analyse de transactions",
        "Toolkit Rust/TypeScript = preuves concrètes de compétence technique",
        "TeachMe = sécurité applicative vue du développeur",
        "Sport = gestion du stress (pertinent pour le SOC)",
        "Chaque hobby est connecté au métier avec un exemple concret"
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
