# Emby-Toolbox
Emby tools ( IDFINDER, DUPLICATE FINDER, GENRE FINDER )

🎬 Emby Toolbox
Boîte à outils tout-en-un pour administrer votre serveur Emby : re-référencement TMDB, détection de doublons et exploration par genres — dans une seule fenêtre, un seul fichier Python.
> 🇬🇧 *All-in-one Emby management toolbox: TMDB re-matching, duplicate detection and genre exploration in a single-file DearPyGui app. The interface is fully bilingual — switch between French and English at any time from the top bar.*
![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Windows-10%2F11-0078d4?logo=windows&logoColor=white)
![GUI](https://img.shields.io/badge/GUI-DearPyGui%202.x-orange)
![License](https://img.shields.io/badge/License-MIT-green)
---
✨ Aperçu
Emby Toolbox regroupe trois outils complémentaires dans une interface à onglets, avec une configuration commune (URL Emby, clés API, langue) saisie une seule fois et chiffrée localement :
Onglet	Rôle
🔍 IDFinder	Re-référence les films et séries mal identifiés (mauvais ID TMDB/IMDB)
👯 Doublons	Détecte les doublons réels dans vos médiathèques, compare et nettoie
🎭 Explorateur de genres	Recherche par genre, enrichit les classifications d'âge via OMDB/TMDB
L'interface bascule français ↔ anglais à chaud (boutons, infobulles, popups, messages, onglets — tout).
---
🧰 Fonctionnalités
🔍 IDFinder (re-référencement)
Scan des médiathèques films ou séries (sélecteur dédié) ;
Détection des éléments dont l'identifiant TMDB/IMDB ne correspond pas au titre/année ;
Recherche TMDB large avec tolérance d'année réglable (± n ans) ;
Mode auto-correction : applique automatiquement le bon ID quand la similarité de titre ≥ 95 % ;
Correction manuelle assistée : liste de candidats TMDB avec similarité, année, aperçu ;
Application via l'API `RemoteSearch` d'Emby (métadonnées rafraîchies par le serveur).
👯 Doublons
Scan limité aux médiathèques cochées (rien n'est pré-sélectionné) ;
Score de confiance par groupe (titre, année, durée, taille, resolution…) ;
7 critères de « versions intentionnelles » (4K vs 1080p, HDR, Director's cut, AV1…) pour ignorer les faux doublons ;
Comparaison côte à côte des métadonnées et des pistes audio (différences surlignées) ;
Lecture d'un fichier, ou de tout le groupe en mosaïque (fenêtres disposées automatiquement) ;
Suppression via l'API Emby (avec confirmation), gestion des groupes ignorés ;
Export HTML riche (graphiques) et CSV ; sauvegarde/rechargement de scan ;
Bouton « Analyser Emby » : déclenche l'analyse serveur des médiathèques sélectionnées uniquement.
🎭 Explorateur de genres
Chargement des genres réels de votre serveur, recherche multi-genres + genre libre ;
Résultats détaillés : titre, année, genres, dossier NAS (chemin Windows/Linux), taille ;
Enrichissement web : classification d'âge + note via OMDB et/ou TMDB, avec repli automatique d'une source vers l'autre si la première ne classe pas le film ;
Table de correspondance d'âges étendue (MPAA, TV US, CNC 🇫🇷, BBFC 🇬🇧, FSK 🇩🇪, Québec) ;
Modification de l'âge (`OfficialRating`) film par film ou en masse : bouton « Appliquer âges sup. » (applique l'âge web à tous les films où il est supérieur à l'âge enregistré, avec popup de progression) ;
Filtre par âge, option « Masquer âges identiques », export CSV ;
Ouverture du film dans votre lecteur, ou du dossier dans l'explorateur.
⚙️ Configuration commune
Bandeau unique en haut : URL Emby, clé API, User ID, clés TMDB/OMDB (boutons « obtenir » qui ouvrent la page d'inscription), préfixe NAS → UNC, lecteur vidéo (avec parcours `...`), langue FR/EN ;
Saisie une seule fois, propagée aux trois outils et enregistrée chiffrée.
---
📦 Installation
Prérequis
Windows 10/11 (le chiffrement DPAPI et l'ouverture de dossiers utilisent l'API Windows) ;
Python 3.10+ — cochez « Add python.exe to PATH » à l'installation.
Étapes
```bash
git clone https://github.com/popov2026/emby-toolbox.git
cd emby-toolbox
pip install -r requirements.txt
```
Puis double-cliquez sur `emby_toolbox_dpg.pyw` (ou lancez `pythonw emby_toolbox_dpg.pyw`).
> 💡 L'extension `.pyw` lance l'application **sans console**. Pour voir les éventuelles erreurs au démarrage, lancez `python emby_toolbox_dpg.pyw` depuis un terminal.
Dépendances
Paquet	Rôle	Obligatoire
`dearpygui`	Interface graphique (GPU, DirectX 11)	✅
`requests`	Appels API TMDB / Emby (IDFinder)	✅
`cryptography`	Chiffrement Fernet (repli si DPAPI indisponible)	recommandé
`pillow`	Traitements d'image optionnels	optionnel
---
🔧 Configuration
URL Emby : `http://IP_DU_SERVEUR:8096` (ou votre reverse proxy HTTPS).
Clé API Emby : Tableau de bord Emby → Avancé → Clés API → Nouvelle clé.
User ID (optionnel) : utile si vos médiathèques sont filtrées par utilisateur.
Clé TMDB (IDFinder + enrichissement) : bouton « obtenir » → themoviedb.org/settings/api — gratuite.
Clé OMDB (enrichissement) : bouton « obtenir » → omdbapi.com/apikey.aspx — gratuite (1000 req/jour).
Préfixe NAS → UNC : convertit les chemins Linux du serveur (`/volume1/...`) en chemins Windows (`\\192.168.1.x\...`) pour la lecture et l'ouverture de dossiers.
Lecteur : chemin vers VLC / MPC-BE / MPC-HC… (bouton `...` pour parcourir). Vide = lecteur par défaut du système.
Cliquez Connecter, cochez vos médiathèques dans l'onglet voulu, et c'est parti.
> ℹ️ Pour la lecture **en mosaïque** (Doublons), votre lecteur doit accepter plusieurs instances : VLC → *Préférences → Interface → décocher « Une seule instance »* ; MPC-BE → *Options → Lecteur → « Permettre plusieurs instances »*.
---
🔐 Sécurité & fichiers créés
Les secrets (clé API Emby, clés TMDB/OMDB) sont chiffrés au repos :
DPAPI Windows (liés à votre session utilisateur) en priorité ;
repli Fernet (`cryptography`) avec une clé locale `emby_secret.key` sinon.
Fichiers créés à côté du script (aucune écriture ailleurs) :
Fichier	Contenu
`emby_toolbox_creds.ini`	Configuration commune (secrets chiffrés `enc:dpapi:` / `enc:fernet:`)
`emby_secret.key`	Clé Fernet locale (générée si nécessaire)
`emby_toolbox_dpg.ini`	Préférences de l'explorateur de genres
`emby_refmatch.ini`	Préférences IDFinder (type, tolérance, sélection)
`*_doublons*.ini` / exports	Préférences doublons, scans sauvegardés, exports HTML/CSV
> ⚠️ **Ne committez jamais ces fichiers sur GitHub.** Ajoutez-les à votre `.gitignore` :
> ```gitignore
> *.ini
> emby_secret.key
> *.html
> *.csv
> ```
---
---
❓ FAQ / Dépannage
Des « ? » s'affichent à la place de certains caractères
L'application charge automatiquement une police système Unicode (Segoe UI). Si le problème persiste, vérifiez que `C:\Windows\Fonts\segoeui.ttf` existe.
« Nécessite la sélection d'au moins une médiathèque »
Volontaire : ni le scan de doublons ni « Analyser Emby » ne s'exécutent sans médiathèque cochée, pour éviter les analyses globales involontaires.
L'enrichissement affiche « n/c »
Le film n'a de classification ni chez OMDB ni chez TMDB (le repli automatique a déjà interrogé les deux si les deux clés sont renseignées).
Erreur 401 sur les actions Emby
Clé API invalide/expirée, ou droits insuffisants (la suppression de fichiers doit être autorisée pour la clé).
Le proxy/HTTPS ne répond pas
Testez d'abord en direct `http://IP:8096` pour isoler un souci de reverse proxy.
---
🛠️ Notes techniques
Un seul fichier : ~5900 lignes, aucune installation, portable.
UI thread-safe : les workers réseau postent leurs mises à jour dans une file drainée par la boucle de rendu.
Thème sombre unifié, boutons d'action colorés (scan orange, connexion verte), popups de progression pour les opérations longues.
Testé avec DearPyGui 2.x et Python 3.10–3.12 sous Windows 10/11.
---
📄 Licence
MIT — utilisez, modifiez, partagez librement.
🙏 Crédits
Développé par Popov2026 ;
Données : TMDB et OMDb API (ce projet utilise l'API TMDB mais n'est ni approuvé ni certifié par TMDB) ;
GUI : DearPyGui.
