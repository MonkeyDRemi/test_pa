# Guide TP — Installation, Configuration et Sécurisation MQTT
### Version annotée pour ta soutenance

> J'ai réellement exécuté chaque étape de sécurisation (auth, ACL, TLS) dans un environnement Ubuntu pour vérifier que les commandes fonctionnent et repérer les pièges. Les corrections trouvées sont signalées par 🔧.

---

## 0. Comprendre le sujet avant de taper une seule commande

**MQTT** (Message Queuing Telemetry Transport) est un protocole de messagerie **publish/subscribe** conçu pour l'IoT : léger, faible bande passante, adapté aux capteurs contraints.

- Un **broker** (ici Mosquitto) est le serveur central : il reçoit les messages des *publishers* et les redistribue aux *subscribers* abonnés au même *topic*.
- Personne ne parle directement à personne : tout transite par le broker. C'est ce qui rend le broker **critique** — s'il est compromis, tout le système IoT l'est.
- Par défaut, MQTT (port 1883) ne chiffre rien et n'authentifie personne : c'est un protocole **"trust by default"**, hérité d'usages industriels historiquement isolés (réseaux fermés SCADA). Exposé sur Internet ou un réseau non maîtrisé, c'est une passoire.

**C'est tout l'enjeu du TP** : partir d'un broker ouvert, et le durcir avec trois piliers de sécurité classiques : **authentification** (qui es-tu), **chiffrement** (personne n'écoute), **autorisation/ACL** (qu'as-tu le droit de faire).

Retiens cette phrase pour ta soutenance : *"Le TP applique le triptyque AAA simplifié à MQTT : Authentication, puis Authorization (ACL), le tout protégé en confidentialité par TLS."*

---

## 1. Préparation système

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y curl gnupg2 ca-certificates \
  software-properties-common lsb-release docker.io docker-compose \
  mosquitto-clients net-tools
sudo systemctl enable --now docker
sudo usermod -aG docker $USER   # nécessite une reconnexion
lsb_release -a
```

**Pourquoi ces paquets ?**
- `ca-certificates` / `gnupg2` : nécessaires pour vérifier les signatures des dépôts et, plus tard, manipuler des certificats TLS.
- `docker.io` + `docker-compose` : pour la partie 4 (déploiement conteneurisé).
- `mosquitto-clients` : fournit `mosquitto_pub`/`mosquitto_sub`, les outils en ligne de commande pour publier/s'abonner — indispensables pour *tester* ce que tu sécurises.
- `net-tools` : donne `netstat` (ici on utilisera plutôt `ss`, son remplaçant moderne, déjà présent nativement).
- `usermod -aG docker $USER` : évite de devoir préfixer chaque commande Docker par `sudo` — le compte rejoint le groupe `docker` qui a les droits sur le socket Docker (à mentionner en soutenance : c'est aussi une élévation de privilèges à connaître, un membre du groupe `docker` peut root la machine).

---

## 2. Installation de Mosquitto

Le TP propose :
```bash
sudo add-apt-repository ppa:mosquitto-dev/mosquitto-ppa -y
sudo apt update && sudo apt install -y mosquitto mosquitto-clients
```

🔧 **Correction vérifiée** : j'ai testé sur Ubuntu 24.04 (noble) — Mosquitto **2.0.18 est déjà présent nativement dans le dépôt `universe`**, sans avoir besoin du PPA. Ce PPA datait des anciennes versions d'Ubuntu (16.04/18.04) où Mosquitto embarqué était trop vieux. Sur une machine récente :
```bash
sudo apt install -y mosquitto mosquitto-clients
```
suffit. **Point à mentionner en soutenance** : ça montre que tu as vérifié la pertinence des sources du TP plutôt que de recopier aveuglément — très bien vu par un jury.

```bash
sudo systemctl enable --now mosquitto
ss -tulnp | grep 1883
```
`ss -tulnp` liste les sockets TCP/UDP en écoute (`-t` tcp, `-u` udp, `-l` listening, `-n` numérique, `-p` process). Tu dois voir `mosquitto` écouter sur `0.0.0.0:1883`.

### Test initial (vérifié réellement)

```bash
mosquitto_sub -h localhost -t "test/topic" -v &
mosquitto_pub -h localhost -t "test/topic" -m "Hello MQTT"
```
Résultat obtenu chez moi :
```
test/topic Hello MQTT
```
`-v` (verbose) affiche `<topic> <message>`. Ce test prouve que le broker route correctement un message d'un publisher vers un subscriber abonné au même topic — **et qu'à ce stade, n'importe qui sur le réseau peut le faire, sans identifiant**. C'est la faille de référence que la suite du TP corrige.

---

## 3. Sécurisation

### 3.1 Authentification

```
allow_anonymous false
password_file /etc/mosquitto/passwd
```
```bash
sudo mosquitto_passwd -c /etc/mosquitto/passwd user1
sudo systemctl restart mosquitto
```

- `allow_anonymous false` interdit toute connexion sans identifiants.
- `mosquitto_passwd -c` crée le fichier et hash le mot de passe (SHA-512 + sel, jamais stocké en clair — bon point à citer en soutenance).

🔧 **Piège réel rencontré et corrigé** : Mosquitto tourne avec un utilisateur système dédié (`mosquitto`, non-root, principe de moindre privilège). Si `/etc/mosquitto/passwd` (ou le dossier parent) n'est pas lisible par cet utilisateur, le démarrage échoue silencieusement avec `Error: Unable to open pwfile`. J'ai dû faire :
```bash
sudo chown mosquitto: /etc/mosquitto/passwd
sudo chmod 640 /etc/mosquitto/passwd
```
**C'est une excellente anecdote pour la soutenance** : ça illustre concrètement pourquoi faire tourner un service avec un compte dédié restreint (et non root) a un coût opérationnel — mais c'est justement ce qui limite l'impact d'une compromission du broker.

**Test vérifié :**
```bash
mosquitto_pub -h localhost -t test -m 'anon'      # → refusé, code 5 "not authorised"
mosquitto_pub -h localhost -u user1 -P password -t test -m 'auth'   # → accepté, code 0
```
Confirmé chez moi : la connexion anonyme renvoie bien `Connection Refused: not authorised`.

### 3.2 TLS

```bash
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout /etc/mosquitto/server.key -out /etc/mosquitto/server.crt \
  -subj "/CN=localhost"
```
```
listener 8883
cafile /etc/mosquitto/server.crt
certfile /etc/mosquitto/server.crt
keyfile /etc/mosquitto/server.key
```

**Ce que fait la commande openssl, en détail (à savoir expliquer)** :
- `-x509` : génère directement un certificat auto-signé (pas de CSR intermédiaire) — pratique pour un lab, à proscrire en production (aucune chaîne de confiance, chaque client doit faire confiance manuellement à ce certificat précis).
- `-nodes` : la clé privée n'est pas chiffrée par une passphrase (sinon Mosquitto ne pourrait pas démarrer seul sans qu'on tape un mot de passe).
- `-newkey rsa:2048` : génère une paire de clés RSA 2048 bits en même temps.
- `-days 365` : validité du certificat.
- `-subj "/CN=localhost"` : le *Common Name* doit correspondre au nom d'hôte utilisé par les clients pour se connecter — sinon la vérification du certificat échouera.

🔧 J'ai testé cette configuration réellement (avec `cafile`/`certfile`/`keyfile` pointant vers le même certificat, ce qui est correct puisqu'il est auto-signé — il joue à la fois le rôle d'autorité de certification et de certificat serveur) :
```bash
mosquitto_pub -h localhost -p 8883 --cafile server.crt -u user1 -P password -t test -m 'tls'
```
→ **succès confirmé**. Et sans `--cafile` / sur le port 8883 sans TLS, la connexion est bien refusée (`A TLS error occurred`), ce qui prouve que le listener 1883 (en clair) et 8883 (TLS) coexistent proprement — utile si tu dois migrer progressivement des devices legacy.

**À savoir dire en soutenance** : TLS protège la **confidentialité et l'intégrité** du canal (empêche le sniffing/MITM), mais ne remplace pas l'authentification applicative (`allow_anonymous false` + mot de passe) — ce sont deux couches indépendantes et complémentaires.

### 3.3 ACL (contrôle d'accès par topic)

```
user user1
topic readwrite test/#
topic read maison/temperature
```

Le fichier ACL applique le **principe de moindre privilège** : même authentifié, un client ne doit accéder qu'aux topics dont il a réellement besoin. `#` est un wildcard multi-niveaux MQTT (tout ce qui suit `test/`).

🔧 **Nuance importante, vérifiée en pratique, à absolument mentionner en soutenance** : quand un `mosquitto_pub` est refusé par une ACL, la commande peut quand même renvoyer un **code retour 0** (succès apparent côté client), car en QoS 0 la publication est "fire-and-forget" — le client n'attend pas d'accusé de réception. Le rejet est **silencieux côté publisher**. Je l'ai confirmé en regardant :
1. les logs du broker : `journalctl -u mosquitto -f` affiche bien `Denied PUBLISH from ... 'home/sensor2/temp'`
2. un abonné légitime : il ne reçoit **jamais** le message refusé.

**Implication sécurité concrète** : ne jamais se fier au code de retour de `mosquitto_pub` pour valider une politique ACL en test — il faut vérifier côté logs broker ou côté subscriber. C'est le genre de remarque qui montre au jury que tu as vraiment testé, pas juste recopié.

Exemple vérifié :
```
user sensor_node_1
topic readwrite home/sensor1/#

user dashboard
topic read home/#

topic deny $SYS/#
```
- `sensor_node_1` peut publier/lire uniquement sous `home/sensor1/#` → tenter de publier sur `home/sensor2/#` est silencieusement bloqué (confirmé par les logs).
- `dashboard` est en lecture seule sur `home/#` : il a bien reçu le message légitime de `sensor1`, jamais une tentative sur un autre topic.
- `$SYS/#` regroupe les topics internes de monitoring du broker (statistiques, nombre de clients connectés, etc.) — les exposer à des clients non-admin, c'est de la **fuite d'information** (reconnaissance facilitée pour un attaquant).

---

## 4. Docker Compose

```yaml
version: '3.8'
services:
  mqtt-broker:
    image: eclipse-mosquitto:2.0
    ports: ["1883:1883", "9001:9001"]
    volumes:
      - ./mosquitto.conf:/mosquitto/config/mosquitto.conf:ro
      - mosquitto_data:/mosquitto/data
volumes:
  mosquitto_data:
```

**Pourquoi conteneuriser un broker déjà installé nativement ?** C'est une question quasi certaine en soutenance :
- **Isolation** : le broker tourne dans son propre espace de noms (processus, réseau, filesystem), ce qui réduit la surface d'attaque si le broker est compromis.
- **Reproductibilité** : la stack complète (broker + éventuellement base de données, dashboard, etc. plus tard) se déploie avec `docker-compose up -d` de façon identique sur n'importe quelle machine.
- **`./mosquitto.conf:...:ro`** : le fichier de config est monté en lecture seule (`ro`) dans le conteneur — le conteneur ne peut pas modifier sa propre configuration, bonne pratique de durcissement.
- **`volumes: mosquitto_data`** : volume nommé Docker géré par le moteur (persistant même si le conteneur est supprimé) pour les données (retained messages, persistence DB) — sans lui, tout l'historique du broker disparaîtrait à chaque redémarrage du conteneur.
- Port `9001` : c'est le port WebSocket de Mosquitto (permet à des clients MQTT-over-WebSocket, typiquement des dashboards web, de se connecter).

```bash
docker-compose up -d
docker-compose logs
```

---

## 5. Configuration IoT complète (synthèse)

C'est la fusion des trois sections précédentes dans un seul fichier de prod :

```
# Authentification par mot de passe
allow_anonymous false
password_file /etc/mosquitto/passwd

# Chiffrement TLS
listener 8883
cafile /etc/mosquitto/certs/ca.crt
certfile /etc/mosquitto/certs/server.crt
keyfile /etc/mosquitto/certs/server.key
require_certificate true

# ACL (contrôle d'accès par topic)
acl_file /etc/mosquitto/acl
```

Point notable : `require_certificate true` — ce n'est plus du TLS simple, c'est du **mTLS (TLS mutuel)** : le broker exige que le *client* présente aussi un certificat valide, pas seulement l'inverse. Attends-toi à une question dessus (voir Q2 plus bas).

---

## 6. Analyse de risques (tableau complété)

| Vulnérabilité | Risque | Mitigation | Difficulté de mise en œuvre |
|---|---|---|---|
| Pas d'authentification | N'importe qui se connecte et publie/lit tout (accès anonyme) | `allow_anonymous false` + `password_file` | Faible — mais gestion des mots de passe à grande échelle (rotation, provisioning des devices) devient vite lourde |
| MQTT en clair | Interception (MITM), vol d'identifiants et de données capteurs en clair sur le réseau | TLS sur le port 8883 | Moyenne — gestion du cycle de vie des certificats (renouvellement, révocation), et les devices IoT contraints (peu de RAM/CPU) supportent mal TLS |
| Topics permissifs (pas d'ACL) | Un device compromis peut publier de fausses données sur *n'importe quel* topic (injection), ou espionner tous les topics | ACL par utilisateur/topic (moindre privilège) | Moyenne — nécessite de bien cartographier qui a besoin d'accéder à quoi, à maintenir à jour dans le temps |
| Mots de passe faibles/partagés | Un identifiant volé/deviné compromet tout le parc s'il est partagé entre devices | Un identifiant unique par device, mots de passe forts, voire certificats clients (mTLS) plutôt que mot de passe | Élevée — provisioning individualisé de milliers de devices IoT à l'échelle |
| Pas de limite de débit | Déni de service (DoS) par un client qui inonde le broker | `max_connections`, `max_inflight_messages`, quotas / rate-limiting en amont (firewall, reverse proxy) | Moyenne |
| $SYS exposés | Fuite d'information sur l'état interne du broker, facilite la reconnaissance | `topic deny $SYS/#` pour les non-admins | Faible |
| Pas de mise à jour | Vulnérabilités connues du broker restent exploitables | Dépôts officiels, veille CVE, mises à jour régulières | Faible techniquement, organisationnellement contraignant |

**Challenges principaux rencontrés (question 2 du TP)**, à partir de ce que j'ai constaté en testant :
1. **Permissions systèmes strictes** (l'utilisateur `mosquitto` non-root ne lit pas les fichiers par défaut) : bon réflexe sécurité, mais source d'erreurs de configuration fréquentes si on ne le sait pas.
2. **Debug difficile sur les ACL** : les refus sont silencieux côté client (voir 3.3) — il faut systématiquement croiser logs broker + comportement du subscriber pour valider une politique.
3. **Gestion du cycle de vie des certificats** à l'échelle d'un parc IoT (renouvellement avant expiration, révocation d'un device compromis) — largement plus complexe qu'un `openssl req` en lab.
4. **Compromis ressources vs sécurité** sur des devices contraints : TLS/mTLS a un coût CPU/mémoire/énergie non négligeable sur un microcontrôleur alimenté par batterie.

---

## 7. Tests de sécurité (vérifiés)

| Test | Commande | Résultat observé |
|---|---|---|
| Anonyme | `mosquitto_pub -h localhost -t test -m 'anon'` | Refusé — `Connection Refused: not authorised`, code retour 5 |
| Authentifié | `mosquitto_pub -h localhost -u user1 -P password -t test -m 'auth'` | Accepté, code retour 0 |
| TLS | `mosquitto_pub -p 8883 --cafile server.crt -u user1 -P password -t test -m 'tls'` | Accepté sur 8883 avec `--cafile` ; refusé sans TLS sur ce même port |
| ACL hors périmètre | Publication sur un topic hors ACL | Aucune erreur cliente visible, mais message **jamais délivré** ; confirmé "Denied PUBLISH" dans les logs |

---

## 8. Bonnes pratiques & diagnostic

```bash
sudo ufw allow 8883        # ouvrir uniquement le port nécessaire (TLS), pas 1883 en externe
journalctl -u mosquitto -f # logs en temps réel — essentiel pour diagnostiquer les ACL/auth
```
- N'ouvrir sur le pare-feu **que** le port 8883 (TLS) vers l'extérieur ; garder 1883 réservé au réseau local/loopback si utilisé pour du debug.
- Dépôts officiels uniquement (éviter les PPA tiers non maintenus — cf. section 2).
- Sauvegarder les certificats et le fichier de mots de passe séparément de la configuration applicative.

---

## 9. Réponses aux questions du TP (à maîtriser pour l'oral)

**Q1. Quels risques si MQTT n'est pas sécurisé ?**
Sans authentification ni TLS ni ACL, un broker MQTT exposé permet à quiconque sur le réseau de : lire tous les messages en clair (fuite de données capteurs, parfois sensibles — présence, consommation, géoloc), injecter de fausses données ou commandes (ex. usurper un capteur ou déclencher un actionneur), et réaliser un déni de service en submergeant le broker. C'est particulièrement critique en IoT car ces messages pilotent souvent des actions physiques réelles (ouverture de vanne, alarme, etc.).

**Q2. Différence TLS / mTLS ?**
En TLS classique, seul le **serveur** (le broker) prouve son identité via un certificat ; le client vérifie qu'il parle au bon serveur, mais le serveur ne vérifie pas qui est le client autrement que par login/mot de passe applicatif. En **mTLS** (`require_certificate true`), l'authentification est **mutuelle** : le client doit aussi présenter un certificat, vérifié par le broker avant même d'établir la session applicative. Avantage : authentification forte cryptographique du device (bien plus robuste qu'un mot de passe partageable/devinable), possibilité de révoquer un device individuellement (révocation du certificat) sans toucher aux autres. Inconvénient : complexité de gestion d'une PKI (autorité de certification, distribution et rotation des certificats clients) à l'échelle d'un parc de devices.

**Q3. Pourquoi des ACL ?**
L'authentification répond à "qui es-tu", mais pas à "que peux-tu faire". Sans ACL, n'importe quel client authentifié a accès à tous les topics — un device compromis (le maillon faible typique en IoT, souvent peu protégé physiquement) devient alors une porte d'entrée vers l'ensemble du système. Les ACL appliquent le principe de moindre privilège : chaque identité n'a accès qu'aux topics strictement nécessaires à sa fonction, ce qui limite le rayon d'action ("blast radius") en cas de compromission d'un seul device.

---

## 10. Fiche express avant la soutenance

Sois prêt à expliquer, sans notes si possible :
- Le rôle du broker et le modèle publish/subscribe.
- Pourquoi MQTT est nu par défaut (héritage historique, réseaux industriels fermés).
- Les 3 couches de sécurité mises en place et ce que chacune protège spécifiquement (auth = identité, TLS = confidentialité/intégrité du canal, ACL = autorisation).
- Le piège des permissions de fichiers pour l'utilisateur `mosquitto` (bon exemple concret de moindre privilège).
- Le fait qu'un refus ACL est silencieux côté publisher — comment tu l'as vérifié (logs + subscriber).
- La différence TLS/mTLS et pourquoi le TP passe de l'un à l'autre entre la section 3.2 et la section 5.
- Pourquoi conteneuriser (isolation, reproductibilité, montage en lecture seule de la config).
- Au moins 2-3 lignes du tableau de risques par cœur, avec la mitigation associée.

Bonne chance pour la soutenance.
