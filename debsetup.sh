#!/bin/bash

# Script de configuration automatique pour systèmes Debian fraîchement installés
# Ce script configure automatiquement le réseau et les utilisateurs sudoers

# Définition des couleurs pour une meilleure lisibilité
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Fonction pour afficher les messages d'information
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

# Fonction pour afficher les messages d'erreur
log_error() {
    echo -e "${RED}[ERREUR]${NC} $1"
}

# Fonction pour afficher les messages d'avertissement
log_warning() {
    echo -e "${YELLOW}[AVERTISSEMENT]${NC} $1"
}

# Vérifier si le script est exécuté en tant que root
if [ "$EUID" -ne 0 ]; then
    log_error "Ce script doit être exécuté en tant que root"
    exit 1
fi

# Vérifier si le répertoire config existe
if [ ! -d "config" ]; then
    log_error "Le répertoire 'config' n'existe pas"
    exit 1
fi

# Vérifier si une configuration existe déjà et demander confirmation
check_existing_config() {
    local config_name="$1"
    local config_file="$2"
    
    if [ -f "$config_file" ]; then
        log_warning "Une configuration $config_name existe déjà ($config_file)"
        echo -n "Voulez-vous la remplacer ? (o/N) "
        read -r answer
        
        if [[ "$answer" =~ ^[oO][uU]?[iI]?$ ]]; then
            log_info "La configuration existante sera remplacée"
            return 0
        else
            log_info "Conservation de la configuration existante"
            return 1
        fi
    fi
    
    return 0  # Pas de configuration existante, poursuivre
}

# Configuration des sources APT
configure_apt_sources() {
    log_info "Configuration des sources APT..."
    
    # Vérifier si la configuration existe déjà
    if ! check_existing_config "des sources APT" "/etc/apt/sources.list"; then
        return 0
    fi
    
    # Sauvegarde du fichier sources.list
    cp /etc/apt/sources.list /etc/apt/sources.list.bak
    
    # Détection de la version de Debian
    if [ -f /etc/os-release ]; then
        source /etc/os-release
        DEBIAN_VERSION="$VERSION_CODENAME"
    else
        DEBIAN_VERSION="bookworm"  # Version par défaut si non détectée
        log_warning "Impossible de détecter la version de Debian, utilisation de la version par défaut ($DEBIAN_VERSION)"
    fi
    
    log_info "Version de Debian détectée : $DEBIAN_VERSION"
    
    # Suppression des entrées cdrom et création du nouveau fichier sources.list
    log_info "Suppression des entrées cdrom et configuration des dépôts Debian..."
    
    cat > /etc/apt/sources.list << EOF
# Sources APT générées par debian-config-script
# Dépôts pour Debian $DEBIAN_VERSION

deb http://deb.debian.org/debian $DEBIAN_VERSION main contrib non-free-firmware
deb-src http://deb.debian.org/debian $DEBIAN_VERSION main contrib non-free-firmware

deb http://security.debian.org/debian-security $DEBIAN_VERSION-security main contrib non-free-firmware
deb-src http://security.debian.org/debian-security $DEBIAN_VERSION-security main contrib non-free-firmware

deb http://deb.debian.org/debian $DEBIAN_VERSION-updates main contrib non-free-firmware
deb-src http://deb.debian.org/debian $DEBIAN_VERSION-updates main contrib non-free-firmware
EOF

    # Mise à jour des listes de paquets
    log_info "Mise à jour des listes de paquets..."
    apt-get update
    
    log_info "Configuration des sources APT terminée avec succès"
    return 0
}

# Configuration IP à partir du fichier config/ip.conf
configure_ip() {
    log_info "Configuration du réseau..."
    
    IP_CONF="config/ip.conf"
    
    if [ ! -f "$IP_CONF" ]; then
        log_error "Le fichier $IP_CONF n'existe pas"
        return 1
    fi
    
    # Vérifier si une configuration réseau existe déjà
    if ! check_existing_config "réseau" "/etc/network/interfaces"; then
        return 0
    fi
    
    # Lecture des paramètres IP depuis le fichier de configuration
    log_info "Lecture de la configuration IP depuis $IP_CONF"
    source "$IP_CONF"
    
    # Vérification de la présence des variables requises
    if [ -z "$INTERFACE" ] || [ -z "$IP_ADDRESS" ] || [ -z "$NETMASK" ] || [ -z "$GATEWAY" ] || [ -z "$DNS1" ]; then
        log_error "Le fichier de configuration IP est incomplet"
        log_error "Format attendu:"
        log_error "INTERFACE=eth0"
        log_error "IP_ADDRESS=192.168.1.100"
        log_error "NETMASK=255.255.255.0"
        log_error "GATEWAY=192.168.1.1"
        log_error "DNS1=8.8.8.8"
        log_error "DNS2=8.8.4.4 (optionnel)"
        return 1
    fi
    
    # Configuration de l'interface réseau dans /etc/network/interfaces
    log_info "Configuration de l'interface $INTERFACE avec l'adresse $IP_ADDRESS"
    
    # Sauvegarde du fichier original
    cp /etc/network/interfaces /etc/network/interfaces.bak
    
    # Création du nouveau fichier de configuration
    cat > /etc/network/interfaces << EOF
# This file describes the network interfaces available on your system
# and how to activate them. For more information, see interfaces(5).

source /etc/network/interfaces.d/*

# The loopback network interface
auto lo
iface lo inet loopback

# The primary network interface
auto $INTERFACE
iface $INTERFACE inet static
    address $IP_ADDRESS
    netmask $NETMASK
    gateway $GATEWAY
EOF

    # Configuration des DNS dans /etc/resolv.conf
    log_info "Configuration des serveurs DNS"
    cat > /etc/resolv.conf << EOF
# Generated by debian-config-script
domain local
search local
nameserver $DNS1
EOF

    # Ajout du DNS2 s'il est défini
    if [ ! -z "$DNS2" ]; then
        echo "nameserver $DNS2" >> /etc/resolv.conf
    fi
    
    # Redémarrage du service réseau
    log_info "Redémarrage du service réseau..."
    systemctl restart networking
    
    # Vérification de la connexion
    log_info "Vérification de la connexion réseau..."
    if ping -c 1 $GATEWAY > /dev/null 2>&1; then
        log_info "Configuration réseau réussie!"
        return 0
    else
        log_warning "Impossible de joindre la passerelle $GATEWAY"
        log_warning "Veuillez vérifier votre configuration"
        return 1
    fi
}

# Changement du mot de passe root
change_root_password() {
    log_info "Changement du mot de passe root..."
    
    ROOT_PASS_CONF="config/root_password.conf"
    
    if [ ! -f "$ROOT_PASS_CONF" ]; then
        log_error "Le fichier $ROOT_PASS_CONF n'existe pas"
        return 1
    fi
    
    # Demander confirmation
    echo -n "Voulez-vous changer le mot de passe root ? (o/N) "
    read -r answer
    
    if [[ ! "$answer" =~ ^[oO][uU]?[iI]?$ ]]; then
        log_info "Changement du mot de passe root ignoré"
        return 0
    fi
    
    # Lecture du mot de passe depuis le fichier de configuration
    log_info "Lecture du mot de passe root depuis $ROOT_PASS_CONF"
    source "$ROOT_PASS_CONF"
    
    # Vérification de la présence de la variable requise
    if [ -z "$ROOT_PASSWORD" ]; then
        log_error "Le fichier de configuration du mot de passe root est incomplet"
        log_error "Format attendu:"
        log_error "ROOT_PASSWORD=mot_de_passe_sécurisé"
        return 1
    fi
    
    # Changement du mot de passe root
    log_info "Mise à jour du mot de passe root..."
    echo "root:$ROOT_PASSWORD" | chpasswd
    
    if [ $? -eq 0 ]; then
        log_info "Mot de passe root changé avec succès"
        return 0
    else
        log_error "Échec du changement du mot de passe root"
        return 1
    fi
}

# Configuration de sendmail
configure_sendmail() {
    log_info "Configuration de sendmail..."
    
    SENDMAIL_CONF="config/sendmail.conf"
    
    if [ ! -f "$SENDMAIL_CONF" ]; then
        log_error "Le fichier $SENDMAIL_CONF n'existe pas"
        return 1
    fi
    
    # Vérifier si une configuration sendmail existe déjà
    if ! check_existing_config "sendmail" "/etc/mail/sendmail.mc"; then
        return 0
    fi
    
    # Vérification si sendmail est installé
    if ! command -v sendmail &> /dev/null; then
        log_info "Installation du paquet sendmail..."
        apt-get update
        apt-get install -y sendmail sendmail-cf
    fi
    
    # Lecture des paramètres sendmail depuis le fichier de configuration
    log_info "Lecture de la configuration sendmail depuis $SENDMAIL_CONF"
    source "$SENDMAIL_CONF"
    
    # Vérification de la présence des variables requises
    if [ -z "$MAIL_RELAY" ]; then
        log_error "Le fichier de configuration sendmail est incomplet"
        log_error "Format attendu:"
        log_error "MAIL_RELAY=mail.domaine.tld"
        return 1
    fi
    
    # Sauvegarde des fichiers de configuration originaux
    log_info "Sauvegarde des fichiers de configuration sendmail..."
    cp /etc/mail/sendmail.mc /etc/mail/sendmail.mc.bak
    
    # Configuration simple pour relayer les emails vers un serveur SMTP
    log_info "Configuration de sendmail pour relayer les emails vers $MAIL_RELAY..."
    
    # Création du fichier de configuration sendmail.mc simplifié
    cat > /etc/mail/sendmail.mc << EOF
divert(-1)dnl
include(\`/usr/share/sendmail/cf/m4/cf.m4')dnl
VERSIONID(\`debian config')dnl
OSTYPE(\`debian')dnl
dnl #
define(\`SMART_HOST', \`$MAIL_RELAY')dnl
define(\`confDONT_PROBE_INTERFACES', \`True')dnl
define(\`confTO_CONNECT', \`1m')dnl
define(\`confTRY_NULL_MX_LIST', \`True')dnl
define(\`confPRIVACY_FLAGS', \`authwarnings,novrfy,noexpn,restrictqrun')dnl
dnl #
FEATURE(\`no_default_msa', \`dnl')dnl
FEATURE(local_procmail, \`', \`procmail -t -Y -a \$h -d \$u')dnl
dnl #
MAILER(local)dnl
MAILER(smtp)dnl
dnl #
EOF

    # Compilation de la configuration
    log_info "Compilation de la configuration sendmail..."
    cd /etc/mail && make
    
    # Redémarrage du service sendmail
    log_info "Redémarrage du service sendmail..."
    systemctl restart sendmail
    
    # Test d'envoi d'email
    log_info "Test d'envoi d'email..."
    echo "Test d'envoi d'email depuis le script de configuration" | mail -s "Test de configuration sendmail" root
    
    # Vérification que sendmail est en cours d'exécution
    if systemctl is-active --quiet sendmail; then
        log_info "Configuration sendmail terminée avec succès"
        return 0
    else
        log_error "Échec du démarrage de sendmail"
        log_error "Vérifiez les journaux système pour plus de détails"
        return 1
    fi
}

# Configuration des utilisateurs sudoers
configure_sudoers() {
    log_info "Configuration des utilisateurs sudoers..."
    
    # Vérification si sudo est installé
    if ! command -v sudo &> /dev/null; then
        log_info "Installation du paquet sudo..."
        apt-get update
        apt-get install -y sudo
    fi
    
    # Vérifier si une configuration sudoers existe déjà
    if ! check_existing_config "sudoers" "/etc/sudoers.d/users"; then
        return 0
    fi
    
    # Création du fichier temporaire pour les règles sudoers
    SUDOERS_TMP=$(mktemp)
    
    # En-tête du fichier
    echo "# Fichier généré automatiquement par debian-config-script" > $SUDOERS_TMP
    echo "# Utilisateurs avec ID > 1000 qui peuvent utiliser sudo" >> $SUDOERS_TMP
    echo "" >> $SUDOERS_TMP
    
    # Inclusion des fichiers sudoers par défaut
    echo "# Inclure les fichiers sudoers par défaut" >> $SUDOERS_TMP
    echo "Defaults        env_reset" >> $SUDOERS_TMP
    echo "Defaults        mail_badpass" >> $SUDOERS_TMP
    echo "Defaults        secure_path=\"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\"" >> $SUDOERS_TMP
    echo "" >> $SUDOERS_TMP
    echo "# Privilèges de l'utilisateur root" >> $SUDOERS_TMP
    echo "root    ALL=(ALL:ALL) ALL" >> $SUDOERS_TMP
    echo "" >> $SUDOERS_TMP
    
    # Ajout des utilisateurs avec ID > 1000
    echo "# Utilisateurs avec ID > 1000" >> $SUDOERS_TMP
    
    # Récupération des utilisateurs avec UID > 1000
    log_info "Recherche des utilisateurs avec UID > 1000..."
    
    while IFS=: read -r username _ uid _ _ home _; do
        if [ "$uid" -gt 1000 ] && [ -d "$home" ]; then
            echo "$username ALL=(ALL:ALL) ALL" >> $SUDOERS_TMP
            log_info "Ajout de l'utilisateur $username (UID: $uid) aux sudoers"
        fi
    done < /etc/passwd
    
    # Vérification de la syntaxe du fichier sudoers
    if visudo -c -f $SUDOERS_TMP > /dev/null 2>&1; then
        # Copie du fichier temporaire vers /etc/sudoers.d/users
        cp $SUDOERS_TMP /etc/sudoers.d/users
        chmod 0440 /etc/sudoers.d/users
        log_info "Configuration des sudoers terminée avec succès"
    else
        log_error "Erreur dans la syntaxe du fichier sudoers"
        cat $SUDOERS_TMP
        rm $SUDOERS_TMP
        return 1
    fi
    
    # Suppression du fichier temporaire
    rm $SUDOERS_TMP
    
    return 0
}

# Configuration du pare-feu (iptables)
configure_firewall() {
    log_info "Configuration du pare-feu (iptables)..."
    
    # Demander si la configuration du pare-feu doit être effectuée
    echo -n "Voulez-vous configurer le pare-feu ? (o/N) "
    read -r answer
    
    if [[ ! "$answer" =~ ^[oO][uU]?[iI]?$ ]]; then
        log_info "Configuration du pare-feu ignorée"
        return 0
    fi
    
    # Vérification si iptables est installé
    if ! command -v iptables &> /dev/null; then
        log_info "Installation du paquet iptables..."
        apt-get update
        apt-get install -y iptables iptables-persistent
    fi
    
    # Réinitialisation des règles
    log_info "Réinitialisation des règles iptables..."
    iptables -F
    iptables -X
    iptables -t nat -F
    iptables -t nat -X
    iptables -t mangle -F
    iptables -t mangle -X
    
    # Définition des politiques par défaut
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT
    
    # Autoriser le trafic sur l'interface loopback
    iptables -A INPUT -i lo -j ACCEPT
    
    # Autoriser les connexions établies et liées
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    
    # Autoriser le ping (ICMP)
    iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT
    
    # Autoriser SSH
    iptables -A INPUT -p tcp --dport 22 -j ACCEPT
    
    # Autoriser HTTP et HTTPS
    iptables -A INPUT -p tcp --dport 80 -j ACCEPT
    iptables -A INPUT -p tcp --dport 443 -j ACCEPT
    
    # Autoriser SMTP
    iptables -A INPUT -p tcp --dport 25 -j ACCEPT
    
    # Sauvegarde des règles
    log_info "Sauvegarde des règles iptables..."
    iptables-save > /etc/iptables/rules.v4
    
    log_info "Configuration du pare-feu terminée avec succès"
    return 0
}

# Configuration de la sécurité de base
configure_basic_security() {
    log_info "Configuration de la sécurité de base..."
    
    # Demander si la configuration de sécurité de base doit être effectuée
    echo -n "Voulez-vous configurer la sécurité de base ? (o/N) "
    read -r answer
    
    if [[ ! "$answer" =~ ^[oO][uU]?[iI]?$ ]]; then
        log_info "Configuration de la sécurité de base ignorée"
        return 0
    fi
    
    # Mise à jour des paquets
    log_info "Mise à jour des paquets système..."
    apt-get update
    apt-get upgrade -y
    
    # Installation des paquets de sécurité essentiels
    log_info "Installation des paquets de sécurité essentiels..."
    apt-get install -y fail2ban unattended-upgrades apt-listchanges
    
    # Configuration des mises à jour automatiques
    log_info "Configuration des mises à jour automatiques..."
    cat > /etc/apt/apt.conf.d/50unattended-upgrades << EOF
Unattended-Upgrade::Allowed-Origins {
    "\${distro_id}:\${distro_codename}";
    "\${distro_id}:\${distro_codename}-security";
    "\${distro_id}:\${distro_codename}-updates";
};
Unattended-Upgrade::Package-Blacklist {
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::InstallOnShutdown "false";
Unattended-Upgrade::Mail "root";
Unattended-Upgrade::MailReport "on-change";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
EOF

    cat > /etc/apt/apt.conf.d/20auto-upgrades << EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF

    # Configuration de fail2ban
    log_info "Configuration de fail2ban..."
    cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 5
EOF

    # Redémarrage des services
    systemctl restart fail2ban
    
    # Renforcement de la sécurité SSH
    log_info "Renforcement de la configuration SSH..."
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
    
    # Modification de la configuration SSH
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
    sed -i 's/#X11Forwarding yes/X11Forwarding no/' /etc/ssh/sshd_config
    sed -i 's/#MaxAuthTries 6/MaxAuthTries 3/' /etc/ssh/sshd_config
    
    # Redémarrage du service SSH
    systemctl restart sshd
    
    log_info "Configuration de la sécurité de base terminée avec succès"
    return 0
}

# Configuration SNMP
configure_snmp() {
    log_info "Configuration de SNMP..."
    
    SNMP_CONF="config/snmp.conf"
    
    if [ ! -f "$SNMP_CONF" ]; then
        log_error "Le fichier $SNMP_CONF n'existe pas"
        return 1
    fi
    
    # Vérifier si une configuration SNMP existe déjà
    if ! check_existing_config "SNMP" "/etc/snmp/snmpd.conf"; then
        return 0
    fi
    
    # Vérification si SNMP est installé
    if ! command -v snmpd &> /dev/null; then
        log_info "Installation des paquets SNMP..."
        apt-get update
        apt-get install -y snmpd snmp libsnmp-dev
    fi
    
    # Lecture des paramètres SNMP depuis le fichier de configuration
    log_info "Lecture de la configuration SNMP depuis $SNMP_CONF"
    source "$SNMP_CONF"
    
    # Vérification de la présence des variables requises
    if [ -z "$SNMP_COMMUNITY" ] || [ -z "$SNMP_LOCATION" ] || [ -z "$SNMP_CONTACT" ]; then
        log_error "Le fichier de configuration SNMP est incomplet"
        log_error "Format attendu:"
        log_error "SNMP_COMMUNITY=public_or_private_string"
        log_error "SNMP_LOCATION=Datacenter Paris"
        log_error "SNMP_CONTACT=admin@domaine.tld"
        log_error "SNMP_ALLOWED_HOSTS=192.168.1.0/24 (optionnel)"
        return 1
    fi
    
    # Sauvegarde de la configuration originale
    log_info "Sauvegarde de la configuration SNMP originale..."
    cp /etc/snmp/snmpd.conf /etc/snmp/snmpd.conf.bak
    
    # Création du fichier de configuration SNMP
    log_info "Création du fichier de configuration SNMP..."
    
    # Configuration de base
    cat > /etc/snmp/snmpd.conf << EOF
# Configuration générée par debian-config-script

# Informations de contact et d'emplacement
sysLocation    $SNMP_LOCATION
sysContact     $SNMP_CONTACT

# Configuration de la communauté
# Autoriser la lecture seule avec la communauté spécifiée
EOF

    # Configuration des hôtes autorisés
    if [ -z "$SNMP_ALLOWED_HOSTS" ]; then
        # Par défaut, autoriser uniquement localhost
        SNMP_ALLOWED_HOSTS="127.0.0.1"
    fi
    
    # Ajout des communautés et restrictions d'accès
    echo "rocommunity $SNMP_COMMUNITY $SNMP_ALLOWED_HOSTS" >> /etc/snmp/snmpd.conf
    
    # Configuration supplémentaire
    cat >> /etc/snmp/snmpd.conf << EOF

# Configuration des vues
view   systemview    included   .1.3.6.1.2.1.1
view   systemview    included   .1.3.6.1.2.1.25.1

# Désactiver l'accès en écriture
# Seule la lecture est autorisée
access  notConfigGroup ""      any       noauth    exact  systemview none none

# Configuration pour la collecte de données
# Informations système
view   systemview    included   .1.3.6.1.2.1.25.1.1      # Uptime
view   systemview    included   .1.3.6.1.4.1.2021.11     # Utilisation CPU
view   systemview    included   .1.3.6.1.4.1.2021.4      # Buffers
view   systemview    included   .1.3.6.1.4.1.2021.9      # Disques

# Collecte des informations réseau
view   systemview    included   .1.3.6.1.2.1.2           # Interfaces
view   systemview    included   .1.3.6.1.2.1.4           # IP

# Configuration des performances
agentAddress udp:161
master agentx
agentXSocket /var/agentx/master
agentXPerms 0660 0550 nobody root
EOF

    # Configuration du service
    log_info "Configuration du service SNMP..."
    
    # Modification pour écouter sur toutes les interfaces
    sed -i 's/^SNMPDOPTS=.*/SNMPDOPTS="-Lsd -Lf \/dev\/null -u snmp -g snmp -I -smux -p \/var\/run\/snmpd.pid"/' /etc/default/snmpd
    
    # Redémarrage du service SNMP
    log_info "Redémarrage du service SNMP..."
    systemctl restart snmpd
    
    # Vérification que SNMP est en cours d'exécution
    if systemctl is-active --quiet snmpd; then
        log_info "Test de la configuration SNMP..."
        # Test de la configuration avec snmpwalk
        if command -v snmpwalk &> /dev/null; then
            if snmpwalk -v2c -c "$SNMP_COMMUNITY" localhost system > /dev/null 2>&1; then
                log_info "Configuration SNMP terminée avec succès"
                return 0
            else
                log_warning "SNMP semble fonctionner mais le test a échoué"
                log_warning "Vérifiez votre configuration manuellement"
                return 0
            fi
        else
            log_info "Configuration SNMP terminée avec succès"
            return 0
        fi
    else
        log_error "Échec du démarrage de SNMP"
        log_error "Vérifiez les journaux système pour plus de détails"
        return 1
    fi
}

# Configuration NTP (synchronisation de l'heure)
configure_ntp() {
    log_info "Configuration de la synchronisation de l'heure (NTP)..."
    
    # Vérifier si une configuration NTP existe déjà
    if ! check_existing_config "NTP" "/etc/systemd/timesyncd.conf"; then
        return 0
    fi
    
    # Installation du paquet systemd-timesyncd
    log_info "Installation du service NTP..."
    apt-get install -y systemd-timesyncd
    
    # Configuration des serveurs NTP
    log_info "Configuration des serveurs NTP..."
    cat > /etc/systemd/timesyncd.conf << EOF
[Time]
NTP=0.ch.pool.ntp.org 1.ch.pool.ntp.org 2.ch.pool.ntp.org 3.ch.pool.ntp.org
FallbackNTP=0.debian.pool.ntp.org 1.debian.pool.ntp.org 2.debian.pool.ntp.org 3.debian.pool.ntp.org
EOF

    # Activation et démarrage du service
    log_info "Activation du service NTP..."
    systemctl enable systemd-timesyncd
    systemctl restart systemd-timesyncd
    
    # Vérification de l'état de la synchronisation
    sleep 2
    if timedatectl status | grep -q "synchronized: yes"; then
        log_info "Synchronisation NTP réussie"
        return 0
    else
        log_warning "La synchronisation NTP n'est pas encore établie"
        log_warning "Vérifiez l'état avec 'timedatectl status'"
        return 0
    fi
}

# Fonction principale
main() {
    log_info "Démarrage de la configuration automatique du système Debian..."
    
    # Afficher un menu des options
    echo "Options de configuration disponibles :"
    echo "1. Configuration des sources APT"
    echo "2. Configuration IP"
    echo "3. Changement du mot de passe root"
    echo "4. Configuration des utilisateurs sudoers"
    echo "5. Configuration de sendmail"
    echo "6. Configuration de la sécurité de base (optionnel)"
    echo "7. Configuration du pare-feu (optionnel)"
    echo "8. Configuration SNMP"
    echo "9. Configuration NTP"
    echo "0. Tout configurer (avec confirmation pour chaque étape)"
    echo ""
    echo -n "Choisissez une option (0-9) ou appuyez sur Entrée pour tout configurer : "
    read -r choice
    
    # Si aucun choix n'est fait, configurer tout
    if [ -z "$choice" ]; then
        choice="0"
    fi
    
    case $choice in
        0)
            # Tout configurer avec confirmations
            
            # Étape 0: Configuration des sources APT
            log_info "Étape 0: Configuration des sources APT"
            if configure_apt_sources; then
                log_info "Configuration des sources APT terminée avec succès"
            else
                log_warning "Échec ou annulation de la configuration des sources APT"
            fi
            
            # Étape 1: Configuration IP
            log_info "Étape 1: Configuration IP"
            if configure_ip; then
                log_info "Configuration IP terminée avec succès"
            else
                log_warning "Échec ou annulation de la configuration IP"
            fi
            
            # Étape 2: Changement du mot de passe root
            log_info "Étape 2: Changement du mot de passe root"
            if change_root_password; then
                log_info "Changement du mot de passe root terminé avec succès"
            else
                log_warning "Échec ou annulation du changement du mot de passe root"
            fi
            
            # Étape 3: Configuration des utilisateurs sudoers
            log_info "Étape 3: Configuration des utilisateurs sudoers"
            if configure_sudoers; then
                log_info "Configuration des utilisateurs sudoers terminée avec succès"
            else
                log_warning "Échec ou annulation de la configuration des utilisateurs sudoers"
            fi
            
            # Étape 4: Configuration de sendmail
            log_info "Étape 4: Configuration de sendmail"
            if configure_sendmail; then
                log_info "Configuration de sendmail terminée avec succès"
            else
                log_warning "Échec ou annulation de la configuration de sendmail"
            fi
            
            # Étape 5: Configuration de la sécurité de base (optionnel)
            log_info "Étape 5: Configuration de la sécurité de base (optionnel)"
            if configure_basic_security; then
                log_info "Configuration de la sécurité de base terminée avec succès"
            else
                log_warning "Configuration de la sécurité de base ignorée ou annulée"
            fi
            
            # Étape 6: Configuration du pare-feu (optionnel)
            log_info "Étape 6: Configuration du pare-feu (optionnel)"
            if configure_firewall; then
                log_info "Configuration du pare-feu terminée avec succès"
            else
                log_warning "Configuration du pare-feu ignorée ou annulée"
            fi
            
            # Étape 7: Configuration SNMP
            log_info "Étape 7: Configuration SNMP"
            if configure_snmp; then
                log_info "Configuration SNMP terminée avec succès"
            else
                log_warning "Échec ou annulation de la configuration SNMP"
            fi
            
            # Étape 8: Configuration NTP
            log_info "Étape 8: Configuration NTP"
            if configure_ntp; then
                log_info "Configuration NTP terminée avec succès"
            else
                log_warning "Échec ou annulation de la configuration NTP"
            fi
            ;;
        1)
            # Configuration des sources APT
            if configure_apt_sources; then
                log_info "Configuration des sources APT terminée avec succès"
            else
                log_error "Échec ou annulation de la configuration des sources APT"
                exit 1
            fi
            ;;
        2)
            # Configuration IP
            if configure_ip; then
                log_info "Configuration IP terminée avec succès"
            else
                log_error "Échec ou annulation de la configuration IP"
                exit 1
            fi
            ;;
        3)
            # Changement du mot de passe root
            if change_root_password; then
                log_info "Changement du mot de passe root terminé avec succès"
            else
                log_error "Échec ou annulation du changement du mot de passe root"
                exit 1
            fi
            ;;
        4)
            # Configuration des utilisateurs sudoers
            if configure_sudoers; then
                log_info "Configuration des utilisateurs sudoers terminée avec succès"
            else
                log_error "Échec ou annulation de la configuration des utilisateurs sudoers"
                exit 1
            fi
            ;;
        5)
            # Configuration de sendmail
            if configure_sendmail; then
                log_info "Configuration de sendmail terminée avec succès"
            else
                log_error "Échec ou annulation de la configuration de sendmail"
                exit 1
            fi
            ;;
        6)
            # Configuration de la sécurité de base
            if configure_basic_security; then
                log_info "Configuration de la sécurité de base terminée avec succès"
            else
                log_warning "Configuration de la sécurité de base ignorée ou annulée"
            fi
            ;;
        7)
            # Configuration du pare-feu
            if configure_firewall; then
                log_info "Configuration du pare-feu terminée avec succès"
            else
                log_warning "Configuration du pare-feu ignorée ou annulée"
            fi
            ;;
        8)
            # Configuration SNMP
            if configure_snmp; then
                log_info "Configuration SNMP terminée avec succès"
            else
                log_error "Échec ou annulation de la configuration SNMP"
                exit 1
            fi
            ;;
        9)
            # Configuration NTP
            if configure_ntp; then
                log_info "Configuration NTP terminée avec succès"
            else
                log_error "Échec ou annulation de la configuration NTP"
                exit 1
            fi
            ;;
        *)
            log_error "Option invalide"
            exit 1
            ;;
    esac
    
    log_info "Configuration automatique terminée"
}

# Exécution de la fonction principale
main
