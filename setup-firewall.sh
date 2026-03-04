#!/bin/bash
set -euo pipefail
umask 077

# --- Fonctions ---
log() { echo "$*"; }
err() { echo "ERREUR : $*" >&2; }

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || { err "commande manquante : $1"; exit 1; }
}

# --- Vérification root ---
if [ "$(id -u)" -ne 0 ]; then
  err "ce script doit être exécuté en tant que root."
  exit 1
fi

# --- Vérification dépendances ---
need_cmd systemctl

# --- Détection du gestionnaire de paquets ---
if command -v apt >/dev/null 2>&1; then
  PKG_MANAGER="apt"
elif command -v dnf >/dev/null 2>&1; then
  PKG_MANAGER="dnf"
else
  err "gestionnaire de paquets non supporté (apt ou dnf requis)."
  exit 1
fi

# --- Détection du firewall actif ---
detect_firewall() {
  if systemctl is-active --quiet firewalld 2>/dev/null; then
    echo "firewalld"
    return
  fi

  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi "active"; then
    echo "ufw"
    return
  fi

  if systemctl is-active --quiet nftables 2>/dev/null; then
    echo "nftables"
    return
  fi
  if command -v nft >/dev/null 2>&1 && nft list ruleset 2>/dev/null | grep -q .; then
    echo "nftables"
    return
  fi

  if command -v iptables >/dev/null 2>&1 && iptables -L -n 2>/dev/null | grep -q "^Chain"; then
    # Ignorer les chaînes résiduelles de ufw si ufw est installé mais inactif
    if ! command -v ufw >/dev/null 2>&1 || ! iptables -L -n 2>/dev/null | grep -q "^Chain ufw-"; then
      echo "iptables"
      return
    fi
  fi

  echo "aucun"
}

DETECTED="$(detect_firewall)"

# --- Affichage résultat détection ---
echo ""
if [ "$DETECTED" = "aucun" ]; then
  log "Aucun firewall actif détecté sur ce système."
else
  log "Firewall actif détecté : $DETECTED"
fi

# --- Menu de sélection ---
echo ""
log "Choisissez le firewall à installer et activer :"
echo ""

options=("iptables" "nftables" "firewalld" "ufw")
descriptions=(
  "classique, compatible partout, simple"
  "successeur d'iptables, performant, syntaxe unifiée"
  "gestion par zones, rechargement dynamique, courant sur Fedora/RHEL"
  "simple d'utilisation, courant sur Ubuntu"
)

for i in "${!options[@]}"; do
  num=$((i + 1))
  marqueur=""
  if [ "${options[$i]}" = "$DETECTED" ]; then
    marqueur=" (actif)"
  fi
  echo "  $num) ${options[$i]} — ${descriptions[$i]}${marqueur}"
done

echo ""
read -rp "Votre choix [1-4] : " choix

case "$choix" in
  1) FIREWALL="iptables" ;;
  2) FIREWALL="nftables" ;;
  3) FIREWALL="firewalld" ;;
  4) FIREWALL="ufw" ;;
  *) err "choix invalide : $choix"; exit 1 ;;
esac

# --- Vérifier si déjà actif ---
if [ "$FIREWALL" = "$DETECTED" ]; then
  echo ""
  log "$FIREWALL est déjà actif sur ce système. Rien à faire."
  exit 0
fi

echo ""
log "Installation et activation de : $FIREWALL"

# --- Demander si un port doit être ouvert (protection anti-lockout SSH) ---
echo ""
read -rp "Port à ouvrir avant activation (ex: port SSH, vide pour passer) : " SAFE_PORT

if [ -n "$SAFE_PORT" ]; then
  if ! [[ "$SAFE_PORT" =~ ^[0-9]+$ ]] || [ "$SAFE_PORT" -lt 1 ] || [ "$SAFE_PORT" -gt 65535 ]; then
    err "port invalide : $SAFE_PORT"
    exit 1
  fi
fi

# --- Désactiver l'ancien firewall ---
if [ "$DETECTED" != "aucun" ]; then
  log "Désactivation de l'ancien firewall : $DETECTED"
  case "$DETECTED" in
    firewalld)
      systemctl stop firewalld
      systemctl disable firewalld
      ;;
    ufw)
      ufw disable
      ;;
    nftables)
      systemctl stop nftables
      systemctl disable nftables
      ;;
    iptables)
      for table in filter nat mangle raw; do
        iptables -t "$table" -F 2>/dev/null || true
        iptables -t "$table" -X 2>/dev/null || true
      done
      if command -v ip6tables >/dev/null 2>&1; then
        for table in filter nat mangle raw; do
          ip6tables -t "$table" -F 2>/dev/null || true
          ip6tables -t "$table" -X 2>/dev/null || true
        done
      fi
      log "Tables iptables/ip6tables vidées (flush + delete chains)."
      ;;
  esac
  log "$DETECTED désactivé."
fi

# --- Installer le nouveau firewall ---
log "Installation du paquet $FIREWALL..."
if [ "$PKG_MANAGER" = "apt" ]; then
  apt update -qq
fi
case "$FIREWALL" in
  iptables)
    if [ "$PKG_MANAGER" = "apt" ]; then
      apt install -y iptables
    else
      dnf install -y iptables
    fi
    ;;
  nftables)
    if [ "$PKG_MANAGER" = "apt" ]; then
      apt install -y nftables
    else
      dnf install -y nftables
    fi
    ;;
  firewalld)
    if [ "$PKG_MANAGER" = "apt" ]; then
      apt install -y firewalld
    else
      dnf install -y firewalld
    fi
    ;;
  ufw)
    if [ "$PKG_MANAGER" = "apt" ]; then
      apt install -y ufw
    else
      dnf install -y ufw
    fi
    ;;
esac

# --- Activer et démarrer le nouveau firewall ---
log "Activation de $FIREWALL..."
case "$FIREWALL" in
  iptables)
    if [ -n "$SAFE_PORT" ]; then
      iptables -I INPUT -p tcp --dport "$SAFE_PORT" -j ACCEPT
      log "Port $SAFE_PORT/tcp ouvert (iptables)."
    fi
    log "iptables est prêt (pas de service systemd à activer)."
    ;;
  nftables)
    systemctl enable nftables
    systemctl start nftables
    if [ -n "$SAFE_PORT" ]; then
      nft add table inet admin_access 2>/dev/null || true
      nft add chain inet admin_access input '{ type filter hook input priority -10 ; policy accept ; }' 2>/dev/null || true
      nft add rule inet admin_access input tcp dport "$SAFE_PORT" accept
      log "Port $SAFE_PORT/tcp ouvert (nftables)."
    fi
    ;;
  firewalld)
    systemctl enable firewalld
    systemctl start firewalld
    if [ -n "$SAFE_PORT" ]; then
      firewall-cmd --permanent --add-port="$SAFE_PORT"/tcp
      firewall-cmd --reload
      log "Port $SAFE_PORT/tcp ouvert (firewalld)."
    fi
    ;;
  ufw)
    if [ -n "$SAFE_PORT" ]; then
      ufw allow "$SAFE_PORT"/tcp
      log "Port $SAFE_PORT/tcp ouvert (ufw)."
    fi
    ufw --force enable
    ;;
esac

echo ""
log "$FIREWALL installé et activé avec succès."
log "Lancez update-blocklist.sh pour télécharger les IP et appliquer les règles de blocage."
