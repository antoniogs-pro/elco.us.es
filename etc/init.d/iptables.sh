#! /bin/bash
# Script de configuración Firewall  con iptables equipo ELCO
# Autor Antonio González
# Fecha última modificación: 15/05/2017
# Sustituir la palabra iptables donde aparecia por $RULE
echo $LANG | grep 'ES.'
FECHAHORA=`date  "+%Y_%m_%d_%r"`
RULE='/sbin/iptables'  # no poner espacios detras
RULE6='/sbin/ip6tables'
IFCFG='/sbin//sbin/ifconfig'
RUTA=/home/$USER/bin
LOG=${LOG=/var/log/iptables.log}
#
US_LAN='150.214.142.0/23'
#MY_NETWORK=$( /sbin/ifconfig eth0 | grep addr: | tr -s " " | cut -d " " -f 3 | cut -d: -f 2 | cut -d"." -f 1,2,3)  # para sistemas en inglés
MY_NETWORK=$( /sbin/ifconfig eth0 | grep inet: | tr -s " " | cut -d " " -f 3 | cut -d: -f 2 | cut -d"." -f 1,2,3)
#MY_NETWORK=150.214.143
#MY_NETWORK=10.10.10
#GATEWAY=$MY_NETWORK.1
GATEWAY=$(ip -4 neigh | cut -d" " -f1)
#
#MY_IP=$(/sbin/ifconfig eth0 | grep addr: | tr -s " " | cut -d " " -f 3 | cut -d: -f 2) # para sistemas en inglés
MY_IP=$(/sbin/ifconfig eth0 | grep inet: | tr -s " " | cut -d " " -f 3 | cut -d: -f 2)
# MY_IP=$(ip -4 address show eth0 |  grep inet | tr -s " " | cut -d " " -f 3 | cut -d"/" -f1)

#MY_IP=$MY_NETWORK.178
#MY_IP=$MY_NETWORK.2
export MYHOMEIP
NTPSERVER=150.214.143.1
SERVIDOR_VPN_CORREO=193.147.175.141
SERVIDOR_VPN_HOSTING=193.147.175.254
SERVIDOR_VPN_PROTOCOLO=UDP
SERVIDOR_VPN_PORT=1194
SERVIDOR_X_PORT=6010
REMOTE_X_PORT=6000
JUANMI_IP=193.147.175.29 # orlock.us.es
JAVIERDEMIGUEL_IP=193.147.175.59 # NERVION.US.ES
JORGE_IP=176.10.75.202
MYHOMEIP=10.219.215.2
#MYHOMEIP=$(nslookup anglez.dyndns.org | grep -v "#" | grep "Address:"|cut -d" " -f2)
sleep 5
export MYHOMEIP
# equipos de confianza
MVWIN7=192.168.3.103
MVWIN10=192.168.2.159
NAGIOSHOSTING=192.168.20.101
SVRLDAP=192.168.1.111
SVRANTIVIRUS=192.168.2.11
SVRANTIVIRUS1=192.168.2.11
SVRANTIVIRUS2=192.168.2.12
SVRANTIVIRUS3=192.168.2.13
SVRANTIVIRUS4=192.168.2.14
SVRANTIVIRUS5=192.168.2.15
SVRANTIVIRUS6=192.168.2.16
SVRCONTINUIDAD=192.168.20.165
SVRARQUERO=172.20.12.125
#DEFAULT
#IPTABLESRULES="OFF"
IPTABLESRULES=${IPTABLESRULES="OFF"}

export IPTABLESRULES
### Reglas contra el falseo (spoofing) de IP
BROADCAST='255.0.0.0/8'
NOIP='0.0.0.0/8'
LOCALHOST='127.0.0.0/8'
BROADCASTDIRECT=${MY_NETWORK}'.255/32'
MULTICAST='224.0.0.0/4'
PRIVA="10.0.0.0/8"
PRIVAOK='10.10.10.0/24'
PRIVB='172.16.0.0/12'
PRIVBOK='172.20.0.0/16'
PRIVCOK='192.168.0.0/19'
PRIVC='192.168.0.0/16'
MSGIPFALSA=' Alerta: IP origen falseada '
# IMPEDIR FALSEO CON PROPIA IP
$RULE -A INPUT -s $MY_IP -j LOG --log-prefix "Alerta: Fuente falseada, IP propia"
$RULE -A INPUT -s $MY_IP -j DROP 


$RULE -A INPUT -s $BROADCAST -j LOG --log-prefix "$MSGIPFALSA"
$RULE -A INPUT -s $BROADCAST -j DROP
$RULE -A INPUT -s $BROADCASTDIRECT -j LOG --log-prefix "$MSGIPFALSA"
$RULE -A INPUT -s $BROADCASTDIRECT -j DROP
$RULE -A INPUT -s $MULTICAST -j LOG --log-prefix "$MSGIPFALSA"
$RULE -A INPUT -s $MULTICAST -j DROP
$RULE -A INPUT -s $NOIP -j LOG --log-prefix "$MSGIPFALSA"
$RULE -A INPUT -s $NOIP -j DROP
$RULE -A INPUT -s $LOCALHOST -j LOG --log-prefix "$MSGIPFALSA"
$RULE -A INPUT -s $LOCALHOST -j DROP

$RULE -A INPUT -s $PRIVCOK -j ACCEPT
$RULE -A INPUT -s $PRIVC -j LOG --log-prefix "$MSGIPFALSA"
#$RULE -A INPUT -s $PRIVC -j DROP

$RULE -A INPUT -s $PRIVBOK -j ACCEPT
$RULE -A INPUT -s $PRIVB -j LOG --log-prefix "$MSGIPFALSA"
#$RULE -A INPUT -s $PRIVB -j DROP

$RULE -A INPUT -s $PRIVAOK -j ACCEPT
$RULE -A INPUT -s $PRIVA -j LOG --log-prefix "$MSGIPFALSA"
$RULE -A INPUT -s $PRIVA -j DROP


##Rastreo de furtivos TCP
$RULE -A INPUT -p tcp ! --syn -m state --state NEW -j LOG --log-prefix "Alerta: Conexiones TCP furtivas "
$RULE -A INPUT -p tcp ! --syn -m state --state NEW -j DROP

# Fin DEFAULT
#################################################################################33
case "$1" in 

"status" )
# show estatus and  save rules
$RULE -L --line-numbers -v
$RULE -S
$RULE6 -nvL
echo Salvando reglas
${RULE}-save |tee  $HOME/"iptables-2014-$FECHAHORA" > /etc/default/iptables.rules
#sudo ip6tables-save > /etc/default/ip6tables.rules

;; # Fin opcion case estatus
"debug" )

# PARA ACTIVAR DEBUG  SOLAMENTE
echo Activando debug para iptables
logger " `date`   Activando depuracion  firewall "
#$RULE -A INPUT -p tcp  -j ACCEPT
$RULE -A OUTPUT -j LOG --log-prefix "Depurando OUTPUT IPTABLES"
$RULE -A INPUT -j LOG --log-prefix "Depurando INPUT  IPTABLES"
$RULE -A FORWARD  -j  LOG --log-prefix "FORWARD Default Policy Droped"
$RULE -A INPUT -p udp  -j LOG  --log-prefix " Depurando UDP"
$RULE -A INPUT -p icmp  -j LOG  --log-prefix " Depurando ICMP"
IPTABLESRULES=OFF
#ACTIVANDO FAIL2BAN
/etc/init.d/fail2ban restart
;; # Fin opcion case

"nodebug" )
# PARA ELIMINAR DEBUG  SOLAMENTE
logger " `date`   Des-activando depuracion  firewall "
#$RULE -A INPUT -p tcp  -j DROP
$RULE -D INPUT -j LOG --log-prefix "Depurando INPUT  IPTABLES"
$RULE -D OUTPUT -j LOG --log-prefix "Depurando OUTPUT IPTABLES"
$RULE -D FORWARD  -j  LOG --log-prefix "FORWARD Default Policy Droped"
$RULE -D INPUT -p udp  -j LOG  --log-prefix " Depurando UDP"
$RULE -D INPUT -p icmp  -j LOG  --log-prefix " Depurando ICMP"
IPTABLESRULES=OFF
#ACTIVANDO FAIL2BAN
/etc/init.d/fail2ban restart
;; # Fin opcion case

"stop" )
#cleanig
echo Eliminando reglas de firewall
$RULE -F
$RULE --delete-chain
$RULE -X
$RULE -t nat -F
# default policy
$RULE -P INPUT  ACCEPT
$RULE -P OUTPUT ACCEPT
$RULE -P FORWARD DROP

IPTABLESRULES=OFF
#ACTIVANDO FAIL2BAN
/etc/init.d/fail2ban restart
;; # Fin opcion case

"start" )
echo Cargando reglas de firewall
#cleanig
$RULE -F
$RULE --delete-chain
$RULE -X
$RULE -t nat -F
# default policy
$RULE -P INPUT DROP
$RULE -P OUTPUT  DROP
$RULE -P FORWARD DROP

# FORWARD rules
$RULE -A FORWARD  -j DROP

# Interfaces siempre  operativas
$RULE -A INPUT -i lo  -j ACCEPT
$RULE -A OUTPUT -o lo  -j ACCEPT
#$RULE -A INPUT -i tun0  -j ACCEPT
#$RULE -A OUTPUT -o tun0  -j ACCEPT
#$RULE -A INPUT -i tun1  -j ACCEPT
#$RULE -A OUTPUT -o tun1  -j ACCEPT

# Interfaces NUNCA  operativas
# wlan0
$RULE -A INPUT -i wlan0  -j DROP
$RULE -A OUTPUT -o wlan0  -j DROP

# mitigar ataques tradicionales de falseamiento
$RULE -A INPUT -s $MY_IP/32  -j DROP
$RULE -A OUTPUT -d $MY_IP/32   -j DROP
$RULE -A INPUT -s $BROADCAST  -j DROP
$RULE -A OUTPUT -d $BROADCAST   -j DROP
#$RULE -A INPUT -s $BROADCASTDIRECT  -j DROP
#$RULE -A OUTPUT -d $BROADCASTDIRECT   -j DROP
$RULE -A INPUT -s $MULTICAST  -j DROP
$RULE -A OUTPUT -d $MULTICAST   -j DROP

#$RULE -A INPUT -s $PRIVBOK -j ACCEPT
#$RULE -A INPUT -s $PRIVB  -j DROP
#$RULE -A OUTPUT -s $PRIVBOK -j ACCEPT
#$RULE -A OUTPUT -d $PRIVB   -j DROP

$RULE -A INPUT -s $PRIVAOK  -j ACCEPT
$RULE -A OUTPUT -d $PRIVAOK   -j ACCEPT
$RULE -A INPUT -s $PRIVA  -j DROP
$RULE -A OUTPUT -d $PRIVA   -j DROP

#  CHAINS definidas
# Chain for preventing SSH brute-force attacks.
# Permits 10 new connections within 5 minutes from a single host then drops 
# incomming connections from that host. Beyond a burst of 100 connections we 
# log at up 1 attempt per second to prevent filling of logs.
$RULE -N SSHBRUTE
$RULE -A SSHBRUTE -m recent --name SSH --set
$RULE -A SSHBRUTE -m recent --name SSH --update --seconds 300 --hitcount 10 -m limit --limit 1/second --limit-burst 100 -j LOG --log-prefix "iptables[SSH-brute]: "
$RULE -A SSHBRUTE -m recent --name SSH --update --seconds 300 --hitcount 10 -j DROP
$RULE -A SSHBRUTE -j RETURN
#

#IP Explicitamente Baneados
#$RULE -A INPUT -s 91.189.0.0/16 -j DROP # jode las actualizaciones de ubuntu

# IP Explicitamente permitidas
#$RULE -A INPUT -s 91.189.0.0/16 -j ACCEPT # para las actualizaciones de ubuntu


# politica por servicios o protocolo ICMP
#  ICMP IN
$RULE -A INPUT -p icmp  --icmp-type echo-reply -j ACCEPT
$RULE -A INPUT -s $MYHOMEIP/32 -p icmp  --icmp-type echo-request -j DROP
$RULE -A INPUT -p icmp  -j DROP
#   ICMP OUT
$RULE -A OUTPUT -p icmp  --icmp-type echo-request -j ACCEPT
#$RULE -A OUTPUT -s $MYHOMEIP/32 -p icmp  --icmp-type echo-reply -j ACCEPT
#$RULE -A OUTPUT -p icmp  -j DROP
#$RULE6 -A INPUT -p icmpv6 --icmpv6-type 128 -j DROP
#$RULE6 -A INPUT -p icmpv6 --icmpv6 -j ACCEPT

# politica por servicios o protocolo UDP
# UDP IN
$RULE -A INPUT -p udp --dport 19 -j DROP
$RULE -A INPUT -p udp  --sport 53 -j ACCEPT  # DNS
$RULE -A INPUT -p udp  --dport 9 -j ACCEPT  # WOL
$RULE -A INPUT -p udp  --dport 7 -j ACCEPT  # WOL
$RULE -A INPUT -p udp -s $NTPSERVER/32 --sport 123 -j ACCEPT # NTP
$RULE -A INPUT -p udp  --sport 500 -j ACCEPT  # IKE 
$RULE -A INPUT -p udp  --sport 4500 -j ACCEPT  # encapsulamiento ESP sobre UDP
$RULE -A INPUT -p udp  --sport $SERVIDOR_VPN_PORT -j ACCEPT # openvpn
$RULE -A INPUT -p gre -j ACCEPT  # IPSEC
$RULE -A INPUT -p ah -j ACCEPT   # IPSEC
$RULE -A INPUT -p esp -j ACCEPT  # IPSEC
$RULE -A INPUT -p 50 -j ACCEPT   # IPSEC ESP
$RULE -A INPUT -p 51 -j ACCEPT   # IPSEC AH
#$RULE -A INPUT -p udp -j ACCEPT
$RULE -A INPUT -p udp -j DROP
# UDP OUT
$RULE -A OUTPUT -p udp --dport 19 -j DROP
$RULE -A OUTPUT -p udp --dport 53 -j ACCEPT  # DNS
$RULE -A OUTPUT -p udp --dport 123 -j ACCEPT # NTP
$RULE -A OUTPUT -p udp --dport 500 -j ACCEPT    # IKE 
$RULE -A OUTPUT -p udp --dport 4500 -j ACCEPT  # encapsulamiento ESP sobre UDP
$RULE -A OUTPUT -p udp --dport $SERVIDOR_VPN_PORT -j ACCEPT # openvpn
$RULE -A OUTPUT -p gre -j ACCEPT  # IPSEC
$RULE -A OUTPUT -p ah -j ACCEPT  # IPSEC
$RULE -A OUTPUT -p esp -j ACCEPT  # IPSEC
$RULE -A OUTPUT -p 50 -j ACCEPT  # IPSEC
$RULE -A OUTPUT -p 51 -j ACCEPT  # IPSEC
#$RULE -A OUTPUT -p udp -j ACCEPT
$RULE -A OUTPUT -p udp -j DROP

# politica por servicios o protocolo TCP
#
# politica de generica de entrada TCP IN
# accepted para definidos default drop
# establecidos
$RULE -A INPUT -p tcp --dport 22 -j LOG --log-prefix "Depurando INPUT to 22 IPTABLES"
$RULE -A INPUT -p tcp --sport 22 -j LOG --log-prefix "Depurando INPUT from 22 IPTABLES"
$RULE -A INPUT -p tcp --sport 22 -m state --state  RELATED,ESTABLISHED -j ACCEPT
$RULE -A INPUT -s$SVRARQUERO/32 -p tcp --sport 3389  -m state --state  RELATED,ESTABLISHED -j ACCEPT
$RULE -A INPUT -p tcp -m state --state  RELATED,ESTABLISHED -j ACCEPT
#$RULE -A INPUT -s 192.168.5.220/32 -p tcp --sport 22 -m state --state RELATED,ESTABLISHED  -j ACCEPT
# pongo la siguiente línea en cuarentena
#$RULE -A INPUT -s 172.20.12.151/32 -p tcp --sport 22 -m state --state RELATED,ESTABLISHED  -j ACCEPT
#
$RULE -A INPUT -s $JUANMI_IP/32 -p tcp --dport 22 -m state --state NEW -j ACCEPT
#$RULE -A INPUT -s $JORGE_IP/32 -p tcp --dport 22 -m state --state NEW -j ACCEPT
$RULE -A INPUT -s $JUANMI_IP/32 -p tcp --dport 2220 -m state --state NEW -j ACCEPT
$RULE -A INPUT -s $JAVIERDEMIGUEL_IP/32 -p tcp --dport 22 -m state --state NEW -j ACCEPT
#
$RULE -A INPUT -s $MYHOMEIP/32 -p tcp --dport 22 -m state --state NEW -j ACCEPT
$RULE -A INPUT -s $MYHOMEIP/32 -p tcp --dport $SERVIDOR_X_PORT -m state --state NEW -j ACCEPT
$RULE -A INPUT -s $MYHOMEIP/32 -p tcp --dport 80 -m state --state NEW -j ACCEPT
$RULE -A INPUT -s $MYHOMEIP/32 -p tcp --dport 443 -m state --state NEW -j ACCEPT
$RULE -A INPUT -s $MYHOMEIP/32 -p tcp --dport 2220 -m state --state NEW -j ACCEPT
$RULE -A INPUT -s $MYHOMEIP/32 -p tcp --dport 2221 -m state --state NEW -j ACCEPT
$RULE -A INPUT -s $MYHOMEIP/32 -p tcp --dport 2222 -m state --state NEW -j ACCEPT
$RULE -A INPUT -s $MYHOMEIP/32 -p tcp --dport 3331 -m state --state NEW -j ACCEPT
$RULE -A INPUT -s $MYHOMEIP/32 -p tcp --dport 3332 -m state --state NEW -j ACCEPT
$RULE -A INPUT -s $MYHOMEIP/32 -p tcp --dport 3337 -m state --state NEW -j ACCEPT
$RULE -A INPUT -s $MYHOMEIP/32 -p tcp --dport 3314 -m state --state NEW -j ACCEPT
$RULE -A INPUT -s $MYHOMEIP/32 -j ACCEPT
# Por tener al menos un sistema de pruebas
$RULE -A INPUT  -p tcp --dport 80 -m state --state NEW -j ACCEPT
$RULE -A INPUT  -p tcp --dport 443 -m state --state NEW -j ACCEPT
$RULE -A INPUT  -p tcp --dport 22 -m state --state NEW -j ACCEPT
#
# $RULE -A INPUT -s ${SERVIDOR_VPN_CORREO}/32 -p tcp --dport 10000 -m state --state NEW -j ACCEPT  # encapsulación ESP sobre TCP
#$RULE -A INPUT -s $MVWIN7/32 --sport 3389 -m state --state  RELATED,ESTABLISHED  -j ACCEPT
$RULE -A INPUT -s $MVWIN7/32  -j ACCEPT
$RULE -A INPUT -s $MVWIN10/32  -j ACCEPT
# 
#$RULE -A INPUT -s150.214.0.0/16 -j ACCEPT

$RULE -A INPUT -s $PRIVC -j DROP

$RULE -A OUTPUT -p udp  --sport 9 -j ACCEPT  # WOL
# politica  generica de  salida TCP OUT
# accepted para definidos default drop

# Conexiones de confianza
$RULE -A OUTPUT -p tcp --dport 22 -m state --state NEW  -j ACCEPT
$RULE -A OUTPUT -p tcp --dport 22  -j ACCEPT
$RULE -A OUTPUT -p tcp --dport 80   -j ACCEPT
$RULE -A OUTPUT -p tcp --dport 443  -j ACCEPT

# $RULE -A INPUT -s ${SERVIDOR_VPN_CORREO}/32 -p tcp --dport 10000 -j ACCEPT  # encapsulación ESP sobre TCP
$RULE -A OUTPUT -p tcp --sport 80 -m state --state  RELATED,ESTABLISHED -j ACCEPT
$RULE -A OUTPUT -p tcp --sport 443 -m state --state  RELATED,ESTABLISHED -j ACCEPT
$RULE -A OUTPUT -p tcp --sport 22 -m state --state  RELATED,ESTABLISHED -j ACCEPT
$RULE -A OUTPUT -p tcp --sport 2220 -m state --state  RELATED,ESTABLISHED -j ACCEPT
$RULE -A OUTPUT -p tcp --sport 3317 -m state --state  RELATED,ESTABLISHED -j ACCEPT
$RULE -A OUTPUT -p tcp --sport 3314 -m state --state  RELATED,ESTABLISHED -j ACCEPT
# Equipos de confianza MV y mio

$RULE -A OUTPUT -d$MVWIN7/32 -j ACCEPT  # Mi VM  WIN7
$RULE -A OUTPUT -d$MVWIN10/32 -j ACCEPT  # Mi VM  WIN10
$RULE -A OUTPUT -d$SVRARQUERO/32 -j ACCEPT  # SVRARQUERO
#$RULE -A OUTPUT -d $MYHOMEIP/32 -j ACCEPT

# Equipos de confianza de servicios
$RULE -A OUTPUT -d$SVRLDAP/32 -j ACCEPT  # ldap
$RULE -A OUTPUT -d$SVRANTIVIRUS/32 -j ACCEPT  # Antivirus
#for i in  1 2 3 4 5 6  ; do  $RULE -A OUTPUT -d$SVRANTIVIRUS$i/32 -j ACCEPT ; done
$RULE -A OUTPUT -d$NAGIOSHOSTING/32 -j ACCEPT  # Nagios Hosting

# Redes de confianza
# VPN correo
$RULE -A OUTPUT -d192.168.1.0/24 -j ACCEPT
$RULE -A OUTPUT -d192.168.2.0/28 -j ACCEPT
$RULE -A OUTPUT -d192.168.3.0/28 -j ACCEPT
$RULE -A OUTPUT -d192.168.4.0/24 -j ACCEPT
$RULE -A OUTPUT -d192.168.5.0/24 -j ACCEPT
# Servicios de confianza
$RULE -A OUTPUT -d$SVRARQUERO/32 -p tcp --dport 3389  -j ACCEPT
# Servicios Correo
$RULE -A OUTPUT -d193.147.0.0/16  -j ACCEPT
$RULE -A OUTPUT -p tcp --dport 587  -j ACCEPT
$RULE -A OUTPUT -p tcp --dport 993  -j ACCEPT
$RULE -A OUTPUT -p tcp --dport 25  -j ACCEPT
#

# La US
$RULE -A OUTPUT -d150.214.0.0/16 -j ACCEPT

# Explicitamente Baneados
$RULE -A OUTPUT -d91.189.0.0/16 -j DROP
# Logging
$RULE -A OUTPUT -j LOG --log-prefix "Depurando OUTPUT IPTABLES"
$RULE -A OUTPUT -d $PRIVC -j DROP


#ACTIVANDO FAIL2BAN
/etc/init.d/fail2ban restart
IPTABLESRULES=ON
echo $IPTABLESRULES > /etc/default/iptables.status
#exit 0
;; # Fin opcion case

"" | "?" | * )

echo USO:
echo "$0 {?|status|debug|nodebug|start|stop}"
;; # Fin opcion case
esac
# Fin case
#ACTIVANDO FAIL2BAN
#/etc/init.d/fail2ban restart
echo  $IPTABLESRULES
echo " El estado (ON/OFF) de las reglas IPTABLES es: $(cat /etc/default/iptables.status)"
# FIN script
