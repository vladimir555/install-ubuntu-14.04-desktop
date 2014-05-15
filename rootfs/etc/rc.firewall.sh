#Подгружаем модули
/sbin/modprobe ip_conntrack_ftp
/sbin/modprobe ip_tables
/sbin/modprobe ip_conntrack
/sbin/modprobe iptable_filter
/sbin/modprobe iptable_mangle
/sbin/modprobe iptable_nat
/sbin/modprobe ipt_LOG
/sbin/modprobe ipt_limit
/sbin/modprobe ipt_state
echo "0" > /proc/sys/net/ipv4/ip_forward
sysctl -w net.ipv4.tcp_syncookies=1

# Отключить ipv6
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
echo 1 > /proc/sys/net/ipv6/conf/default/disable_ipv6

#
echo 0 > /proc/sys/net/ipv4/ip_forward

II='eth1'
IL='eth'
IW='eth'
IPT='iptables'
I='-A INPUT -i'
O='-A OUTPUT -o'
F='-A FORWARD'
TCP="-p tcp -m tcp"
UDP="-p udp -m udp"
ICMP="-p icmp -m icmp"
S="-m state --state"
SP="--sport"
DP="--dport"
UP="1024:65535"


#сброс правил
$IPT -t mangle  -X
$IPT -t nat     -X
$IPT -t filter  -X
$IPT -t raw     -X

$IPT -t mangle  -F
$IPT -t nat     -F
$IPT -t filter  -F
$IPT -t raw     -F

#запрет пакетов по умолчанию
$IPT -P INPUT   DROP
$IPT -P OUTPUT  DROP
$IPT -P FORWARD DROP


#####трассировка
#$IPT -t raw -A PREROUTING                 -j TRACE
#$IPT -t raw -A OUTPUT                     -j TRACE
#####


#####общие правила
# Блокировка интернета для группы noinet
#iptables -A OUTPUT ! -o lo -m owner --gid-owner noinet -j DROP

# Запрещаем подключение к X серверу через сетевые интерфейсы.
$IPT -A INPUT   $TCP $DP 6000:6063              -j DROP --syn

# Запрещаем любые новые подключения с любых интерфейсов, кроме известных к компьютеру.
$IPT -A INPUT ! -i lo         $S NEW            -j DROP

# Отбрасывать все пакеты, которые не могут быть иденти1фицированы и поэтому не могут иметь определенного статуса.
$IPT -A INPUT   $S INVALID                      -j DROP
$IPT -A FORWARD $S INVALID                      -j DROP

# Существует одна из разновидностей спуфинг-атак, которая называется "Предсказание номера TCP-последовательности".
# Смысл атак такого рода заключается в использовании чужого IP-адреса для нападения на какой либо узел сети.
$IPT -A INPUT -p tcp --tcp-flags SYN,ACK SYN,ACK -m state --state NEW -j REJECT --reject-with tcp-reset

# SYN наводнение.
# Приводит к связыванию системных ресурсов, так что реальных обмен данными становится не возможным.
$IPT -A INPUT   $TCP  $S NEW                    -j DROP ! --syn
$IPT -A OUTPUT  $TCP  $S NEW                    -j DROP ! --syn

# Принимать все пакеты, которые инициированы из уже установленного соединения, и имеющим признак ESTABLISHED.
# Состояние ESTABLISHED говорит о том, что это не первый пакет в соединении.
$IPT -A INPUT   $S ESTABLISHED,RELATED          -j ACCEPT

# UDP наводнение 
# Службы использующие UDP, очень часто становятся мишенью для атак с целью вывода системы из строя
#$IPT -A INPUT   $UDP    -s 0/0                  --destination-port 138 -j DROP
#$IPT -A INPUT   $UDP    -s 0/0                  --destination-port 113 -j REJECT
#$IPT -A INPUT   $UDP    -s 0/0 --source-port 67 --destination-port 68  -j ACCEPT
#$IPT -A INPUT   $UDP                                                   -j RETURN
#$IPT -A OUTPUT  $UDP    -s 0/0                                         -j ACCEPT

# ICMP - перенаправление
# ICMP - сообщение указывает системе изменить содержимое таблиц маршрутизации с тем, что бы направлять
# пакеты по более короткому маршруту. Может быть использовано взломщиком для перенаправления вашего трафика через с
$IPT -A INPUT   -p icmp --fragment                -j DROP
$IPT -A OUTPUT  -p icmp --fragment                -j DROP

# Если интерфейс не lo, то запрещаем входить в список его адресов
$IPT -A INPUT -s 127.0.0.1/8 ! -i lo              -j DROP

# Запрещаем подключение к X серверу через сетевые интерфейсы.
$IPT -A INPUT ! -i lo $TCP  $DP 6000:6063         -j DROP --syn

# Прописываем порты, которые открыты в системе, но которые не должны быть открыты на сетевых интерфейсах:
$IPT -A INPUT ! -i lo $TCP  -m multiport --dports 630,640,783,3310,10000 -j DROP
$IPT -A INPUT ! -i lo $UDP  -m multiport --dports 630,640,783,3310,10000 -j DROP

# Разрешаем прохождение любого трафика по интерфейсу обратной петли.
$IPT $I lo                                        -j ACCEPT
$IPT $O lo                                        -j ACCEPT
#####


#####internet
#исходящий ping в интернет
$IPT $I $II $ICMP   --icmp-type echo-reply      -j ACCEPT
$IPT $O $II $ICMP   --icmp-type echo-request    -j ACCEPT
$IPT $I $II $ICMP   --icmp-type source-quench   -j ACCEPT
$IPT $O $II $ICMP   --icmp-type source-quench   -j ACCEPT
$IPT $I $II $ICMP   --icmp-type destination-unreachable -j ACCEPT #
$IPT $O $II $ICMP   --icmp-type destination-unreachable -j ACCEPT
$IPT $I $II $ICMP   --icmp-type time-exceeded   -j ACCEPT
$IPT $O $II $ICMP   --icmp-type time-exceeded   -j ACCEPT         #

# Разрешаем AUTH-запросы на удаленные сервера, на свой же компьютер - запрещаем.
#$IPT $I $II $TCP    $DP $UP     $SP 113         -j ACCEPT ! --syn
#$IPT $I $II $TCP    $DP 113                     -j DROP
#$IPT $O $II $TCP    $SP $UP     $DP 113         -j ACCEPT

# DNS
#$IPT $I $II $UDP    $DP 53      $SP $UP         -j ACCEPT
#$IPT $O $II $UDP    $SP $UP     $DP 53          -j ACCEPT

# DHCP клиент
#$IPT $I $II $UDP    $SP 67      $DP 68          -j ACCEPT
#$IPT $O $II $UDP    $SP 68      $DP 67          -j ACCEPT

# HTTP
$IPT $I $II $TCP    $DP 80      $SP $UP         -j ACCEPT ! --syn
$IPT $O $II $TCP    $SP $UP     $DP 80          -j ACCEPT

# HTTPS
#$IPT $I $II $TCP    $DP 443     $SP $UP         -j ACCEPT ! --syn
#$IPT $O $II $TCP    $SP $UP     $DP 443         -j ACCEPT

# Transmission входящий для раздачи
#$IPT $I $II $TCP    $DP $UP     $SP 51413       -j ACCEPT 
#$IPT $O $II $TCP    $SP 51413   $DP $UP         -j ACCEPT
#$IPT $I $II $UDP    $DP $UP     $SP 51413       -j ACCEPT 
#$IPT $O $II $UDP    $SP 51413   $DP $UP         -j ACCEPT

# Transmission исходящий случайный
#$IPT $I $II $TCP    $DP $UP     $SP 65534:65535 -j ACCEPT ! --syn
#$IPT $O $II $TCP    $SP 65534:65535 $DP $UP     -j ACCEPT

# Mail client
#$IPT $I $II $TCP    $DP 25      $SP $UP         -j ACCEPT ! --syn
#$IPT $O $II $TCP    $SP $UP     $DP 25          -j ACCEPT
#$IPT $I $II $TCP    $DP 110     $SP $UP         -j ACCEPT ! --syn
#$IPT $O $II $TCP    $SP $UP     $DP 110         -j ACCEPT

# Transmission Remote GUI client
$IPT $I $II $TCP    $DP 9091    $SP $UP         -j ACCEPT ! --syn
$IPT $O $II $TCP    $SP $UP     $DP 9091        -j ACCEPT

# NFS client
$IPT $I $II $TCP    $DP 2049                    -j ACCEPT ! --syn
$IPT $O $II $TCP                $DP 2049        -j ACCEPT

# GIT client
#$IPT $I $II $TCP    $DP 9418                    -j ACCEPT ! --syn
#$IPT $O $II $TCP                $DP 9418        -j ACCEPT

# Radio client
#$IPT $I $II $UDP    $DP 8000    $SP $UP         -j ACCEPT
#$IPT $O $II $UDP    $SP $UP     $DP 8000        -j ACCEPT
#$IPT $I $II $TCP    $DP 8000    $SP $UP         -j ACCEPT ! --syn
#$IPT $O $II $TCP    $SP $UP     $DP 8000        -j ACCEPT

#NTP client
$IPT $I $II $UDP    $DP 123     $SP 123         -j ACCEPT
$IPT $O $II $UDP    $SP 123     $DP 123         -j ACCEPT

#TOR
#$IPT $I $II $TCP    $DP 9001    $SP $UP         -j ACCEPT ! --syn
#$IPT $O $II $TCP    $SP $UP     $DP 9001        -j ACCEPT

#
#$IPT $I $II $TCP    $DP 8080    $SP $UP         -j ACCEPT ! --syn
#$IPT $O $II $TCP    $SP $UP     $DP 8080        -j ACCEPT

#$IPT $I $II $UDP    $DP 2049    $SP $UP         -j ACCEPT
#$IPT $O $II $UDP    $SP $UP     $DP 2049        -j ACCEPT

#$IPT $I $II $TCP    $DP 111     $SP 111         -j ACCEPT ! --syn
#$IPT $O $II $TCP    $SP 111     $DP 111         -j ACCEPT

#$IPT $I $II $UDP    $DP 111     $SP $UP         -j ACCEPT
#$IPT $O $II $UDP    $SP $UP     $DP 111         -j ACCEPT

# proxy client
$IPT $I $II $TCP    $DP 3128    $SP $UP         -j ACCEPT ! --syn
$IPT $O $II $TCP    $SP $UP     $DP 3128        -j ACCEPT

# quake3 client
$IPT $I $II $UDP    $DP 27960   $SP $UP         -j ACCEPT
$IPT $O $II $UDP    $SP $UP     $DP 27960       -j ACCEPT

#$IPT $I $II $TCP    $DP 3129    $SP $UP         -j ACCEPT ! --syn
#$IPT $O $II $TCP    $SP $UP     $DP 3129        -j ACCEPT

# bitcoin wallet client
#$IPT $I $II $TCP    $DP 8331    $SP $UP         -j ACCEPT ! --syn
#$IPT $O $II $TCP    $SP $UP     $DP 8331        -j ACCEPT

# bitcoin stratum client
#$IPT $I $II $TCP    $DP 8332    $SP $UP         -j ACCEPT ! --syn
#$IPT $O $II $TCP    $SP $UP     $DP 8332        -j ACCEPT

#$IPT $I $II $TCP    $DP 3333    $SP $UP         -j ACCEPT ! --syn
#$IPT $O $II $TCP    $SP $UP     $DP 3333        -j ACCEPT
#$IPT $I $II $UDP    $DP 3333    $SP $UP         -j ACCEPT
#$IPT $O $II $UDP    $SP $UP     $DP 3333        -j ACCEPT
#####


###ppp0 direct
# DNS
#$IPT $I ppp0 $UDP    $DP 53      $SP $UP        -j ACCEPT
#$IPT $O ppp0 $UDP    $SP $UP     $DP 53         -j ACCEPT

# HTTP
#$IPT $I ppp0 $TCP    $DP 80     $SP $UP         -j ACCEPT ! --syn
#$IPT $O ppp0 $TCP    $SP $UP    $DP 80          -j ACCEPT

# HTTPS
#$IPT $I ppp0 $TCP    $DP 443     $SP $UP        -j ACCEPT ! --syn
#$IPT $O ppp0 $TCP    $SP $UP     $DP 443        -j ACCEPT


#$IPT $I ppp0 $ICMP   --icmp-type echo-reply     -j ACCEPT
#$IPT $O ppp0 $ICMP   --icmp-type echo-request   -j ACCEPT
#$IPT $I ppp0 $ICMP   --icmp-type source-quench  -j ACCEPT
#$IPT $O ppp0 $ICMP   --icmp-type source-quench  -j ACCEPT
#$IPT $I ppp0 $ICMP   --icmp-type destination-unreachable -j ACCEPT #
#$IPT $O ppp0 $ICMP   --icmp-type destination-unreachable -j ACCEPT
#$IPT $I ppp0 $ICMP   --icmp-type time-exceeded  -j ACCEPT
#$IPT $O ppp0 $ICMP   --icmp-type time-exceeded  -j ACCEPT         #

#$IPT $I ppp0 $TCP    $DP 8332    $SP $UP        -j ACCEPT ! --syn
#$IPT $O ppp0 $TCP    $SP $UP     $DP 9332       -j ACCEPT
##$IPT $I ppp0 $UDP    $DP 8332    $SP $UP        -j ACCEPT
##$IPT $O ppp0 $UDP    $SP $UP     $DP 9332       -j ACCEPT

#$IPT $I ppp0 $TCP    $DP 3333    $SP $UP        -j ACCEPT ! --syn
#$IPT $O ppp0 $TCP    $SP $UP     $DP 3333       -j ACCEPT
#$IPT $I ppp0 $UDP    $DP 3333    $SP $UP        -j ACCEPT
#$IPT $O ppp0 $UDP    $SP $UP     $DP 3333       -j ACCEPT

###


#$IPT $I $II  -j LOG
#$IPT $O $II  -j LOG

echo 0 > /proc/sys/net/ipv4/ip_forward
echo 0 > /proc/sys/net/ipv4/ip_dynaddr

iptables-save > /etc/iptables.rules
echo OK
