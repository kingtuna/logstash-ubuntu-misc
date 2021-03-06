####################################################
####						####
#### honeypot Install Script               	####
#### tuna@people.ops-trust.net			####
####						####
####################################################

apt-get update
apt-get -y install gcc build-essential bind9 dnsutils cmake make gcc g++ flex bison
apt-get -y install libpcap-dev libgeoip-dev libssl-dev python-dev zlib1g-dev libmagic-dev 
apt-get -y install hping3 vim ntp xinetd curl default-jre git rubygems swig2.0 wondershaper
mkdir build
cd build

###### setup hostname ######

OLDHOSTNAME=`cat /etc/hostname`
echo honey`/sbin/ifconfig eth0 | grep 'inet addr:' | cut -d: -f2 | awk '{ print $1}'`> /etc/hostname
NEWHOSTNAME=`cat /etc/hostname`
hostname $NEWHOSTNAME

cat /etc/hosts | sed  s/$OLDHOSTNAME/$NEWHOSTNAME/g > /tmp/hosts
mv -f /tmp/hosts /etc/hosts
echo -e "127.0.0.1\t$NEWHOSTNAME" >> /etc/hosts

###### Install NTP ######
mkdir build && cd build
wget http://www.eecis.udel.edu/~ntp/ntp_spool/ntp4/ntp-4.2/ntp-4.2.6p4.tar.gz
tar zxvf ntp-4.2.6p4.tar.gz
cd ntp-4.2.6p4/
./configure --enable-clockctl
make
make install
cd ..
echo "driftfile /var/lib/ntp/ntp.drift" > /etc/ntp.conf

echo "e30003fa000100000001000000000000000000000000000000000000000000000000000000000000d6a42558d961df90" > /root/ntp.bin
/usr/local/bin/ntpd -u ntp:ntp -p /var/run/ntpd.pid -g

echo '#!/bin/bash
killall ntpd
/usr/local/bin/ntpd -u ntp:ntp -p /var/run/ntpd.pid -g
killall sshpot
service sshpot restart
#wondershaper eth0 10000 10000
/usr/sbin/hping3 --rand-source -c 600 --udp -p 123 --fast -n 127.0.0.1 -d 48 -E /root/ntp.bin' > /root/killntp.sh 
chmod +x /root/killntp.sh 

hping3 --rand-source -c 600 --udp -p 123 --fast -n 127.0.0.1 -d 48 -E /root/ntp.bin


###### Install CHARGEN ######

echo 'service chargen
{
	disable = yes
	type = INTERNAL
	id = chargen-stream
	socket_type = stream
	protocol = tcp
	user = root
	wait = no
}                                                                               

# This is the udp version.
service chargen
{
	disable = no
	type = INTERNAL
	id = chargen-dgram
	socket_type = dgram
	protocol = udp
	user = root
	wait = yes
}' > /etc/xinetd.d/chargen 

service xinetd restart

###### Install Recursive DNS ######

echo "Installing DNS"

apt-get install bind9 dnsutils -y


echo 'include "/etc/bind/named.conf.options";
include "/etc/bind/named.conf.local";
include "/etc/bind/rndc.key";
# make it comment
# include "/etc/bind/named.conf.default-zones";
# add
include "/etc/bind/named.conf.internal-zones";
include "/etc/bind/named.conf.external-zones";' > /etc/bind/named.conf

echo '# define for internal section
view "internal" {
        match-clients {
                localhost;
                10.0.0.0/24;
        };
        zone "." {
                type hint;
                file "db.root";
        };
# set zone for internal
        zone "server.world" {
                type master;
                file "server.world.lan";
                allow-update { none; };
        };
# set zone for internal *note
        zone "0.0.10.in-addr.arpa" {
                type master;
                file "0.0.10.db";
                allow-update { none; };
        };
        zone "localhost" {
                type master;
                file "db.local";
        };
        zone "127.in-addr.arpa" {
                type master;
                file "db.127";
        };
        zone "0.in-addr.arpa" {
                type master;
                file "db.0";
        };
        zone "255.in-addr.arpa" {
                type master;
                file "db.255";
        };
};' > /etc/bind/named.conf.internal-zones

echo '# define for external section
view "external" {
        match-clients { any; };
# allo any query
        allow-query { any; };
# prohibit recursion
        recursion yes;
# set zone for external
        zone "server.world" {
                type master;
                file "server.world.wan";
                allow-update { none; };
        };
# set zone for external *note
        zone "80.0.16.172.in-addr.arpa" {
                type master;
                file "80.0.16.172.db";
                allow-update { none; };
        };
};' > /etc/bind/named.conf.external-zones

rndc-confgen | head -n5 > /etc/bind/rndc.key

echo 'options {
# change
directory "/etc/bind";
# query range you allow
version "eatdix";
allow-query {any;};
# the range to transfer zone files
allow-transfer {any;};
# recursion range you allow
allow-recursion {any;};
dnssec-validation auto;
auth-nxdomain no;
};' > /etc/bind/named.conf.options

service bind9 restart

###### Install Bro ######
#
# apt-get install cmake make gcc g++ flex bison libpcap-dev 
# libgeoip-dev libssl-dev python-dev zlib1g-dev libmagic-dev swig2.0 -y

echo "Installing Bro"

wget http://geolite.maxmind.com/download/geoip/database/GeoLiteCity.dat.gz
wget http://geolite.maxmind.com/download/geoip/database/GeoLiteCityv6-beta/GeoLiteCityv6.dat.gz
gunzip GeoLiteCity.dat.gz
gunzip GeoLiteCityv6.dat.gz
mv GeoLiteCity.dat  /usr/share/GeoIP/GeoLiteCity.dat
mv GeoLiteCityv6.dat /usr/share/GeoIP/GeoLiteCityv6.dat
ln -s /usr/share/GeoIP/GeoLiteCity.dat /usr/share/GeoIP/GeoIPCity.dat
ln -s /usr/share/GeoIP/GeoLiteCityv6.dat /usr/share/GeoIP/GeoIPCityv6.dat
wget https://www.bro.org/downloads/release/bro-2.3.2.tar.gz
tar -xvzf bro-*.tar.gz
cd bro-2.*
./configure --prefix=/nsm/bro
make
make install

# this is an NTP script for bro to understand the protocol
curl https://raw.githubusercontent.com/kingtuna/logstash-ubuntu-misc/master/ntp.bro > /nsm/bro/share/bro/site/ntp.bro

echo '#add NTP suport
@load ntp' >> /nsm/bro/share/bro/site/local.bro

export PATH=/nsm/bro/bin:$PATH
/nsm/bro/bin/broctl install
/nsm/bro/bin/broctl start

cd /root/build/

###### logstash ######

gem install fpm

git clone https://github.com/Yuav/logstash-packaging.git --depth=1
cd logstash-packaging
./package.sh

cd ..
dpkg -i logstash_1.*.deb
/etc/init.d/logstash start

## clear out previous logstash configs
rm -f /etc/logstash/*

#http://www.appliednsm.com/parsing-bro-logs-with-logstash/
printf 'IyBDcmVhdGVkIGJ5IFRlcnJlbmNlIEdhcmVhdSAidHVuYSIgZm9yIGhvbmV5cG90IHByb2plY3QK
IyB0dW5hQHBlb3BsZS5vcHMtdHJ1c3QubmV0CgojIFVzZWQgSmFzb24gU21pdGgncyBzZXR1cCBh
cyBhIGJhc2UgCiMgR3JlYXQgQmxvZyBwb3N0IGh0dHA6Ly93d3cuYXBwbGllZG5zbS5jb20vcGFy
c2luZy1icm8tbG9ncy13aXRoLWxvZ3N0YXNoLwojIGh0dHA6Ly9ibG9nLmx1c2lzLm9yZy9ibG9n
LzIwMTIvMDEvMzEvbG9hZC1iYWxhbmNpbmctbG9nc3Rhc2gtd2l0aC1hbXFwLwojIHR1bmFAcGVv
cGxlLm9wcy10cnVzdC5uZXQKIyBodHRwczovL2hvbWUucmVnaXQub3JnLzIwMTQvMDEvYS1iaXQt
b2YtbG9nc3Rhc2gtY29va2luZy8gZ2VvaXAKIyBodHRwczovL2hvbWUucmVnaXQub3JnL3RhZy9s
b2dzdGFzaC8KI0xvZ3MgYmVpbmcgcGFyc2VkOgojY29ubi5sb2cKI2Rucy5sb2cKI250cC5sb2cK
CmlucHV0IHsKCiNQcm9kdWN0aW9uIExvZ3MjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIwog
IGZpbGUgewogICAgdHlwZSA9PiAiQlJPX2Nvbm5sb2ciCiAgICBwYXRoID0+ICIvbnNtL2Jyby9s
b2dzL2N1cnJlbnQvY29ubi5sb2ciCiAgfQogIGZpbGUgewogICAgdHlwZSA9PiAiQlJPX2Ruc2xv
ZyIKICAgIHBhdGggPT4gIi9uc20vYnJvL2xvZ3MvY3VycmVudC9kbnMubG9nIgogIH0KCiAgZmls
ZSB7CiAgICB0eXBlID0+ICJCUk9fbnRwbG9nIgogICAgcGF0aCA9PiAiL25zbS9icm8vbG9ncy9j
dXJyZW50L250cC5sb2ciCiAgfQoKICBmaWxlIHsKICAgIHR5cGUgPT4gIlNTSFBPVF9zc2hsb2ci
CiAgICBwYXRoID0+ICIvdmFyL2xvZy9zc2hwb3RfYXV0aC5sb2ciCiAgfQoKIyMjIyMjIyMjIyMj
IyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjCn0KCmZpbHRlciB7CiAgaWYg
W21lc3NhZ2VdID1+IC9eIy8gewogICAgZHJvcCB7ICB9CiAgfSBlbHNlIHsKICAKIyBTU0hQT1Rf
c3NobG9nICMjIyMjIyMjIyMjIyMjIyMjIyMjIyMKICBpZiBbdHlwZV0gPT0gIlNTSFBPVF9zc2hs
b2ciIHsKICAgICAgZ3JvayB7IAogICAgICAgIG1hdGNoID0+IFsgIm1lc3NhZ2UiLCAiKD88dHM+
KC4qPykpXHQoPzxpZC5vcmlnX2g+KC4qPykpXHQoPzx1c2VyPiguKj8pKVx0KD88cGFzcz4oLio/
KSlcdCIgXQogICAgICB9CiAgfQoKIyBCUk9fbnRwbG9nICMjIyMjIyMjIyMjIyMjIyMjIyMjIyMK
ICBpZiBbdHlwZV0gPT0gIkJST19udHBsb2ciIHsKICAgICAgZ3JvayB7IAogICAgICAgIG1hdGNo
ID0+IFsgIm1lc3NhZ2UiLCAiKD88dHM+KC4qPykpXHQoPzx1aWQ+KC4qPykpXHQoPzxpZC5vcmln
X2g+KC4qPykpXHQoPzxpZC5yZXNwX2g+KC4qPykpXHQoPzxyZWZpZD4oLio/KSlcdCg/PGNvZGU+
KC4qPykpXHQoPzxzdHJhdHVtPiguKj8pKVx0KD88cG9sbD4oLio/KSlcdCg/PHByZWNlaXNzaW9u
PiguKj8pKVx0KD88cmVmdGltZT4oLio/KSlcdCg/PGV4Y2Vzcz4oLio/KSkiIF0KICAgICAgfQog
ICAgICBpZiBbY29kZV0gPX4gL140LyB7CiAgICAgICAgZHJvcCB7ICB9CiAgICAgICB9CiAgfQoK
IyBCUk9fZG5zbG9nICMjIyMjIyMjIyMjIyMjIyMjIyMjIyMKICBpZiBbdHlwZV0gPT0gIkJST19k
bnNsb2ciIHsKICAgIGdyb2sgewptYXRjaCA9PiBbICJtZXNzYWdlIiwgIig/PHRzPiguKj8pKVx0
KD88dWlkPiguKj8pKVx0KD88aWQub3JpZ19oPiguKj8pKVx0KD88aWQub3JpZ19wPiguKj8pKVx0
KD88aWQucmVzcF9oPiguKj8pKVx0KD88aWQucmVzcF9wPiguKj8pKVx0KD88cHJvdG8+KC4qPykp
XHQoPzx0cmFuc19pZD4oLio/KSlcdCg/PHF1ZXJ5PiguKj8pKVx0KD88cWNsYXNzPiguKj8pKVx0
KD88cWNsYXNzX25hbWU+KC4qPykpXHQoPzxxdHlwZT4oLio/KSlcdCg/PHF0eXBlX25hbWU+KC4q
PykpXHQoPzxyY29kZT4oLio/KSlcdCg/PHJjb2RlX25hbWU+KC4qPykpXHQoPzxBQT4oLio/KSlc
dCg/PFRDPiguKj8pKVx0KD88UkQ+KC4qPykpXHQoPzxSQT4oLio/KSlcdCg/PFo+KC4qPykpXHQo
PzxhbnN3ZXJzPiguKj8pKVx0KD88VFRMcz4oLio/KSlcdCg/PHJlamVjdGVkPiguKikpIiBdCiAg
ICB9CiAgfQogIAojIEJST19jb25ubG9nICMjIyMjIyMjIyMjIyMjIyMjIyMjIyMKICBpZiBbdHlw
ZV0gPT0gIkJST19jb25ubG9nIiB7CiAgICBncm9rIHsKbWF0Y2ggPT4gWyAibWVzc2FnZSIsICIo
Pzx0cz4oLio/KSlcdCg/PHVpZD4oLio/KSlcdCg/PGlkLm9yaWdfaD4oLio/KSlcdCg/PGlkLm9y
aWdfcD4oLio/KSlcdCg/PGlkLnJlc3BfaD4oLio/KSlcdCg/PGlkLnJlc3BfcD4oLio/KSlcdCg/
PHByb3RvPiguKj8pKVx0KD88c2VydmljZT4oLio/KSlcdCg/PGR1cmF0aW9uPiguKj8pKVx0KD88
b3JpZ19ieXRlcz4oLio/KSlcdCg/PHJlc3BfYnl0ZXM+KC4qPykpXHQoPzxjb25uX3N0YXRlPigu
Kj8pKVx0KD88bG9jYWxfb3JpZz4oLio/KSlcdCg/PG1pc3NlZF9ieXRlcz4oLio/KSlcdCg/PGhp
c3Rvcnk+KC4qPykpXHQoPzxvcmlnX3BrdHM+KC4qPykpXHQoPzxvcmlnX2lwX2J5dGVzPiguKj8p
KVx0KD88cmVzcF9wa3RzPiguKj8pKVx0KD88cmVzcF9pcF9ieXRlcz4oLio/KSlcdCg/PHR1bm5l
bF9wYXJlbnRzPiguKj8pKSIgXQogICAgfQogIH0KIH0KICBpZiBbaWQub3JpZ19oXSAgewogICAg
Z2VvaXAgewogICAgICBzb3VyY2UgPT4gImlkLm9yaWdfaCIKICAgICAgdGFyZ2V0ID0+ICJnZW9p
cCIKICAgICAgYWRkX2ZpZWxkID0+IFsgIltnZW9pcF1bY29vcmRpbmF0ZXNdIiwgIiV7W2dlb2lw
XVtsb25naXR1ZGVdfSIgXQogICAgICBhZGRfZmllbGQgPT4gWyAiW2dlb2lwXVtjb29yZGluYXRl
c10iLCAiJXtbZ2VvaXBdW2xhdGl0dWRlXX0iICBdCiAgICB9CiAgICBtdXRhdGUgewogICAgICBj
b252ZXJ0ID0+IFsgIltnZW9pcF1bY29vcmRpbmF0ZXNdIiwgImZsb2F0IiBdCiAgICB9IAogICAg
bXV0YXRlIHsKICAgICAgdXBwZXJjYXNlID0+IFsgImdlb2lwLmNvdW50cnlfY29kZTIiIF0KICAg
IH0KICB9Cn0K' | base64 -d  > /etc/logstash/bro.conf

printf 'output {
  rabbitmq {
     user => "amp"
     exchange_type => "direct"
     password => "PASSWORD"
     exchange => "EXHANGE"
     vhost => "/amp"
     durable => true
     ssl => true
     port => 5671
     persistent => true
     host => "HOSTNAME"
  }
}' >> /etc/logstash/bro.conf

curl https://raw.githubusercontent.com/kingtuna/logstash-ubuntu-misc/master/upstart.logstash.conf > /etc/init/logstash.conf

cd /root/build/

###### Setup SSH Honeypot ######

apt-get install libssh-dev -y
git clone https://github.com/kingtuna/sshpot.git
cd sshpot
make
mv /etc/ssh/sshd_config /etc/ssh/sshd_config.old
cat /etc/ssh/sshd_config.old | sed 's/Port 22$/Port 2222/g' > /etc/ssh/sshd_config
cp upstart.sshpot.conf /etc/init/sshpot.conf
cp sshpot /usr/local/bin/
touch cat /var/log/sshpot_auth.log
service ssh restart
service sshpot start
cd /root/build/

##
# Added in killntp.sh script
# killall sshpot
# service sshpot restart 
##

###### Clean Ups and Cron ######

echo '
/usr/local/bin/ntpd -u ntp:ntp -p /var/run/ntpd.pid -g
export PATH=/nsm/bro/bin:$PATH
/nsm/bro/bin/broctl install
/nsm/bro/bin/broctl start
sleep 2
hping3 --rand-source -c 600 --udp -p 123 --fast -n 127.0.0.1 -d 48 -E /root/ntp.bin
service logstash restart

exit 0
' > /etc/rc.local 



##### crontab to install
##start logstash and bro

printf '*/30 * * * * service bind9 restart
*/30 * * * * /etc/init.d/xinetd restart
* */2 * * * /root/killntp.sh
0-59/5 * * * * /nsm/bro/bin/broctl cron
' > crontab.txt
crontab crontab.txt

echo "net.ipv4.tcp_keepalive_intvl=570" >> /etc/sysctl.conf

reboot

