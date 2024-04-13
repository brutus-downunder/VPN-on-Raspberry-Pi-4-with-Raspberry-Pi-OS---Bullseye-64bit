## **VPN on Raspberry Pi 4 with Raspberry Pi OS - Bullseye 64bit**
**Features**

\- Openvpn (with killswitch), Transmission and security  
\- Transmission Remote Gui on Windows for starting .torrents  
\- A shared folder for downloaded torrents accessable from Windows File Explorer

***Last updated: 21th February 2023.***

### ***Initial Requirements***
1. Download the latest Raspberry Pi OS 64bit lite image
2. Install image to a boot device using Raspberry Pi Imager with SSH enabled
3. The boot device is large enough to save downloaded torrents to i.e USB 3 attached SSD
4. A NordVPN account and have download the required .ovpn
5. Copied username and password from the NordVPN service credentials page in your Nord Account dashboard
6. Downloaded putty, pageant, puttygen and installed winscp for Windows
7. Created a public key using puttygen
8. Public key is in a file called *authorized_keys*
9. Downloaded a Transmission gui such as Transmission Remote GUI for Windows
10. If you are going to create/edit any files on Windows and then copy them to your raspberry pi using WinSCP. Then please use a proper Editor for Windows like Notepad++ and convert any files to Unix LF EOL. In Notepad++ go to *Edit > EOL Conversion > Unix (LF)* and then save the file. Now use WinSCP to copy the file to your raspberry pi. The only exception to this is the */etc/openvpn/nordvpn.auth* file which should be Windows CRLF EOL format.
11. Know that you need to change IP addresses, gateways, passwords etc to suit your system
12. Understand that acting on, copying, downloading, installing anything from the Internet has a level of risk. If you can't or don't understand the risks, then STOP HERE AND DO NOT CONTINUE.
13. It is your sole responsibilty to seek Professional Legal Advice regarding any Laws in your country that may be applicable to you before acting on ANYTHING that is contained herein.

### ***Links***
Raspberry Pi OS 64bit lite image - https://downloads.raspberrypi.org/raspios_lite_arm64/images/  
Raspberry Pi Imager - https://downloads.raspberrypi.org/imager/  
How to use Raspberry Pi Imager - https://learn.adafruit.com/raspberry-pi-zero-creation/using-rpi-imager  
NordVPN - https://nordvpn.com/  
Putty etc - https://www.chiark.greenend.org.uk/~sgtatham/putty/latest.html  
WinSCP - https://winscp.net/eng/download.php  
How to use puttygen - https://www.ssh.com/academy/ssh/putty/windows/puttygen  
Transmission Remote GUI - https://github.com/transmission-remote-gui/transgui  
Notepad++ - https://notepad-plus-plus.org/

## **Let's start**
From Windows find the Raspberry Pi on your network and SSH in using putty with *IP Address, Port 22* and user *pi*  
Open a Command Prompt in Windows and type *ping raspberrypi*  
ping will return the *IP Address* of your Raspberry Pi  
Note: if you did not enter *raspberrypi* as the Hostname during image install, ping *\<Your Hostname\>* instead

### ***First Update and Upgrade***

Change to root
```
sudo su
```
Check for and install updates
```
apt update && apt upgrade -y
```
### ***Start Configuring Services***

**Set IP address**

Open file */etc/dhcpcd.conf* in nano and add the lines at the bottom
```
nano /etc/dhcpcd.conf
```
```
interface eth0
static ip_address=192.168.0.206/24
static routers=192.168.0.200
static domain_name_servers=192.168.0.200 8.8.8.8
```
Save the file by *Ctrl X* and exit nano  
now reboot and SSH using the new IP address and user *pi*
```
reboot
```
***Configure SSH***

Change to root
```
sudo su
```
if not present create the folder
```
mkdir /etc/ssh/sshd_config.d/
```
Now make a new file */etc/ssh/sshd_config.d/01-update-sshd_config.conf* by starting nano and adding 1 line
```
nano /etc/ssh/sshd_config.d/01-update-sshd_config.conf
```
```
Port 2122
```
Save the file by *Ctrl X* and exit nano  
or use this easy method to do the above
```
echo -e "Port 2122" >> /etc/ssh/sshd_config.d/01-update-sshd_config.conf
```
***Set up SSH Authentication for Public Key***

Create and set permissions for user *pi* Public Key folder
```
mkdir /home/pi/.ssh && chmod 700 /home/pi/.ssh
```
Copy *authorized_keys* file using WINSCP to */home/pi/.ssh*

Set permissions
```
chmod 0600 /home/pi/.ssh/authorized_keys
```
Create, set permissions and copy the Public Key folder to */root/.ssh*
```
mkdir /root/.ssh && chmod 700 /root/.ssh && cp -r /home/pi/.ssh /root
```
Set permissions
```
chmod 0600 /root/.ssh/authorized_keys
```
Change ownership
```
chown pi:pi /home/pi/.ssh && chown pi:pi /home/pi/.ssh/authorized_keys
```
Now Reboot to test SSH
```
reboot
```
***Test SSH access***

Load Pageant with your Private key and SSH in as user *pi* with *192.168.0.206:2122*  
Only do the following if successful with Publickey authentication.

Now increase SSH Authentication security.  
Change to user *root* and start nano adding 3 more lines
```
sudo su
```
```
nano /etc/ssh/sshd_config.d/01-update-sshd_config.conf
```
```
PermitRootLogin yes
PubkeyAuthentication yes
PasswordAuthentication no
```
Save the file by *Ctrl X* and exit nano  
or use this easy method to do the above
```
echo -e "PermitRootLogin yes\nPubkeyAuthentication yes\nPasswordAuthentication no" >> /etc/ssh/sshd_config.d/01-update-sshd_config.conf
```
Now Reboot
```
reboot
```
Make sure Pageant is still loaded with your Private key  
SSH in as *pi* and then again as *root* with *192.168.0.206:2122*, both should be successful  
Now close down Pageant and try to SSH in as *pi* and then again as *root*, both should fail  
This proves that access is only granted using SSH with your Private key
We have finished configuring SSH and with the user *pi*

Make sure Pageant is still loaded with your Private key  
SSH in as *root* with *192.168.0.206:2122*

### ***Disabling the unnecessary***

***Disable Journal***

If */etc/systemd/journald.conf.d/* is not present create the folder
```
mkdir /etc/systemd/journald.conf.d/
```
Now make a new file */etc/systemd/journald.conf.d/01-disable-journal.conf* by starting nano and adding 4 lines
```
nano /etc/systemd/journald.conf.d/01-disable-journal.conf
```
```
[Journal]
Storage=none
SystemMaxUse=1M
ReadKMsg=no
```
Save the file by *Ctrl X* and exit nano  
or use this easier method to do the above
```
echo -e "[Journal]\nStorage=none\nSystemMaxUse=1M\nReadKMsg=no" >> /etc/systemd/journald.conf.d/01-disable-journal.conf
```
Restart systemd-journald
```
systemctl restart systemd-journald.service
```
***Disable IPv6 Interface in sysctl.conf and improve Transmission throughput***

Open file */etc/sysctl.conf* in nano and add the lines at the bottom
```
nano /etc/sysctl.conf
```
```
# Disable IPv6
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
net.ipv6.conf.eth0.disable_ipv6 = 1

# Adjust for Transmission throughput
net.ipv4.ip_local_port_range = 16384 65535
```
Save the file by *Ctrl X* and exit nano  
Restart sysctl service
```
sysctl -p /etc/sysctl.conf
```
## ***Install required packages for managing and testing the firewall (with automatic killswitch)***

Note: The ferm install package script will ask if ferm should be started on every boot. Select NO so NOT to enable ferm on boot
```
apt update && apt install ferm iftop screen -y
```
Change to old iptables that are compatible with ferm
```
update-alternatives --config iptables
```
Type in a *1* and press *Enter*

### ***Start configuring iptables firewall for VPN***

Delete exsisting and make a new file */etc/ferm/ferm.conf* by starting nano and add the following lines
```
rm /etc/ferm/ferm.conf && nano /etc/ferm/ferm.conf
```
```
# -*- shell-script -*-
#
#  Configuration file for ferm(1).
#
#  V: 1.0
#
#  ferm manual: https://manpages.debian.org/bullseye/ferm/ferm.1.en.html
#

# Make sure that these modules exist and are loaded.
@hook pre "/sbin/modprobe nf_conntrack_ftp";
@hook pre "/sbin/modprobe nfnetlink_log";

# Network interfaces.
@def $DEV_LAN = eth0;
@def $DEV_LOOPBACK = lo;
@def $DEV_VPN = tun0;

# Network definition for the loopback device. This is needed to allow
# DNS resolution on Ubuntu Linux where the local resolver is bound
# to 127.0.1.1 - as opposed to the default 127.0.0.1.
@def $NET_LOOPBACK = 127.0.0.1/8;

# Common application ports.
@def $PORT_DNS = 53;
@def $PORT_NTP = 123;
@def $PORT_SSH = 2122;
# Ports for Web Browsers.
@def $PORT_WEB = ( 80 443 );
# Ports for Windows Samba SMB.
@def $PORT_SMBT = ( 139 445 );
@def $PORT_SMBU = ( 137 138 );
# Port for Windows Transmission Web GUI.
@def $PORT_TWEB = 9091;
# Ports for Transmission Trackers.
@def $PORT_TRACKERS = ( 1337 6888 6969 );
# Ports Transmission is allowed to use.
@def $PORT_TRANSMISSION = 16384:65535;


# The ports the VPN allows OpenVPN to connect to
# For NordVPN TCP connections use port 443
# For NordVPN UDP connections use port 1194
# Change ports required for other VPN's but
# only to those that are supported
@def $PORT_OPENVPN = ( 443 1194 );

# Public DNS servers and those that are only reachable via VPN.
# DNS servers are specified in the outbound DNS rules to prevent DNS leaks
# (https://www.dnsleaktest.com/). The public DNS servers configured on your
# system should be the vpn ones, but you should verify this.
#
@def $IP_DNS_IPR_PUBLIC = ( 103.86.96.100/32 103.86.99.100/32 );

# Add your ISP name server to this object if you want to restrict
# which DNS servers can be queried.
@def $IP_DNS_PUBLIC = 0.0.0.0/0;

# DNS servers available within the VPN.
# For NordVPN DNS is 103.86.96.100/32 or 103.86.99.100
@def $IP_DNS_VPN = ( 103.86.96.100/32 103.86.99.100/32 );

# Make sure to use the proper VPN interface (e.g. tun0 in this case).
@def $VPN_ACTIVE = `ip link show tun0 >/dev/null 2>/dev/null && echo 1 || echo`;

# VPN interface conditional. If true the following rules are loaded.
@if $VPN_ACTIVE {
    domain ip {
        table filter {
            chain INPUT {
                interface $DEV_VPN {
                    proto (tcp udp) dport $PORT_TRANSMISSION ACCEPT;
                    proto udp dport $PORT_TRACKERS ACCEPT;
                }
            }

            chain OUTPUT {
# Default allowed outbound services on the VPN interface.
# If you need more simply add your rules here.
                outerface $DEV_VPN {
                    proto (tcp udp) daddr ( $IP_DNS_VPN $IP_DNS_IPR_PUBLIC ) dport $PORT_DNS ACCEPT;
                    proto (tcp udp) dport $PORT_TRANSMISSION ACCEPT;
                    proto (tcp udp) dport $PORT_WEB ACCEPT;
                    proto udp dport $PORT_TRACKERS ACCEPT;
                }
            }
        }
    }
}


# The main IPv4 rule set.
domain ip {
    table filter {
        chain INPUT {
        # The default policy for the chain 
            policy DROP;
        
        # Connection tracking.
            mod state state INVALID DROP;
            mod state state (ESTABLISHED RELATED) ACCEPT;

        # Allow local traffic to loopback interface.
            daddr $NET_LOOPBACK ACCEPT;

        # Allowed services on the LAN interface.
        # SSH, TWEB (transmission gui - windows), samba smb (shared folders - windows)
            interface $DEV_LAN {
                proto tcp dport $PORT_SSH ACCEPT;
                proto tcp dport $PORT_TWEB ACCEPT;
                proto tcp dport $PORT_SMBT ACCEPT;
                proto udp dport $PORT_SMBU ACCEPT;
            }

        # Respond to ping.
                proto icmp icmp-type echo-request ACCEPT;

        # Log dropped packets.
#        NFLOG nflog-group 1;
#        DROP;
        }

        chain OUTPUT{
            policy DROP;

        # Connection tracking.
            mod state state INVALID DROP;
            mod state state (ESTABLISHED RELATED) ACCEPT;

        # Allow local traffic from the loopback interface.
            saddr $NET_LOOPBACK ACCEPT;

        # Respond to ping.
                proto icmp icmp-type echo-request ACCEPT;

        # Allowed services on the LAN interface.
        # DNS (domain name server), NTP (network time), OPENVPN (connect port for vpn provider),
        # SSH, Web (apt update etc), TWEB (transmission gui - windows), samba smb (shared folders - windows)
            outerface $DEV_LAN {
                proto (tcp udp) daddr $IP_DNS_PUBLIC dport $PORT_DNS ACCEPT;
                proto udp dport $PORT_NTP ACCEPT;
                proto (tcp udp) dport $PORT_OPENVPN ACCEPT;
                proto tcp dport $PORT_SSH ACCEPT;
                proto (tcp udp) dport $PORT_WEB ACCEPT;
                proto tcp dport $PORT_TWEB ACCEPT;
                proto tcp dport $PORT_SMBT ACCEPT;
                proto udp dport $PORT_SMBU ACCEPT;
            }

        # Log dropped packets.
#        NFLOG nflog-group 1;
#        DROP;
        }

        chain FORWARD {
            policy DROP;

        # If you use your machine to route traffic eg.
        # from a VM you have to add rules here!

        # Log dropped packets.
#        NFLOG nflog-group 1;
#        DROP;
        }
    }
}
```
Save the file by *Ctrl X* and exit nano  
Now test ferm
```
ferm --interactive -l /etc/ferm/ferm.conf
```
at the bottom you should be able to type *yes* if you can't type yes then the ferm rules will not be applied to iptables  
Note: *--interactive* is a safety measure during testing so we can't be locked out of ssh access by a bad ferm rule.

***Check the change to iptables made by the ferm***
```
iptables -nL -v
```
ferm has restricted ports to the basic necessity and those required to connect to NordVPN  
Access to the web for things like apt update is only availble when the vpn is not running via eth0

Change ferm startup settings in */etc/default/ferm* from *ENABLED="no"* to *ENABLED="yes"*
```
nano /etc/default/ferm
```
```
ENABLED="yes"
```
Save the file by *Ctrl X* and exit nano

Now make a new file */etc/udev/rules.d/81-vpn-firewall.rules* by starting nano and add 2 lines  
```
nano /etc/udev/rules.d/81-vpn-firewall.rules
```
```
KERNEL=="tun0", ACTION=="add", RUN+="/usr/local/bin/fermreload.sh add"
KERNEL=="tun0", ACTION=="remove", RUN+="/usr/local/bin/fermreload.sh remove"
```
Save the file by *Ctrl X* and exit nano  
or use this easy method to do the above
```
echo -e 'KERNEL=="tun0", ACTION=="add", RUN+="/usr/local/bin/fermreload.sh add"\nKERNEL=="tun0", ACTION=="remove", RUN+="/usr/local/bin/fermreload.sh remove"' >> /etc/udev/rules.d/81-vpn-firewall.rules
```
Now make a new file */usr/local/bin/fermreload.sh* by starting nano and add the following lines
```
nano /usr/local/bin/fermreload.sh
```
```
#!/bin/bash
#
# fermreload.sh
# V: 1.0
#
# Reloads the ferm firewall ruleset and is invoked by
# the udev via /etc/udev/rules.d/81-vpn-firewall.rules.
#
#

LOGGER=/usr/bin/logger
LOGGER_TAG=$0

UDEV_ACTION=$1

FERM=/usr/sbin/ferm
FERM_CONF=/etc/ferm/ferm.conf

MSG_FW_RULE_ADD="Adding VPN firewall rules."
MSG_FW_RULE_REMOVE="Removing VPN firewall rules."
MSG_UDEV_ACTION_UNKNOWN="Unknown udev action."

case "$UDEV_ACTION" in
    add)
        $LOGGER -t $LOGGER_TAG $MSG_FW_RULE_ADD
        $FERM $FERM_CONF
        ;;
    remove)
        $LOGGER -t $LOGGER_TAG $MSG_FW_RULE_REMOVE
        $FERM $FERM_CONF
        ;;
    *)
        $LOGGER -t $LOGGER_TAG $MSG_UDEV_ACTION_UNKNOWN
        exit 1
esac
```
Save the file by *Ctrl* X and exit nano  
Set permissions and reload udev
```
chmod 555 /usr/local/bin/fermreload.sh && systemctl reload udev
```
Now Reboot
```
reboot
```
Make sure Pageant is still loaded with your Private key  
SSH in as *root* with *192.168.0.206:2122*

### ***Installing, Configuring openvpn and testing the VPN rules created by ferm***

Note: If this install fails then ferm is not configured correctly
```
apt update && apt install openvpn -y
```
openvpn service will start on boot so we need to stop it  
Stop and Disable openvpn autostart on boot
```
systemctl stop openvpn && systemctl disable openvpn
```
***Configure openvpn to start with your vpn settings and credentials***  

Download the *.ovpn* file from NordVPN for the vpn server you want to use. Copy this file to */etc/openvpn* using winscp and then  
rename it from *.ovpn* to *nordvpn.conf*. When openvpn starts we will use *nordvpn.conf* to connect.  
Note: Replace *your.ovpn* below with the *ovpn* you downloaded from NordVPN
```
mv /etc/openvpn/your.ovpn /etc/openvpn/nordvpn.conf
```
We want our credentials automatically entered when openvpn starts, use nano to edit the file *nordvpn.conf* and  
change the following line from *auth-user-pass* to *auth-user-pass /etc/openvpn/nordvpn.auth*  
```
nano /etc/openvpn/nordvpn.conf
```
```
auth-user-pass /etc/openvpn/nordvpn.auth
```
now save the file by *Ctrl X* and exit nano  
or use this easy method to do the above
```
sed -i 's#auth-user-pass#auth-user-pass /etc/openvpn/nordvpn.auth#g' /etc/openvpn/nordvpn.conf
```
Everytime we edit the nordvpn.conf file we should reload/update it into openvpn
```
systemctl daemon-reload
```
Now use nano to create a new file called */etc/openvpn/nordvpn.auth*  
on the first line put your *username* and on the second line put your *password*  
Note: *nordvpn.auth* file must be in Windows CRLF EOL format
```
nano /etc/openvpn/nordvpn.auth
```
```
put your username here
put your password here
```
now save the file by *Ctrl X* and exit nano  
Change to Windows CRLF EOL format
```
unix2dos /etc/openvpn/nordvpn.auth
```
Now when you start openvpn it will automatically log you into the vpn server.  
Note: the *username* and *password* above is from the NordVPN service credentials page in your Nord Account dashboard  
Note for security: Your *username* and *password* is in plaintext and can be read by anyone with access to */etc/openvpn/nordvpn.auth*

***Testing the iptables rules with openvpn running using dual screens***
```
screen
```
Start openvpn in this new screen. Note: this will automatically use your NordVPN login as configured above
```
systemctl start openvpn@nordvpn
```  
Press *Ctrl A* then *Ctrl D* to exit the new screen and you are now returned back to the original screen  
it's ok, openvpn is still running in the new screen  
Lets have a look at the current interfaces to see if tun0 was added
```
ifconfig
```
Also we can look at what happened in syslog
```
tail -F /var/log/syslog
```
Here we see that the tun0 interface was created and you should see  
*Feb  19 20:48:30 raspberrypi /usr/local/bin/fermreload.sh: Adding VPN firewall rules.*

Now we can also check the iptables after the vpn is started showing the vpn rules have been added
```
iptables -nL -v
```
All is good so we can return to the new screen and stop openvpn
```
screen -r
```
Stop openvpn Note: usually *Ctrl C* or type *systemctl stop openvpn* and then type *exit*  
Lets have a look at the current interfaces to see if tun0 was removed
```
ifconfig
```
Also we can check syslog again
```
tail -F /var/log/syslog
```
syslog should show  
Feb  19 20:48:47 raspberrypi /usr/local/bin/fermreload.sh: Removing VPN firewall rules.  

Now we can check the iptables showing the vpn rules have been removed and iptables have been restored to before the vpn was started
```
iptables -nL -v
```
Great, the iptables have now been restored to before the vpn was started

## ***Install and Configure transmission***

Note: If this install fails then ferm is not configured correctly
```
apt update && apt install transmission-cli transmission-daemon -y
```
transmission will start on boot so we need to stop it  
Stop and Disable transmission autostart on boot
```
systemctl stop transmission-daemon && systemctl disable transmission-daemon
```
***Configure transmission to work with windows Transmission Remote GUI***

Ensure transmission-daemon is stopped
```
systemctl stop transmission-daemon
```
Use nano to edit the file */etc/transmission-daemon/settings.json* and change the following
```
nano /etc/transmission-daemon/settings.json
```
```
"rpc-password": "put a password in here",
"rpc-username": "put a username in here",
"rpc-whitelist": "127.0.0.1,192.168.0.4",
```
Now save the file by *Ctrl X* and exit nano

## ***Install and Configure samba with a transmission shared folder***

Create the folder */media/Downloads* to be shared and set ownership and permissions
```
install -m 0755 -g debian-transmission -o debian-transmission -d /media/Downloads
```
Now install samba
```
apt update && apt install samba -y
```
***Configure samba with the shared folder***

Open file *smb.conf* in nano find the following line *workgroup = WORKGROUP*  
and edit it with your workgroup name *workgroup = \<MyDomain here\>* and then add the following lines at the bottom  
Note: Open a Command Prompt in Windows and type *wmic computersystem get domain* to get your Domain  
Note for security: Only *192.168.0.4* in *hosts allow =* can access this shared folder so change to your own Windows IP Address
```
nano /etc/samba/smb.conf
```
```
[global]
# Disable participation in master browser election
local master = no

# Disable Printers
load printers = no
printing = bsd
printcap name = /dev/null
disable spoolss = yes

# Allow access only from selected and DENY all others
hosts allow = 127.0.0.1 192.168.0.4
hosts deny = ALL

# Shared folder accessable from Windows
# comment = the name of the share as it will show in File Explorer
[Downloads]
comment = Transmission Downloads Folder
path = /media/Downloads
browseable = yes
create mask = 0755
directory mask = 0755
force user = root
guest ok = yes
only guest = yes
read only = no
```
Save the file by *Ctrl X* and exit nano  
Restart samba service
```
systemctl restart smbd
```
From Windows Explorer you can access this folder by typing *\\\192.168.0.206* into the address bar  
and you should be able to copy into and delete files in this folder

Create Symbolic Links to our folder for the torrents and resume folders that are independant of transmission default locations
```
install -m 0755 -g debian-transmission -o debian-transmission -d /media/torrents
install -m 0755 -g debian-transmission -o debian-transmission -d /media/resume
rm -d /var/lib/transmission-daemon/.config/transmission-daemon/torrents
rm -d /var/lib/transmission-daemon/.config/transmission-daemon/resume
ln -s /media/torrents /var/lib/transmission-daemon/.config/transmission-daemon
ln -s /media/resume /var/lib/transmission-daemon/.config/transmission-daemon
```
## ***Install and Configure Transmission Remote GUI***

***Install Transmission Remote GUI into Windows and configure for transmission-daemon***

Download and install Transmission Remote Gui for Windows and run it  
In *Tools \> Application options \> Transmission* change -

>Remote Host: 192.168.0.206  
>Port: 9091  
>Authentication Required &#x2611;  
>Always Auto-reconnect &#x2611;  
>User name: *The same username as used above in transmission*  
>Password: *The same password as used above in transmission*

Exit Transmission Remote GUI and start transmission-daemon
```
systemctl start transmission-daemon  
```
Start Transmission Remote GUI and it should connect.  
In *Tools \> Transmission options* change -

>*Download* section  
>Default download folder on remote host /media/Downloads  
>Disk cache size: 32MB  
>*Network (WAN)* section  
>Incomping port: &#x2611; Pick random port on Transmission launch

Change any other settings in Transmission Remote GUi to suit your needs and then Exit.  
Ensure transmission-daemon is stopped
```
systemctl stop transmission-daemon
```
## ***Create a script to start/stop openvpn and transmission***

Note: The script will wait for tun0 (vpn) to be up before starting transmission.

Add an alias that runs the script  
Start nano and add the following line to the bottom of file */root/.bashrc*

```
nano /root/.bashrc
```
```
alias start_vpn=/root/.scripts/start_vpn.sh
```
Save the file by *Ctrl X* and exit nano  
or use this easy method to do the above
```
echo -e "alias start_vpn=/root/.scripts/start_vpn.sh" >> /root/.bashrc
```
Create a folder */root/.scripts* for the script
```
mkdir /root/.scripts
```
Now make a new file */root/.scripts/start_vpn.sh* by starting nano and add the following lines
```
nano /root/.scripts/start_vpn.sh
```
```
#!/bin/bash

function ask_yes_or_no() {
    read -p "$1 ([y]es or [N]o): "
    case $(echo $REPLY | tr '[A-Z]' '[a-z]') in
        y|yes) echo "yes" ;;
        *)     echo "no" ;;
    esac
}
STATE="down"
DATE=`date +%H:%M:%S%t%d-%m-%Y`
echo
echo -ne "At" $DATE
if ps ax | grep -v grep | grep openvpn > /dev/null && ps ax | grep -v grep | grep transmission-daemon > /dev/null
then
    echo " All Services already running so Stopping all Services."
if [[ "no" == $(ask_yes_or_no "Are you sure?") ]]
then
    echo "Aborted Stopping Services."
    exit 0
fi
echo
    systemctl stop transmission-daemon
sleep 2
    systemctl stop openvpn
sleep 2
echo
echo "Confirming Services Stopped."
    systemctl -n1 status openvpn
    systemctl -n1 status transmission-daemon
echo
echo "All Services stopped."
echo
exit 0

else
     echo " Services not running so starting all Services."
if [[ "no" == $(ask_yes_or_no "Are you sure?") ]]
then
    echo "Aborted Starting Services."
    exit 0
fi
systemctl start openvpn@nordvpn

while [ $STATE == "down" ]; do
    echo -ne "waiting for tun0 to be up\033[0K\r"
    STATE=$(/usr/sbin/ifconfig tun0 2>/dev/null | grep -q "00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00" > /dev/null && echo up || echo down)
    sleep 2
done
systemctl start transmission-daemon
ifconfig
fi
```
Save the file by *Ctrl X* and exit nano  
Set permissions
```
chmod 700 /root/.scripts && chmod 500 /root/.scripts/start_vpn.sh
```
install the updated bashrc
```
source ~/.bashrc
```

You can start\stop the the vpn by typing *start_vpn* on the command line.

I hope you are successful using the method shown above  
Regards.....

## ***Extra information***

The VPN iptable rules in ferm allow port 80 so that DHT & Trackers that use port 80 can be used.  
Other tracker ports are allowed as follows  
Trackers that use the ports opened by ferm as defined in *@def $PORT_TRACKERS = ( 1337 6888 6969 );*  
Just add Tracker Ports to this list by placing a *space* between them.  
If you must have Port 80 closed in the VPN then comment (add the # to) this line in */etc/ferm/ferm.conf*
```
#                    proto (tcp udp) dport $PORT_WEB ACCEPT;
```
Another reason to have Port 80 open is to complete a torrent IP Address check like the one at TorGuard  
https://torguard.net/checkmytorrentipaddress.php after starting the VPN with *start_vpn* go to their website and  
click on Download, then open the .torrent in Transmission Remote GUI (don't close the website)  
After a few seconds check the website and you should see only your VPN IP Address.  

***Monitoring Internal and VPN traffic.***

While the vpn is up (openvpn started) you can use the following to view torrent activity on interfaces eth0 or tun0
```
iftop -i eth0
iftop -i tun0
````
More information. *iftop --help* for for more options
```
iftop -nNPi eth0
iftop -nNPi tun0
```
While you are downloading torrents you should see the following traffic -  
On eth0 from 192.168.0.206 to the IP Address of the VPN but there shouldn't be any connections to torrent peers  
On tun0 you should see traffic between the VPN IP Address and torrent peers, there shouldn't be any connections  
to 192.168.0.206 or your External IP Address (the IP Address provided by your ISP -Internet Service Provider)

IMPORTANT: If you ever change the contents of the nordvpn.conf file you must reload/update it into openvpn
```
systemctl daemon-reload
```
***There are two common ways of managing services.***

The *systemctl* command is a systemd daemon used to manage services
```
systemctl start openvpn
systemctl start transmission-daemon

systemctl stop openvpn
systemctl stop transmission-daemon

systemctl status openvpn
systemctl status transmission-daemon
```
The *service* command manages services under the */etc/init.d* directory
```
service openvpn start
service transmission-daemon start

service openvpn stop
service transmission-daemon stop

service openvpn status
service transmission-daemon status
```