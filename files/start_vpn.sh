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