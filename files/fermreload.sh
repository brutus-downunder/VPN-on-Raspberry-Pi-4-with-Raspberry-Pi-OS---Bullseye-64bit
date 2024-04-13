#!/bin/bash
#
# fermreload.sh
# V: 0.1
#
# Reloads the ferm firewall ruleset and is invoked by
# the udev via /etc/udev/rules.d/81-vpn-firewall.rules.
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
