# ************************
# Title: main.py
# Author: Andrew Carr
#
# Function: Control Cisco router config (in GNS3)
# Pre-requisites: netmiko
# Implementation: TBC
# Version history:
#  - 0.1 - first imprint
#  - 0.2 - commented out debug print statements
# ************************

'''
HELP:
 - https://github.com/jayspalma/netmiko_basic_automation/blob/master/netmiko%20files/basic_automation.py
 - http://ktbyers.github.io/netmiko/
 - https://ktbyers.github.io/netmiko/docs/netmiko/index.html
 - https://stackoverflow.com/questions/39751563/python-ipaddress-get-first-usable-host-only
 - https://docs.python.org/3/library/ipaddress.html

TODO:
 - IPv6 support?
 - logging?
 - better way to store the password rather than in plaintext? Keyvault? public/private key for ssh?
'''

from netmiko import ConnectHandler
from netmiko.ssh_exception import NetmikoTimeoutException
from paramiko.ssh_exception import AuthenticationException, SSHException
import argparse
import ipaddress
import sys


def get_arguments():
    parser = argparse.ArgumentParser(
        description="Example: filename.py -l 10 -i 10.7.0.0 -m 255.255.0.0"
    )
    parser.add_argument(
        '-l', '--loopback_id', type=str, help="Loopback ID to use between 1 and 2,147,483,647", required=True
    )
    parser.add_argument(
        '-i', '--ip_prefix', type=str, help="IP prefix to block", required=True
    )
    parser.add_argument(
        '-m', '--mask', type=str, help="Mask for the prefix to block", required=True
    )
    args = parser.parse_args()
    get_arguments.loopback_id = args.loopback_id
    get_arguments.ip_prefix = args.ip_prefix
    get_arguments.mask = args.mask


def validate_ip_address(prefix):
    try:
        if ipaddress.IPv4Address(prefix).version == 4:
            return True
    except ipaddress.AddressValueError:
        # print("This does not appear to be a valid IP address")
        sys.exit("ip_validation_error")


def prefix_to_first_host(prefix, mask):
    try:
        prefix_length = ipaddress.IPv4Network(prefix + '/' + mask).prefixlen
    except ValueError:
        # print("Check the IP address - it appears to be a host address, not the expected network address")
        sys.exit("prefix_has_host_bit_set")
    prefix_cidr = prefix + '/' + str(prefix_length)
    i = ipaddress.ip_network(prefix_cidr)
    first_host = next(i.hosts())
    return first_host


def basic_connection_test():
    # Not actively used, here for ease if debugging needed
    output = net_connect.send_command('show run')
    # print(output)


def create_loopback(loopback_id, prefix_fuh, mask):
    config_commands = [ 'interface loopback ' + loopback_id,
                        'ip address ' + prefix_fuh + ' ' + mask ]
    output = net_connect.send_config_set(config_commands)
    # print(output)


def advertise_route(prefix, mask):
    config_commands = [ 'router bgp 65535',
                        'network ' + prefix + ' mask ' + mask ]
    output = net_connect.send_config_set(config_commands)
    # print(output)


def save_disconnect():
    # Try to save, if any error gracefully close then exit with error; if ok, gracefully exit
    try:
        net_connect.send_command("copy r s")
    except:
        # print("Unknown error when attempting to save configuration to NVRAM")
        net_connect.disconnect()
        sys.exit("save_config_error")
    net_connect.disconnect()


if __name__ == "__main__":
    # Read in the args
    get_arguments()

    # Check loopback_id value is valid
    try:
        if not 1 <= int(get_arguments.loopback_id) <= 2147483647:
            # print("Loopback_id should be an int between 1 and 2,147,483,647")
            sys.exit("loopback_id_out_of_bounds")
    except ValueError:  # for non-ints
        # print("Loopback_id should be an int between 1 and 2,147,483,647")
        sys.exit("loopback_id_not_int")

    # Validate IP address and mask
    if validate_ip_address(get_arguments.ip_prefix) != True:
        sys.exit("ip_prefix_not_valid")
    if validate_ip_address(get_arguments.mask) != True:
        sys.exit("mask_not_valid")

    # Get first usable host in the prefix for the loopback address
    ip_prefix_first_host = prefix_to_first_host(get_arguments.ip_prefix, get_arguments.mask)

    # Setup connection
    gns3 = {
        'device_type' : 'cisco_ios_telnet',             # GNS3 routers are on telnet via the VM. Change to cisco_ios for "real"
        'host' : '192.168.56.107',                      # GNS3 VM
        'username' : 'python',
        'password' : 'weakpass',
        'port' : '5000',                                # port for NMC router in GNS3
        'secret' : '',                                  # not currently needed
    }

    try:
        net_connect = ConnectHandler(**gns3)
    except(AuthenticationException):
        # print("Incorrect username or password")
        sys.exit("ssh_auth_fail")
    except(SSHException):
        # print("Connection failure")
        sys.exit("ssh_connection_fail")
    except(NetmikoTimeoutException):
        # print("Timeout when connecting")
        sys.exit("ssh_timeout")
    except Exception as unknown_error:
        # print("Unknown error encountered during connection: " + str(unknown_error))
        sys.exit("ssh_unknown_error")

    # Create loopback
    create_loopback(str(get_arguments.loopback_id), str(ip_prefix_first_host), str(get_arguments.mask))

    # Advertise network
    advertise_route(str(get_arguments.ip_prefix), str(get_arguments.mask))

    # exit
    save_disconnect()
