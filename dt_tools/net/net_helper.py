"""
Network utilities helper module.

Functions to assist with network related information and tasks.

- ping
- local IP address
- get ip for given hostname
- get hostname for given ip
- get mac address for given hostname or ip
- get mac vendor
- get local client info on LAN

"""
import ipaddress
import pathlib
import platform
import random
import socket
import subprocess
from dataclasses import dataclass
from time import sleep
from typing import List, Tuple, Union

import requests
import scapy.all as scapy
from dt_tools.logger.logging_helper import logger_wraps
from dt_tools.os.os_helper import OSHelper
from loguru import logger as LOGGER

_UNKNOWN = 'unknown'

COMMON_PORTS = {
    "Echo service": 7,
    "FTP-data": 20,
    "FTP": 21,
    "SSH": 22,
    "Telnet": 23,
    "SMTP": 25,
    "DNS": 53,
    "TFTP": 69,
    "HTTP": 80,
    "Kerberos": 88,
    "Iso-tsap": 102,
    "POP3": 110,
    "MS EPMAP": 135,
    "NetBIOS-ns": 137,
    "NetBIOS-ssn": 139,
    "IMAP4": 143,
    "HP Openview (alarm)": 381,
    "HP Openview (data)": 383,
    "HTTPS": 443,
    "Kerberos (pwd)": 464,
    "SMTP TLS/SSL": 465,
    "SMTP (submission)": 587,
    "MS DCOM": 593,
    "LDAP TLS/SSL": 636,
    "MS Exchange": 691,
    "VMWare": 902,
    "FTP SSL (data)": 989,
    "FTP SSL (control)": 990,
    "IMAP4 SSL": 993,
    "POP3 SSL": 995,
    "MS RPC": 1025,
    "OpenVPN": 1194,
    "WASTE": 1337,
    "Cisco VQP": 1589,
    "Steam": 1725,
    "cPanel": 2082,
    "radsec": 2083,
    "Oracle DB": 2483,
    "Oracle DB SSL": 2484,
    "Semantec AV": 2967,
    "XBOX Live": 3074,
    "MySQL": 3306,
    "World of Warcraft": 3724,
    "Google Desktop": 4664,
    "PostgresSQL": 5432,
    "RFB/VNC": 5900,
    "IRC1": 6665,
    "IRC2": 6666,
    "IRC3": 6667,
    "IRC4": 6668,
    "IRC5": 6669,
    "BitTorrent": 6881,
    "Quicktime": 6970,
    "BitTorrent2": 6999,
    "Kaspersky CC": 8086,
    "Kaspersky": 8087,
    "VMWare Server": 8222,
    "PDL": 9100,
    "BackupExec": 10000,
    "NetBus": 12345,
    "Sub7": 27374,
    "Back Orifice": 31337,
}

@dataclass
class LAN_Client():
    """
    Data class to hold Lan Client information.

    """
    ip: str #: Device IP address
    mac: str #: Device MAC address
    hostname: str = None # Device hostname
    vendor: str = None # NIC Vendor

    def to_dict(self):
        """
        Return LAN_Client as a dictionary.
        """
        LAN_Client_dict = {}
        for attr in self.__dict__:
            LAN_Client_dict[attr] = self.__dict__[attr]

        return LAN_Client_dict        


# ===============================================================================================
def get_port_name(port:int) -> str:
    """
    Retrieve (common) port name if defined else none.

    Args:
        port (int): port number

    Returns:
        str: Port name if found, else none
    """
    port_name = None
    if port in COMMON_PORTS.values():
        for key, val in COMMON_PORTS.items():
            if val == port:
                port_name = key
                break
    return port_name

def _get_ipaddress_obj(ip: str) -> Union[ipaddress.IPv4Address, ipaddress.IPv6Address]:
    """
    get ip_address object

    Args:
        ip (str): String representation of IPv4 or IPv6 address.

    Returns:
        Union[ipaddress.IPv4Address, ipaddress.IPv6Address]: ipaddress object
    """
    ip_obj = None
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        pass

    return ip_obj

def is_valid_ipaddress(ip: str) -> bool:
    """
    Check if IP is valid address.

    Args:
        ip (str): IP address.

    Returns:
        bool: True if valid else False.
    """
    return _get_ipaddress_obj(ip) is not None

def is_ipv4_address(ip: str) -> bool:
    """
    Validate IPv4 address in dotted-quad notation.
    
    Args:
        ip_address: (str) in format 999.999.999.999

    Example::

        >>> is_ipv4_address("1.2.3.4")
        True
        >>> is_ipv4_address("127.0.0.1/8")
        False
        >>> is_ipv4_address("1.2.3.4.5")
        False
    """
    ip_obj = _get_ipaddress_obj(ip)
    return ip_obj is not None and isinstance(ip_obj, ipaddress.IPv4Address)

def is_ipv6_address(ip: str) -> bool:
    """
    Validate IPv6 address.

    Args:
        ip (str): IPv6 formatted address.

    Returns:
        bool: True if valid else False.
    """
    ip_obj = _get_ipaddress_obj(ip)
    return ip_obj is not None and isinstance(ip_obj, ipaddress.IPv6Address)


def is_port_open(host_name: str, port: int, timeout:float=1.0) -> bool:
    """
    Check if port is open on target host.

    Args:
        host_name (str): Target host name
        port (int): Port number to test
        timeout (float, optional): Seconds to wait for connection. Defaults to 1.0.

    Returns:
        bool: True if port is open else False
    """
    port_is_open = False
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    LOGGER.debug(f'is_port_open() - attempting to connect to {host_name}:{port}')
    try:
        s.connect((host_name, int(port)))
        s.shutdown(socket.SHUT_WR)
        LOGGER.debug('is_port_open() - connection successful.')
        port_is_open = True
    except:  # noqa: E722
        LOGGER.debug(f'is_port_open() - unable to connect to {host_name}:{port}')
    finally:
        s.close()

    return port_is_open

@logger_wraps(level="TRACE")
def is_valid_host(host_name: str) -> bool:
    """
    Check if host_name is valid.  
    
    Args:
        host (str): Host name or IP address.

    Returns:
        bool: True if hostname is resolvable else False
    """
    try:
        if is_valid_ipaddress(host_name):
            LOGGER.debug(f'is_valid_host() - check via IP addr: {host_name}')
            _ = socket.gethostbyaddr(host_name)
        else:
            LOGGER.debug(f'is_valid_host() - check via hostname: {host_name}')
            _ = socket.gethostbyname(host_name)
        valid_host = True

    except (socket.gaierror, socket.herror):
        valid_host = False

    return valid_host
    

# == get hostname, ip, MAC, vendor routins ======================================================
@logger_wraps(level="TRACE")
def get_hostname_from_ip(ip: str) -> str:
    """
    Get hostname from IP address.

    Arguments:
        ip: IP address to get hostname for.

    Returns:
        Hostname if found else 'unknown' if not found or error.
    """
    hostname = _UNKNOWN
    if ip == get_local_ip():
        hostname = get_local_hostname()
    else:
        try:
            host = socket.gethostbyaddr(ip)
            hostname = host[0]
        except Exception as ex:
            LOGGER.debug(f'Unable to get_hostname_from_ip("{ip}") - {repr(ex)}')

    return hostname

@logger_wraps(level="TRACE")
def get_ip_from_hostname(host_name: str = None) -> str:
    """
    Get IP address from hostname.

    Arguments:
        host_name: Name of target host, if missing, use local hostname

    Returns:
        IP address if found or '' if not found or error.

    """
    if host_name is None:
        host_name = socket.gethostname()

    try:
        ip = socket.gethostbyname(host_name)
    except socket.gaierror:
        ip = ''
    return ip

@logger_wraps(level="TRACE")
def get_ip_from_mac(mac: str) -> str:
    """
    Get IP address based on MAC (via ARP)

    Args:
        mac (str): MAC address

    Raises:
        ValueError: Unknown MAC address format
        ValueError: Unable to determine IP from MAC address

    Returns:
        str: IP address
    """
    mac = format_mac(mac)

    cmd_list = _arp_entries_command().split()
    try:
        process_rslt = subprocess.run(cmd_list, capture_output=True)
        rslt = process_rslt.stdout.decode('utf-8').splitlines()
    except Exception as ex:
        LOGGER.error(f'get_ip_from_mac("{mac}"): unable to run {cmd_list}.  {repr(ex)}')
        rslt = ""

    LOGGER.debug(f'MAC: {mac}\nRESULT: {rslt}')
    arp = [token for token in rslt if mac.lower() in token.lower()]
    arp_line = '' if len(arp) == 0 else arp[0]
    LOGGER.debug(f'  arp line: {arp}')
    ip = None
    if len(arp_line) > 0:
        try:
            if platform.system() == "Windows":
                ip = " ".join(arp_line.split()).split()[0]
            else:
                # This used to be [2] for some reason...
                ip = " ".join(arp_line.split()).split()[0]
        except Exception as ex:
            LOGGER.error(f'  mac [{mac}]-problem resolving ip: {arp_line} - {repr(ex)}')

    if ip is not None:
        LOGGER.debug(f'  MAC {mac} resolves to {ip}')
        return ip
    
    raise ValueError(f'Unable to resolve IP for mac {mac}')

def get_wan_ip() -> str:
    """
    Get the WAN (ie. Internet) IP address for this device.

    Returns:
        str: WAN IP or 'Unknown'
    """
    from dt_tools.net.ip_info_helper import IpHelper

    ip_info, _ = IpHelper.get_wan_ip_info()
    return ip_info.get('ip', _UNKNOWN)


def get_lat_lon_for_ip(ip: str) -> Tuple[float, float]:
    """
    Get GPS coordinates (lat/lon) for Internet IP address.

    Args:
        ip (str): Internet IP address, local address will NOT work.

    Returns:
        Tuple[float, float]: latitude, longitude or 0.0, 0,0 if not found.
    """
    lat: float = 0.0
    lon: float = 0.0
    url = f'https://ipapi.co/{ip}/latlong/'
    #headers = {'user-agent': 'ipapi.co/#ipapi-python-v1.0.4'} 
    headers = {'user-agent': 'ipapi.co/#custom'}               
    resp = requests.get(url, headers=headers)
    if resp.text.count(',') == 1:
        token = resp.text.split(',')
        lat = token[0]
        lon = token[1]
    LOGGER.debug(f'Lat/Lon identified - ip: {ip}  lat: {lat}  lon: {lon}')
    return lat, lon


@logger_wraps(level="TRACE")
def get_local_ip() -> str:
    """
    Get local IP address

    Returns:
        Local machine IP address, or '127.0.0.1' if not found or error
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # doesn't even have to be reachable
        s.connect(('192.255.255.255', 1))
        ip = s.getsockname()[0]
    except:  # noqa: E722
        ip = '127.0.0.1'
    finally:
        s.close()

    return ip

@logger_wraps(level="TRACE")
def get_local_hostname() -> str:
    """
    Get local hostname

    Returns:
        str: local host name or 'unknown'
    """
    hostname = _UNKNOWN
    try:
        hostname = socket.gethostname()
    except Exception as ex:
        LOGGER.debug(f'Unable to get_local_hostname() - {repr(ex)}')

    return hostname

def get_workgroup_name() -> str:
    """
    Get windows worgroup/domain name

    Returns:
        str: Workgroup/domain name or 'unknown'
    """
    workgroup = _UNKNOWN
    if OSHelper.is_windows():
        try:
            process_rslt = subprocess.run('systeminfo', capture_output=True)
            rslt = process_rslt.stdout.decode('utf-8').splitlines()
            for line in rslt:
                if line.startswith('Domain:'):
                    workgroup = line.split()[1]
                    break
        except Exception as ex:
            LOGGER.error(f'get_workgroup_name(): unable to run systeminfo command.  {repr(ex)}')
    else:
        try:
            smb_file = pathlib.Path('/etc/samba/smb.conf')
            if smb_file.exists():
                for line in smb_file.read_text().splitlines():
                    if line.strip().startswith('workgroup'):
                        workgroup = line.split()[2]
                        break
        except Exception as ex:
            LOGGER.error(f'get_workgroup_name(): unable to run systeminfo command.  {repr(ex)}')

    return workgroup
        
@logger_wraps(level="TRACE")
def get_mac_address(ip: str) -> str:
    """
    Get mac address for specified IP

    Returns:
        str: MAC address or None if not found.
    """
    
    if ip == get_local_ip():
        import uuid
        mac = (':'.join(['{:02x}'.format((uuid.getnode() >> ele) & 0xff) for ele in range(0,8*6,8)][::-1]))    
    else:
        from scapy.layers.l2 import getmacbyip
        mac = getmacbyip(ip)
    
    if mac is not None:
        mac = str(mac).upper()
    return mac

@logger_wraps(level="TRACE")
def get_vendor_from_mac(mac: str) -> str:
    """
    Return the vendor name for specified MAC address

    Arguments:
        mac: Target MAC address

    Returns:
        Vendor name if found, else 'unknown'
    """
    if mac is None:
        raise ValueError('MAC address cannot be None.')
    vendor = _UNKNOWN
    # url = f'https://api.maclookup.app/v2/macs/{mac}'
    url = f'https://api.macvendors.com/{mac}'
    retry = 0
    RETRY_MAX = 15
    try:
        while retry < RETRY_MAX and vendor == _UNKNOWN:
            resp = requests.get(url)
            if resp.status_code == 200:
                # vendor = resp.json()['company']      # api.maclookup
                vendor = resp.text # api.macvendors.com
                if len(vendor) == 0:
                    LOGGER.debug(f'  ERROR: Vendor not found, {url}, {resp.text}')
                    vendor = "Not Found"
                if retry > 0:
                    LOGGER.debug(f'  SUCCESS. Retry succeeded, {vendor}, {url}')    
            elif resp.status_code == 429:  # You've been throttled
                retry += 1
                sleep_secs = random.uniform(0.5,3.5)
                LOGGER.debug(f'  WARNING: Throttle ({mac}) [{retry}]... {sleep_secs:1.2} {url}')
                sleep(sleep_secs) # Throttle (limit = 2 requests/second)
            else:
                LOGGER.debug(f'  ERROR: MAC Lookup resp: {resp.status_code}, {url}, {resp.text}')
                retry = RETRY_MAX

    except Exception as ex:
        LOGGER.debug(f'  ERROR: MAC Lookup error {url}: {repr(ex)}')
        vendor = _UNKNOWN
        
    if vendor == _UNKNOWN:
        LOGGER.debug(f'  ERROR: Unable to resolve, {mac}')

    return vendor


# == ARP Calls ===============================================================================================
@logger_wraps(level="TRACE")
def get_lan_clients_ARP_broadcast(include_hostname: bool = False, include_mac_vendor: bool = False) -> List[LAN_Client]:
    """
    Retrieve a list of LAN_Clients from the local network.

    The list of clients are retrieved via a Scapy ARP broadcast

    Keyword Arguments:
        include_hostname: Include hostname information (default: {False})
        include_mac_vendor: Include MAC vendor name (default: {False})

    Raises:
        PermissionError: Linux requires this call to be run as ROOT

    Returns:
        A list of :class:`~LAN_Client` entries 
    
    Note:
        including hostname and/or vendor will slow down process due to additional calls

    """
    if OSHelper.is_linux() and not OSHelper.is_linux_root():
        LOGGER.critical('You must be root on linux for ARP_Broadcast to work')
        raise PermissionError('Must be root')

    request = scapy.ARP()
    request.pdst = _get_target_protocol_address_pdst() # '192.168.1.1/24'
    broadcast = scapy.Ether() 
    
    broadcast.dst = 'ff:ff:ff:ff:ff:ff'    
    request_broadcast = broadcast / request 
    clients = scapy.srp(request_broadcast, timeout=3, verbose=False)[0] 

    lan_client_list: List[LAN_Client] = []
    for element in clients: 
        ip = element[1].psrc
        if is_ip_local(ip):
            mac: str = element[1].hwsrc
            entry = LAN_Client(ip, mac.upper())
            lan_client_list.append(entry)
    
    if include_hostname or include_mac_vendor:
        lan_client_list = _get_hostname_and_or_vendor(lan_client_list, include_hostname, include_mac_vendor)

    return lan_client_list        

@logger_wraps(level="TRACE")
def get_lan_clients_from_ARP_cache(include_hostname: bool = False, include_mac_vendor: bool = False) -> List[LAN_Client]:
    """     
    Retrieve a list of LAN_Clients from the local network.

    The list of clients are retrieved via the ARP cache.

    Keyword Arguments:
        include_hostname: Include hostname information (default: {False})
        include_mac_vendor: Include MAC vendor name (default: {False})

    Returns:
        A list of :class:`~LAN_Client` entries 

    Note:
        including hostname and/or vendor will slow down process due to additional calls

    """
    arp_cmd = ["arp", "-a"] if OSHelper().is_windows() else ["arp", "-n"]
    LOGGER.debug(f'ARP command: {arp_cmd}')
    process_rslt = subprocess.run(arp_cmd, capture_output=True)
    result = process_rslt.stdout.decode('utf-8').splitlines()
    # Remove lines that are not IPs
    tokens =  [ line.strip() for line in result if line.count('.')==3 and not line.startswith('Interface')]

    lan_client_list = []
    for arp_entry in tokens:
        # If windows, response will be IP MAC TYPE, else IP TYPE MAC
        arp_field = arp_entry.split()
        ip = arp_field[0]
        if is_ip_local(ip):
            mac = arp_field[1] if OSHelper().is_windows() else arp_field[2]
            mac = mac.replace('-',':').upper()
            entry = LAN_Client(ip, mac)
            lan_client_list.append(entry)

    if include_hostname or include_mac_vendor:
        lan_client_list = _get_hostname_and_or_vendor(lan_client_list, include_hostname, include_mac_vendor, bypass_cache=False)

    return lan_client_list

# ===========================================================================================================
def ping(host_name: str, wait_secs: int = 1) -> bool:
    """
    Ping target host (ip or name).

    Arguments:
        host_name: Target hostname (or ip address)

    Keyword Arguments:
        wait_secs: Number of seconds to wait for a reply (default: {1}).

    Returns:
        True if host responds, False if timeout or error.
    """
    # Token can be an IP or a hostname
    if OSHelper().is_windows():
        ping_cmd = ['ping', '-n', '1', '-w', str(wait_secs * 1000), host_name]
    else:
        ping_cmd = ['ping', '-c', '1', '-W', str(wait_secs), host_name]

    online_state = False
    ping_result = subprocess.run(ping_cmd, capture_output=True)
    if ping_result.returncode == 0 and 'unreachable' not in ping_result.stdout.decode('utf-8'):
        online_state = True
            
    return online_state

def is_ip_routable(ip: str) -> bool:
    """
    Checks if an IP address is routable on the public internet.

    Args:
        ip (str): ip address

    Returns:
        bool: True if routable, False if not.
    """

    try:
        ip = ipaddress.ip_address(ip)
    except ValueError:
        return False

    # return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast)
    return ip.is_global and not ip.is_reserved

def is_ip_local(ip: str) -> bool:
    """
    Checks if an IP address is local address (i.e. not routable on public internet).

    Args:
        ip (str): ip address

    Returns:
        bool: True if local, False if not.
    """

    try:
        ip: ipaddress.IPv4Address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    # if ip.is_private:
    #     print(f'ip_address    : {ip}')
    #     print(f'is_multicast  : {ip.is_multicast}')
    #     print(f'is_private    : {ip.is_private}')
    #     print(f'is_global     : {ip.is_global}')
    #     print(f'is_unspecified: {ip.is_unspecified}')
    #     print(f'is_reserved   : {ip.is_reserved}')
    #     print(f'is_loopback   : {ip.is_loopback}')
    #     print(f'is_link_local : {ip.is_link_local}')
    #     print('')
    return ip.is_private and not ip.is_reserved


# == Private Methods ==========================================================================
@logger_wraps(level="TRACE")
def _get_hostname_and_or_vendor(client_list: list, include_hostname: bool, include_mac_vendor: bool, bypass_cache: bool = False) -> List[LAN_Client]:

    updated_list: List[LAN_Client] = []
    from dt_tools.net.ip_info_helper import IpHelper
    ip_info = IpHelper()
    arp_entry: LAN_Client = None

    for arp_entry in client_list:
        ip_data = ip_info.get_ip_info(arp_entry.ip, bypass_cache=bypass_cache)
        if include_hostname:
            arp_entry.hostname = ip_data.get('hostname')
        if include_mac_vendor:
            arp_entry.vendor = ip_data.get('vendor')
        updated_list.append(arp_entry)

    return updated_list

def _get_target_protocol_address_pdst() -> str:
    """
    _summary_

    Returns:
        str: _description_
    """
    ip = get_local_ip()
    octet = ip.split('.')
    octet[3] = '1'
    network = '.'.join(octet) + "/24"

    return network

def _ipv4_mask_len(dotquad) -> int:
    """
    Finds the number of bits set in the netmask.

    >>> ipv4_mask_len("255.255.255.0")
    24
    >>> ipv4_mask_len("0.0.0.0")
    0
    >>> ipv4_mask_len("255.255.255.255")
    32
    >>> ipv4_mask_len("127.0.0.0")
    Traceback (most recent call last):
    ...
    ValueError: Invalid netmask: 127.0.0.0
    """
    if not is_ipv4_address(dotquad):
        raise ValueError("Invalid netmask: {0}".format(dotquad))
    a, b, c, d = (int(octet) for octet in dotquad.split("."))
    mask = a << 24 | b << 16 | c << 8 | d

    if mask == 0:
            return 0

    # Count the number of consecutive 0 bits at the right.
    # https://wiki.python.org/moin/BitManipulation#lowestSet.28.29
    m = mask & -mask
    right0bits = -1
    while m:
        m >>= 1
        right0bits += 1

    # Verify that all the bits to the left are 1's
    if mask | ((1 << right0bits) - 1) != 0xffffffff:
        raise ValueError("Invalid netmask: {0}".format(dotquad))
    return 32 - right0bits

def _arp_entries_command() -> str:
    return "arp -a" if OSHelper().is_windows() else "/usr/sbin/arp -n"

def format_mac(mac: str) -> str:
    """
    Format mac str to OS style

    Args:
        mac (str): mac str representation (12 or 17 characters)

    Raises:
        ValueError: Invalid mac string

    Returns:
        str: formatted as XX:XX:XX:XX (linux) or XX-XX-XX-XX (win)
    """
    if len(mac) == 17:
        sep = mac[2]
        fmt_mac = mac.replace(sep, _mac_separator()).lower()
    elif len(mac) == 12:
        # sep = _mac_platform_separator()
        mac_byte_list = [mac[i:i+2] for i in range(0, 12, 2) ]
        fmt_mac = _mac_separator().join(mac_byte_list).lower()
    else:
        raise ValueError(f'MAC invalid format: {mac}')
    return fmt_mac

def unformat_mac(mac: str) -> str:
    """
    Unformat mac address by removeing seperators from string

    Args:
        mac (str): formatted mac str

    Returns:
        str: mac address with no seperators (i.e. ':' linux or '-' win)
    """
    mac_address = mac
    # Check macaddress format and try to compensate.
    if len(mac_address) == 12:
        LOGGER.debug('unformat_mac() - already unformattted')
    elif len(mac_address) == 12 + 5:
        mac_address = mac_address.replace(":", "").replace("-","")
            
    if len(mac_address) != 12:
        LOGGER.debug(f'unformat_mac(): unknown format - {mac} / {mac_address}')
        mac_address = mac

    LOGGER.debug(f'unformat_mac()  in: {mac}  out: {mac_address}')
    return mac_address

def _mac_separator() -> str:
    return '-' if OSHelper.is_windows() else ":"


if __name__ == "__main__":
    import dt_tools.logger.logging_helper as lh
    import dt_tools.cli.demos.dt_net_demos as cli

    lh.configure_logger()
    cli.demo()
    print(get_workgroup_name())
    print(get_ip_from_mac('18:c0:4d:d8:e1:4e'))