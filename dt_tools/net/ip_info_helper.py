"""
Helper tools for IP related information.

**Features**:

    Uses **ipinfo.io** (https://ipinfo.io) API to retrive IP related information.

        - A free **API token** is required to call the API.
        - Tokens can be aquired by going to https://ipinfo.io/signup.
        - See below (Setting up user Token) for integrating token with this package.

    To minimize API calls (and response time):

        - IP Data is cached locally in ~/.IpHelper/cache.json.
        - MAC Data is cached locally in ~/.IpHelper/mac_info.json.

**Setting up a User Token**:

    - Go to https://ipinfo.io/signup
    - Fill out form as requested
    - Capture your token key for future reference 
    - Save your token using set-iphelper-token utility (dt-cli-tools) or manually.
    
    **Saving token manually**

        - Open an editor and load/create: ~/.IpHelper/ip_token_info.json.
        - Create one line in the file as: {"token": "xxxxxxxxxxxxxx"}
            - Replace the x's with the token supplied by ipinfo.io.
        - Save the file.



**Note**:

    For devices that are only identified by their IP and MAC address (ie. no hostname identified),
    You may assign a hostname by manually updating ~/.IpHelper/mac_info.json, 
    which is keyed by mac address.

    Format::

        {
            "XX:XX:XX:XX:XX:XX": {
                "vendor": "Ring LLC",
                "hostname": "Ring.Doorbell"
            },
        }

    One or both of the keys (vendor/hostname) must be supplied.

"""
import ipaddress
import json
import pathlib
from datetime import datetime, timedelta
from threading import Semaphore
from typing import Dict, List, Tuple

import requests
import urllib3
from dateutil import parser
from loguru import logger as LOGGER

import dt_tools.net.ip_info_helper as ih
from dt_tools.console.console_helper import TextStyle
from dt_tools.console.console_helper import ConsoleHelper as console
from dt_tools.logger.logging_helper import logger_wraps
from dt_tools.net import net_helper as nh

BASE_URL='https://ipinfo.io'
TOKEN="NOT SET"

IP_INFO_TOKEN_LOCATION=pathlib.Path('~').expanduser().absolute() / ".IpHelper" / "ipinfo_token.json"
IP_INFO_CACHE_LOCATION=pathlib.Path('~').expanduser().absolute() / ".IpHelper" / "cache.json"
MAC_INFO_LOCATION=pathlib.Path('~').expanduser().absolute() / ".IpHelper" / "mac_info.json"

_SECONDS_IN_MINUTE = 60
_SECONDS_IN_HOUR = 60 * _SECONDS_IN_MINUTE
_CACHE_TTL_HOURS = 48 
_CACHE_SEMAPHORE = Semaphore()
_UNKNOWN = 'unknown'

class IpHelper():
    """
    This class provides information about an IP address.  
    
    It interfaces with the free **ipinfo.io** site.  The ipinfo.io site
    requires a user token which is free.

    - See 'setting up user token' in docs for information on aquiring and setting up token.

    In order to minimize API calls and improve performance, a cache
    for IP and MAC information is created and stored locally.
      
    The local data will be refresed if it is > 48 hours old. It can also
    be manually refreshed/cleared from cache.
    
    The class provides the following information:

    For WAN IPs:

    - ip         : xxx.xxx.xxx.xxx
    - hostname   : hostname.domain
    - city       : Atlanta
    - region     : Georgia
    - country    : US
    - loc        : 33.7490,-84.3880
    - org        : XXXXXXXXXXXX
    - postal     : 30302
    - timezone   : America/New_York

    For LAN IPs:

    - ip         : xxx.xxx.xxx.xxx
    - hostname   : hostname.domain[or workgroup]
    - bogon      : True (identifies this as a local IP)
    - mac        : XX:XX:XX:XX:XX:XX
    - vendor     : Raspberry Pi Trading Ltd

    """
    # Class variables
    _cache_last_update_mtime: float = 0.0
    _cache: Dict[str, dict] = None
    _mac_info: Dict[str, dict] = None  # Manually maintained.
    _token_initialized: bool = False

    @classmethod
    @logger_wraps(level="TRACE")
    def __init__(cls, purge_stale_entries: bool = True, no_token:bool = False):
        if not no_token:
            cls._validate_token()        
        cls._load_cache(purge_stale_entries)

    @property
    def cache_dict(cls) -> dict:
        """
        The IP Info cache dictionary.
        """
        return IpHelper._cache
            
    @classmethod            
    @logger_wraps(level="TRACE")
    def clear_cache(cls, ip_address: str = None)-> int:
        """
        Clear the IP Info cache or cache entry.

        Keyword Arguments:
            ip_address -- IP address to be cleared (default: {None})
              If None, all entries will be removed.
        
        Returns:
            int -- Number of entries removed.
        """
        IP_INFO_CACHE_LOCATION.parent.mkdir(exist_ok=True)
        IP_INFO_CACHE_LOCATION.touch(exist_ok=True)
        cls._load_cache()
        initial_cache_len = len(IpHelper._cache)
        if ip_address:
            if ip_address in IpHelper._cache.keys():
                del IpHelper._cache[ip_address]
                _CACHE_SEMAPHORE.acquire(timeout=2.0)
                IP_INFO_CACHE_LOCATION.write_text(json.dumps(IpHelper._cache))
                _CACHE_SEMAPHORE.release()
                IpHelper._cache_last_update_mtime = IP_INFO_CACHE_LOCATION.stat().st_mtime
                LOGGER.debug(f'{ip_address} removed from cache')
            else:
                LOGGER.debug(f'{ip_address} does NOT exist in cache')
        else:
            _CACHE_SEMAPHORE.acquire(timeout=2.0)
            IP_INFO_CACHE_LOCATION.write_text("{}")
            _CACHE_SEMAPHORE.release()
            IpHelper._cache = {}
            IpHelper._cache_last_update_mtime = IP_INFO_CACHE_LOCATION.stat().st_mtime
        
        cur_len = len(IpHelper._cache)
        removed_cnt = initial_cache_len - cur_len
        LOGGER.debug(f'IpHelper Cache cleared.  {removed_cnt} entries removed. {cur_len} entries remaining.')
        return removed_cnt
    
    @classmethod
    def is_cached(cls, ip_address: str) -> bool:
        """
        Check if IP address is in cache.

        Arguments:
            ip_address -- Ip address to be checked.

        Returns:
            True if found else False.
        """
        cls._load_cache()  # Load cache if needed
        ip_info = IpHelper._cache.get(ip_address, None)
        if ip_info:
            return ip_info.get('_cached', False)
    
        return False
    
    @classmethod
    @logger_wraps(level="TRACE")
    def get_ip_info(cls, ip_address: str, 
                    include_unknown_fields: bool = False, 
                    include_private_fields: bool = False,
                    bypass_cache: bool = False) -> dict:
        """
        Get all information related to IP Address

        Arguments:
            ip_address: Target IP address.

        Keyword Arguments:
            bypass_cache: If true, force API call and refresh (default: {False}).

        Returns:
            JSON dictionary of all data related to target IP address.
        """
        urllib3.disable_warnings()
        cls._load_cache() 
        entry_updated = False
        if not nh.is_ipv4_address(ip_address):
            ip_info = {'ip': ip_address, "title": "Not IPv4 address", "error": "Only IPv4 addresses supported"}
            return ip_info

        LOGGER.debug(f'GET_IP_INFO for {ip_address}')   
        if bypass_cache:
            LOGGER.debug('- Bypassing cache lookup')
            ip_info = None
        else:
            ip_info = IpHelper._cache.get(ip_address, None)
            if ip_info and cls._stale(ip_address):
                LOGGER.debug(f'- {ip_address} stale, will re-fresh')
                ip_info = None

        if ip_info is None:
            LOGGER.debug(f'- {ip_address} NOT in cache or stale')
            ip_info = {'ip': ip_address}
            if not nh.is_ip_routable(ip_address):
                ip_info['bogon'] = True
            else:
                url=f'{BASE_URL}/{ip_address}?token={TOKEN}'
                try:
                    resp = requests.get(url, verify=False)
                    ip_info = resp.json()
                    entry_updated = True
                except Exception as ex:
                    resp = ""
                    LOGGER.debug(f'  ERROR- url: {url} ex: {repr(ex)}')
                    # ip_info = {'ip': ip_address, "title": "Error in API call", 'error': f'Exception: {url}- {repr(ex)}'}
                    ip_info['title'] = 'Error in API call'
                    ip_info['error'] = f'Exception: {url}- {repr(ex)}'

        if 'error' in ip_info.keys():
            LOGGER.warning(f'ERROR - url: {url}  resp: {ip_info}')
            return ip_info

        ip = ip_info['ip']
        mac = ip_info.get('mac', _UNKNOWN)
        if ip_info.get('hostname', None) is None:
            LOGGER.debug(f'- get hostname from ip {ip}')
            ip_info['hostname'] = nh.get_hostname_from_ip(ip)
            if _UNKNOWN not in ip_info['hostname']:        
                entry_updated = True

        if _UNKNOWN in mac:
            LOGGER.debug(f'- get mac address for ip {ip}')
            mac = nh.get_mac_address(ip)
            if mac is None:
                mac = _UNKNOWN
            else:
                ip_info['vendor'] = nh.get_vendor_from_mac(mac)
                entry_updated = True

        if _UNKNOWN in mac:
            LOGGER.debug(f'- Unable to determine MAC from ip {ip}')
        else:
            ip_info['mac'] = mac
            if _UNKNOWN in ip_info['hostname']:
                # Check the Mac Info cache
                hostname = IpHelper._mac_info.get(mac,{'hostname': _UNKNOWN})['hostname']
                LOGGER.debug(f'- {mac} - Lookup hostname based on mac_info cache. [{hostname}]')
                ip_info['hostname'] = f'-> {hostname}'
                if _UNKNOWN not in hostname:
                    entry_updated = True
            if _UNKNOWN in ip_info.get('vendor',_UNKNOWN):
                # Check the Mac Info cache
                vendor = IpHelper._mac_info.get(mac,{'vendor': _UNKNOWN})['vendor']
                LOGGER.debug(f'- {mac} - Lookup vendor based on mac_info cache. {vendor}')
                ip_info['vendor'] = f'-> {vendor}'
                if _UNKNOWN not in vendor:
                    entry_updated = True

        if entry_updated:
            ip_info["_cached"] = datetime.now().isoformat() 
            cls._load_cache() 
            _CACHE_SEMAPHORE.acquire(timeout=5.0)
            IpHelper._cache[ip_address] = ip_info
            # TODO: Performance, ONLY write new entry
            IP_INFO_CACHE_LOCATION.write_text(json.dumps(IpHelper._cache))
            _CACHE_SEMAPHORE.release()
            LOGGER.debug(f'SUCCESS: cache updated: {ip}/{ip_info["hostname"]}/{mac}')
            IpHelper._cache_last_update_mtime = IP_INFO_CACHE_LOCATION.stat().st_mtime
        
        if not include_private_fields or not include_unknown_fields:
            new_dict = {}
            for key, value in ip_info.items():
                if not include_private_fields and key.startswith('_'):
                    continue
                if not include_unknown_fields and value == _UNKNOWN:
                    continue
                new_dict[key] = value
            ip_info = new_dict

        return ip_info


    @classmethod
    def get_wan_ip_info(cls) -> Tuple[dict, int]:
        """
        Return the WAN (ie. Internet) address for this device.

        Returns:
            Tuple[dict, int]: ip_info entry and return code.
        """
        urllib3.disable_warnings()
        cls._validate_token()
        ip_info = None
        url=f'{BASE_URL}?token={TOKEN}'
        resp = ""
        rc = -1
        try:
            resp = requests.get(url, verify=False)
            ip_info = resp.json()
            rc = resp.status_code
        except Exception as ex:
            ip_info = {'error': f'Exception: {repr(ex)}'}

        if 'error' in ip_info:
            LOGGER.warning(f'ERROR- url: {url}  resp: {ip_info}')

        return (ip_info, rc)
        
    @classmethod        
    def find_in_cache(cls, search_token: str) -> List[str]:
        """
        Search each cache entry for supplied search string.

        Arguments:
            search_token: Text to search for.

        Returns:
            A list of IPs (str) whose data containes the search_token.
        """
        cls._load_cache() # update memory with any changes
        found_keys = []
        for key, entry in IpHelper._cache.items():
            for field_val in entry.values():
                if search_token.lower() in str(field_val).lower():
                    found_keys.append(key)
                    LOGGER.debug(f'- found {key} in {field_val}')
                    break

        found = len(found_keys)
        if found == 0:
            LOGGER.debug(f'- Search key [{search_token}] NOT found')
        else:
            for key in found_keys:
                cls.list_cache(key)
            LOGGER.debug(f'- {found} entries found.')

        return found_keys

    @classmethod
    def _load_mac_cache(cls):
        if not MAC_INFO_LOCATION.parent.exists():
            LOGGER.debug(f'Create directory {MAC_INFO_LOCATION.parent}')
            MAC_INFO_LOCATION.parent.mkdir(exist_ok=True)
        if not MAC_INFO_LOCATION.exists():
            LOGGER.debug(f'Create MAC Cache file: {MAC_INFO_LOCATION}')
            MAC_INFO_LOCATION.touch(exist_ok=True)
        buffer = MAC_INFO_LOCATION.read_text()
        if buffer == "":
            buffer = "{}"
        LOGGER.debug(f'Load MAC info from {MAC_INFO_LOCATION}')
        IpHelper._mac_info = json.loads(buffer)

    @classmethod
    def list_mac_cache(cls):
        LOGGER.info(f'MAC Cache [{MAC_INFO_LOCATION}]')
        LOGGER.info('')
        if len(cls._mac_info) == 0:
            LOGGER.warning('Sorry MAC cache is empty.')
        for key, value in cls._mac_info.items():
            LOGGER.success(f'=== {key} =============================================')
            for k,v in value.items():
                LOGGER.info(f'    {k:10} : {v}')
            LOGGER.info('')

    @classmethod
    def list_cache(cls, ip: str = None, show_all_fields: bool = True):
        """
        Print formatted contents of cache to console.

        Args:
            ip (str, optional): Target IP address. Defaults to None.
            show_all_fields (bool, optional): Include private (_) fields. Defaults to True.
        """        
        cls._load_cache() # Update memory with any changes
        if len(IpHelper._cache) == 0:
            LOGGER.warning('Sorry, cache is empty')
        elif ip is not None:
            entry = IpHelper._cache.get(ip, None)
            if entry:
                LOGGER.success(f'{console.cwrap(f"-- {ip} ---------------------------------------", style=TextStyle.BOLD)}')
                cls._print_entry(entry, show_all=show_all_fields)
            else:
                LOGGER.warning(f'{ip} does NOT exist in cache.')
        else:
            for key, entry in IpHelper._cache.items():
                LOGGER.success(f'{console.cwrap(f"-- {key} ---------------------------------------", style=TextStyle.BOLD)}')
                cls._print_entry(entry, show_all=show_all_fields)
                LOGGER.info('')
            LOGGER.info(f'IP Info cache contains {len(IpHelper._cache)} entries')

    @classmethod
    def _validate_token(cls) -> bool:
        LOGGER.debug('Token validation in progress...')
        rc = -1
        if not cls._token_initialized:
            if not IP_INFO_TOKEN_LOCATION.exists():
                LOGGER.error('Cached token NOT found.')
                cls._raise_token_error()            
            token_dict: dict = json.loads(IP_INFO_TOKEN_LOCATION.read_text())
            ih.TOKEN = token_dict.get('token', 'NOT VALID')
            cls._token_initialized = True
            ip_info, rc = cls.get_wan_ip_info()
            if rc != 200:
                LOGGER.error(f'Token check returns: {(ip_info)}')
                cls._raise_token_error()

        return True

    @classmethod
    def _raise_token_error(cls):
        LOGGER.warning('A token is required for IpHelper to function.')
        LOGGER.warning('Tokens are free, to get your token, go to "https://ipinfo.io/missingauth')
        LOGGER.warning('When you have a token run dt_set_iptoken to set the token for IpHelper.')
        raise RuntimeError('Invalid token for ipinfo.io.  See log and https://ipinfo.io/missingauth')

    @classmethod        
    def _load_cache(cls, purge_stale: bool = False):
        _CACHE_SEMAPHORE.acquire(timeout=15.0)
        if cls._refresh_required:
            IpHelper._cache = {}
            if not IP_INFO_CACHE_LOCATION.exists():
                cls.clear_cache()
            try:
                buffer = IP_INFO_CACHE_LOCATION.read_text()
                if buffer == "":
                    buffer = "{}"
                IpHelper._cache = json.loads(buffer)
                LOGGER.debug(f'{len(IpHelper._cache)} IpHelper cache entries loaded.')
                if purge_stale:
                    dropped = cls._drop_stale_entries()
                    LOGGER.debug(f'{dropped} IpHelper cache stale entries dropped.')
                IpHelper._cache_last_update_mtime = IP_INFO_CACHE_LOCATION.stat().st_mtime
            except Exception as ex:
                LOGGER.error(f'Unable to load IP Info Cache: {IP_INFO_CACHE_LOCATION}')
                LOGGER.warning(f'  {repr(ex)}')

        if IpHelper._mac_info is None:
            cls._load_mac_cache()

        _CACHE_SEMAPHORE.release()

    @property
    def _refresh_required(cls) -> bool:
        refresh = False
        if IP_INFO_CACHE_LOCATION.exists():
            last_update = IP_INFO_CACHE_LOCATION.stat().st_mtime
            if last_update > IpHelper._cache_last_update_mtime:
                # Cache has been updated
                LOGGER.debug('Cache refresh required!')
                refresh = True
        elif IpHelper._cache is None:
            LOGGER.debug('Cache is empty, refresh required!')
            refresh = True
        else:
            LOGGER.debug('Cache refresh is NOT required.')
        return refresh

    @classmethod
    def _stale(self, ip_address: str) -> bool:
        """Return true if cached entry is stale"""
        ip_info = IpHelper._cache.get(ip_address, None)
        if ip_info:
            cached_time = ip_info.get('_cached', None)
            if cached_time:
                created = parser.parse(cached_time)
                delta = datetime.now() - created
                age_in_hours = delta.total_seconds() / _SECONDS_IN_HOUR
                if age_in_hours > _CACHE_TTL_HOURS:
                    return True
            
        return False

    @classmethod
    def _age(cls, entry: dict) -> str:
        cached_time =  entry.get('_cached', None)
        age = 'N/A'
        if cached_time:
            created = parser.parse(cached_time)
            td = datetime.now() - created
            age = f'{td.days} days, {td.seconds//3600} hours, {(td.seconds//60)%60} minutes'
        return age

    @classmethod
    def _expires(cls, entry: dict) -> str:
        cached_time =  entry.get('_cached', None)
        expires = "Unknown"
        ttl = 'N/A'
        if cached_time:
            created = parser.parse(cached_time)
            expire_time = created + timedelta(hours=_CACHE_TTL_HOURS)
            ttl = expire_time - datetime.now()
            if ttl.seconds < 0:
                expires = "expired."
            else:
                expires = f'{ttl.days} days, {ttl.seconds//3600} hours, {(ttl.seconds//60)%60} minutes'
        return expires

    @classmethod
    def _drop_stale_entries(self) -> int:
        dropped = 0
        del_list = []
        for ip_address in IpHelper._cache.keys():
            # Create list of IPs to be removed
            if self._stale(ip_address):
                del_list.append(ip_address)
        for ip_address in del_list:
            # Remove identified IPs
            self.clear_cache(ip_address)
            dropped += 1
        return dropped 
    
    @classmethod
    def _print_entry(cls, entry: dict, show_all: bool = True):
        entry['_cache_age'] = cls._age(entry)
        entry['_expires'] = cls._expires(entry)
        entry['_stale'] = cls._stale(entry['ip'])
        for k,v in entry.items():
            if not show_all and k.startswith('_'):
                pass
            else:
                LOGGER.info(f'  {k:10} : {v}')

