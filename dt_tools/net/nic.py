"""
Module to assist in identifying NIC cards and their properties.

- Methods identifies a list of installed Adapter names.
- WiFiAdapterInfo class provides attributes of the WiFi Adapters.

"""
from dataclasses import dataclass
from typing import List

import dt_tools.logger.logging_helper as lh
from dt_tools.os.os_helper import OSHelper
from loguru import logger as LOGGER

from dt_tools.net.wifi_scanner import _CONSTANTS, ScannerBase


# ====================================================================================================
def identify_wifi_adapters() -> List[str]:
    """
    Return list of installed **Wifi** adapter names.

    Returns:
        List[str]: List of adapter names if found else empty list.
    """
    adapters: List[str] = []
    if OSHelper.is_linux():
        cmd_output, ret_cd = ScannerBase._execute_process(_CONSTANTS.IWCONFIG, show_feedback=False)
        if ret_cd == 0:
            for line in cmd_output:
                if 'ESSID' in line:
                    adapters.append(line.split()[0].strip())
    elif OSHelper.is_windows():
        cmd_output, ret_cd = ScannerBase._execute_process('netsh wlan show interfaces', show_feedback=False)
        if ret_cd == 0:
            for line in cmd_output:
                if line.strip().startswith('Name'):
                    adapters.append(line.split(':')[1].strip())

    if len(adapters) > 0:
        return adapters
    
    return None

def identify_all_adapters() -> List[str]:
    """
    Return list of installed adapter names.

    Returns:
        List[str]: List of adapter names if found else empty list.
    """
    # TODO: Build interface list
    adapters = []
    if OSHelper.is_linux():
        lines, _ = ScannerBase._execute_process(f'{_CONSTANTS.IFCONFIG} -a', False)
        for line in lines:
             if 'flags' in line:
                 iface_name = line.split(':',1)[0].strip()
                 adapters.append(iface_name)
                 
    elif OSHelper.is_windows():
        lines, _ = ScannerBase._execute_process('ipconfig /all', False)
        for line in lines:
            if 'adapter' in line and '* ' not in line:
                iface_name = line.split('adapter')[1].replace(':','').strip()
                adapters.append(iface_name)
    else:   
        pass # Unsupported OS

    LOGGER.debug(f'- adapters: {", ".join(adapters)}')
    return adapters


# == Adapter Object ==========================================================================================================   
@dataclass 
class WifiAdapterInfo:
    """
    WiFi NIC Adapter information.

    Raises:
        NameError: Unable to identify WiFi adapter with specified name.
        RuntimeError: Unsupported operating system (Only Windows and Linux supported).

    """
    name: str                   #: NIC Adapter Name
    desc: str = ''              #: NIC Description
    mac: str = ''               #: NIC MAC Address
    connected: bool = False     #: True if NIC is connected
    SSID: str = 'Not Associated' #: Name of WiFi Network
    BSSID: str = ''             #: Unique ID for Access point
    radio_type: str = ''        #: IEEE 802.11 standard (b, ax, ac, n, g, ...)
    Authentication: str = ''    #: WiFi authentication method
    cipher: str = ''            #: Cipher used for encryption
    band: str = ''              #: 2.4GHz or 5GHz
    channel: int = -1           #: Broadcast channel number
    receive_rate: float = -1.0  #: Adapter receive rate
    transmit_rate: float = -1.0 #: Adapter send rate
    signal: int = -1            #: Adapter signal strength

    def __post_init__(self):
        if OSHelper.is_windows():
            if not self._get_windows_wifi_adapter():
                raise NameError(f'Unable to identify wifi adapter "{self.name}"')
        elif OSHelper.is_linux():
            if not self._get_linux_wifi_adapter():
                raise NameError(f'Unable to identify wifi adapter "{self.name}"')
        else:
            raise RuntimeError('Unsupported OS.')
        
    def _get_linux_wifi_adapter(self) -> bool:
        # iw wlan0 info = channel, mhz, mac
        iwconfig_output, _ = ScannerBase._execute_process('iwconfig', show_feedback=False)
        adapter_found = False
        for line in iwconfig_output:
            line = line.strip()
            if 'ESSID' in line:
                if adapter_found:
                    # done, bail
                    break
                adapter_found = True
                self.SSID = line.split('ESSID:')[1].strip()
                continue
            if "Frequency:" in line:
                token = line.split('Frequency:')[1].strip()
                if token.startswith('2'):
                    self.radio_type = "2.4 GHz"
                elif token.startswith('5'):
                    self.radio_type = '5 GHz'
            if "Access Point:" in line:
                self.BSSID = line.split('Access Point:')[1].strip()
            if "Bit Rate=" in line:
                self.receive_rate = line.split('Bit Rate=')[1].split()[0]
                self.transmit_rate = self.receive_rate
            if "Link Quality=" in line:
                txt_sig = line.split('=')[1].split()[0]
                signals = txt_sig.split('/')
                self.signal = int(int(signals[0]) / int(signals[1]) * 100)
            # self.Authentication
            # self.channel
            # self.band
            # self.cipher
            # self.connected
            # self.desc
            # self.mac
            # self.radio_type

        return adapter_found
    
    def _get_windows_wifi_adapter(self) -> bool:
        netsh_output, _ = ScannerBase._execute_process('netsh wlan show interfaces', show_feedback=False)
        adapter_found = self._process_netsh_adapter_output(netsh_output)
        # if not adapter_found:
        #     netsh_output, _ = ScannerBase._execute_process('netsh lan show interfaces', show_feedback=False)
        #     adapter_found = self._process_netsh_adapter_output(netsh_output)

        return adapter_found
    
    def _process_netsh_adapter_output(self, netsh_output: List[str]) -> bool:
        name_found = False
        adapter_found = False
        for line in netsh_output:
            line = line.strip()
            value = '' if len(line.split(':',1)) == 1 else line.split(':',1)[1].strip()
            if line.startswith('Name'):
                if adapter_found:
                    # Fully processed target name, quit
                    break
                elif self.name == value:
                    adapter_found = True
                    name_found = True
                    continue
                else:
                    # Wrong adapter, keep going
                    continue
            if not name_found:
                continue
            # value = '' if len(line.split(':',1)) == 1 else line.split(':',1)[1].strip()
            if line.startswith('Description'):
                self.desc = value
                continue
            if line.startswith('Physical address'):
                self.mac = value
                continue
            if line.startswith('State'):
                self.connected = value == 'connected'
                continue
            if line.startswith('SSID'):
                self.SSID = value
                continue
            if line.startswith('BSSID'):
                self.BSSID = value
                continue
            if line.startswith('Radio type'):
                self.radio_type = value
                continue
            if line.startswith('Authentication'):
                self.Authentication = value
                continue
            if line.startswith('Cipher'):
                self.cipher = value
                continue
            if line.startswith('Channel'):
                self.channel = int(value)
                continue
            if line.startswith('Band'):
                self.band = value
                continue
            if line.startswith('Receive rate'):
                self.receive_rate = float(value)
                continue
            if line.startswith('Transmit rate'):
                self.transmit_rate = float(value)
                continue
            if line.startswith('Signal'):
                self.signal = int(value.replace('%',''))
                continue

        return adapter_found
    



if __name__ == "__main__":
    lh.configure_logger(log_level="INFO", log_format=lh.DEFAULT_CONSOLE_LOGFMT)
    import json  # noqa: F401

    adapter_list = identify_all_adapters()
    LOGGER.info (f'All  Adapters: {adapter_list}')
    wifi_adapter_list = identify_wifi_adapters()
    LOGGER.info(f'WiFi Adapters: {wifi_adapter_list}')

    for adapter_name in adapter_list:
        try:
            LOGGER.info('')
            LOGGER.info(f"Getting info for '{adapter_name}'")
            adapter = WifiAdapterInfo(adapter_name)
            LOGGER.success(f'adapter: {adapter}')
        except NameError  as ne:
            LOGGER.error(f'- {repr(ne)}.  Are you sure its a WiFi adapter?')

