"""
Wake-on-LAN utility class

This class can be used to send WOL packet to target machines via IP or Hostname.

The wol function can optionally wait for the host to 'wake-up' and provide a
status message indicating success or failure.

Raises:
    ex: Invalid MAC address
    ValueError: When MAC address does not conform to expected format

Example::

    from dt_tools.net.wol import WOL

    wol = WOL()
    wol.send_wol_to_host(myTargetHost, wait_secs=60)
    print(wol.status_message)



"""
import socket
import struct
import time

import dt_tools.logger.logging_helper as lh
from dt_tools.console.spinner import Spinner, SpinnerType
from dt_tools.os.os_helper import OSHelper
from loguru import logger as LOGGER

import dt_tools.net.net_helper as nh

# from dt_tools.console.progress_bar import ProgressBar

_LOGLEVEL="INFO"

class WOL():
    '''
    Send WOL request to target device via MAC address, hostname or IP
    and optionally, wait for device to come online.

    Example::

        from dt_tools.net.wol import WOL

        wol = WOL()
        wol.send_wol_to_host('somehost', wait_secs=20)
        print(wol.status_message)
    '''
    _BROADCAST_IP = "255.255.255.255"
    _DEFAULT_PORT = 9
    
    _status_message: str = ''

    def __init__(cls):
        LOGGER.debug('WOL class created.')

    @property
    def status_message(cls) -> str:
        """Return WOL request status message"""
        return cls._status_message
    
    def send_wol_to_host(cls, host_name: str, wait_secs: int = 0) -> bool:
        """
        Send WOL to target hostname or IP

        Args:
            host_name (str): host name (or IP Address).
            wait_secs (int, optional): Number of secs to wait for host to come online. Defaults to 0.

        Returns:
            bool: True if wol packet successfully sent, else False
        """
        LOGGER.debug(f'send_wol_via_host("{host_name}")')
        return_status = False
        try:
            if nh.is_valid_ipaddress(host_name):
                _ip = host_name
                _host = nh.get_hostname_from_ip(_ip)
            else:
                _ip = nh.get_ip_from_hostname(host_name)
                _host = host_name

            if not nh.is_valid_host(host_name):
                host_type = 'ip address' if _host == nh._UNKNOWN else 'hostname'
                cls._status_message = f'Invalid {host_type} [{host_name}]'
            else:
                mac = nh.get_mac_address(_ip)
                if mac:
                    return cls.send_wol_via_mac(mac, wait_secs=wait_secs, ip=_ip)  
                cls._status_message = f"Unable to determine MAC address for {host_name}"
                LOGGER.debug(cls._status_message)
        except Exception as ex:
            LOGGER.exception(repr(ex))
            cls._status_message = f'Unable to send wol packet to {hostname} - {repr(ex)}.'

        return return_status
    
    # === Private functions ==============================================================
    def send_wol_via_mac(cls, mac: str, wait_secs: int = 0, ip: str = None) -> bool:
        LOGGER.debug(f'send_wol_via_mac("{mac}")')
        try:
            mac_address = nh.unformat_mac(mac)
        except ValueError as ve:
            cls._status_message = f'Incorrectly formatted MAC address: {mac}'
            LOGGER.error(f'{cls._status_message} - {repr(ve)}')
            return False

        # Pad the synchronization stream.
        LOGGER.debug(f'pad the mac address: {mac_address}')
        data = b"FFFFFFFFFFFF" + (mac_address * 20).encode()
        send_data = b""
        LOGGER.debug(f'padded  mac address: {data}')
        # Split up the hex values and pack.
        for i in range(0, len(data), 2):
            send_data += struct.pack("B", int(data[i : i + 2], 16))

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        LOGGER.debug(f'Sending WOL to {mac}')
        try:
            sock.sendto(send_data, ("<broadcast>", 9))  # 7
        except Exception as ex:
            LOGGER.error(f'Error sending WOL: {repr(ex)}')
        finally:
            sock.close()

        if wait_secs == 0:
            cls._status_message = "Packet sent."
            return True

        if ip is None:
            try:
                ip = nh.get_ip_from_mac(mac)
            except ValueError as ve:
                LOGGER.error({ve})

            if ip is None:
                LOGGER.debug(f'ERROR: Unable to resolve IP from MAC {mac}')
                cls._status_message = "Packet sent, could not resolve IP, not waiting for device to come online."
                return True

        is_online = cls._wait_for_device_to_come_online(ip, wait_secs)
        hostname = nh.get_hostname_from_ip(ip) if is_online else None
        if hostname:
            LOGGER.debug(f'Host: {hostname} | MAC: {mac} | {ip} - is online {is_online}')
        else:
            LOGGER.debug(f'MAC: {mac} | {ip} - is online {is_online}')
        
        cls._status_message = "Packet sent.  Host online." if is_online else f"Packet sent. Host NOT online after waiting {wait_secs} seconds."
        return is_online

    def _create_magic_packet(cls, mac: str) -> bytes:
        if len(mac) == 17:
            sep = mac[2]
            mac = mac.replace(sep, "")
        elif len(mac) != 12:
            raise ValueError("Incorrect MAC address format")

        return bytes.fromhex("F" * 12 + mac * 16)
                    
    def _wait_for_device_to_come_online(cls, ip: str, wait_secs: int) -> bool:
        is_online = nh.ping(ip)
        valid_spinner = False
        if not is_online:
            if OSHelper.is_running_in_foreground():
                try:
                    spinner = Spinner(caption=f'- Waiting for {ip} to come online', spinner=SpinnerType.DOTS, show_elapsed=True)
                    spinner.start_spinner()
                    valid_spinner = True
                except Exception:
                    # Could not create spinner
                    pass
            LOGGER.debug(f'Waiting for {wait_secs} seconds for device to come online.')
            start = time.time()
            elapsed = 0
            while elapsed < wait_secs and not is_online:
                time.sleep(1)
                is_online = nh.ping(ip)
                elapsed = time.time() - start
        if valid_spinner:
            spinner.stop_spinner()

        return is_online


if __name__ == "__main__":
    lh.configure_logger(log_level="TRACE", log_format=lh.DEFAULT_DEBUG_LOGFMT)
    wol = WOL()
    hostnames = ['nirvana', 'badhost']
    for hostname in hostnames:
        LOGGER.info('')
        LOGGER.info(f'Sending WOL to {hostname}...')
        try:
            if wol.send_wol_to_host(hostname, wait_secs=20):
                LOGGER.success(f'  {wol.status_message}')
            else:
                LOGGER.warning(f'  {wol.status_message}')
        except Exception as ex:
            LOGGER.error(repr(ex))
