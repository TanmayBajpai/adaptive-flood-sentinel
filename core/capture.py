import logging
from scapy.all import AsyncSniffer
from config import DEFAULT_INTERFACE

log = logging.getLogger(__name__)


class PacketCapture:
    def __init__(self, callback, interface: str = DEFAULT_INTERFACE):
        self._callback = callback
        self._interface = interface
        self._sniffer: AsyncSniffer | None = None

    def start(self):
        self._sniffer = AsyncSniffer(
            iface=self._interface,
            filter="ip and (tcp or udp or icmp)",
            prn=self._callback,
            store=False,
        )
        self._sniffer.start()
        log.info("Sniffer started on %s", self._interface)

    def stop(self):
        if self._sniffer and self._sniffer.running:
            self._sniffer.stop()
            log.info("Sniffer stopped")
