#!/usr/bin/env python3

import asyncio
import logging
import argparse
import signal

from fido2_hid_bridge.ctap_hid_device import CTAPHIDDevice


async def run_device() -> None:
    """Asynchronously run the event loop."""
    device = CTAPHIDDevice()

    await device.start()

    stop_event = asyncio.Event()

    def signal_handler(sig):
        logging.info(f"Received signal {sig.name}, shutting down...")
        stop_event.set()

    loop = asyncio.get_running_loop()

    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, lambda s=sig: signal_handler(s))
        except NotImplementedError:
            pass

    logging.info("FIDO2 HID Bridge started successfully")
    
    # Notify systemd, if possible
    try:
        import sd_notify
        notify = sd_notify.Notifier()
        if notify.enabled():
            notify.ready()
            logging.info("Notified systemd: service is ready")
    except ImportError:
        pass

    await stop_event.wait()

    logging.info("FIDO2 HID Bridge shutting down...")


def main():
    parser = argparse.ArgumentParser(description='Relay USB-HID packets to PC/SC', allow_abbrev=False)
    parser.add_argument('--debug', action='store_const', const=logging.DEBUG, default=logging.INFO, 
                        help='Enable debug messages')
    args = parser.parse_args()
    logging.basicConfig(level=args.debug)
    
    asyncio.run(run_device())

