#!/usr/bin/env python3

import asyncio
import logging
import argparse

from fido2_hid_bridge.ctap_hid_device import CTAPHIDDevice


async def run_device() -> None:
    """Asynchronously run the event loop."""
    device = CTAPHIDDevice()

    await device.start()


def main():
    parser = argparse.ArgumentParser(description='Relay USB-HID packets to PC/SC', allow_abbrev=False)
    parser.add_argument('--debug', action='store_const', const=logging.DEBUG, default=logging.INFO, 
                        help='Enable debug messages')
    args = parser.parse_args()
    logging.basicConfig(level=args.debug)
    loop = asyncio.get_event_loop()
    loop.run_until_complete(run_device())
    loop.run_forever()

