#!/usr/bin/env python3

import asyncio
import logging

from fido2_hid_bridge.ctap_hid_device import CTAPHIDDevice


async def run_device() -> None:
    """Asynchronously run the event loop."""
    device = CTAPHIDDevice()

    await device.start()


def main():
    logging.basicConfig(level=logging.DEBUG)
    loop = asyncio.get_event_loop()
    loop.run_until_complete(run_device())
    loop.run_forever()

if __name__ == '__main__':
    main()
