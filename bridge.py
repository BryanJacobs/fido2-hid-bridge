#!/usr/bin/env python3

import asyncio
import logging
import random
import time
from enum import IntEnum
from typing import Tuple, Callable, Sequence, Dict

from fido2.pcsc import CtapPcscDevice, CtapDevice, CtapError
from fido2.hid import CTAPHID

import uhid

channels_to_devices = {}
channels_to_state = {}

BROADCAST_CHANNEL = bytes([0xFF, 0xFF, 0xFF, 0xFF])


class CommandType(IntEnum):
    PING = 0x01
    MSG = 0x03
    INIT = 0x06
    WINK = 0x08
    CBOR = 0x10
    CANCEL = 0x11
    KEEPALIVE = 0x3B
    ERROR = 0x3F


def parse_initial_packet(buffer: bytes) -> Tuple[bytes, int, CommandType, bytes]:
    """Parse an incoming initial packet."""
    logging.debug(f"Initial packet {buffer.hex()}")
    channel = buffer[1:5]
    cmd_byte = buffer[5] & 0x7F
    lc = (int(buffer[6]) << 8) + buffer[7]
    data = buffer[8:8+lc]
    cmd = CommandType(cmd_byte)
    return channel, lc, cmd, data


def is_initial_packet(buffer: bytes) -> bool:
    """Return true if packet is the start of a new sequence."""
    if buffer[5] & 0x80 == 0:
        return False
    return True


def assign_channel_id() -> Sequence[int]:
    """Create a new, random, channel ID."""
    return [random.randint(0, 255), random.randint(0, 255),
            random.randint(0, 255), random.randint(0, 255)]


def handle_init(channel: bytes, buffer: bytes) -> Sequence[int]:
    """Initialize or re-initialize a channel."""
    logging.debug(f"INIT on channel {channel}")

    new_channel = assign_channel_id()

    ctap = get_pcsc_device(new_channel)

    if channel == BROADCAST_CHANNEL:
        assert len(buffer) == 8
        return ([x for x in buffer] +
             new_channel +
             [
                0x02,  # protocol version
                0x01,  # device version major
                0x00,  # device version minor
                0x00,  # device version build/point
                ctap.capabilities,  # capabilities, from the underlying device
             ])
    else:
        handle_cancel(channel, b"")


def get_pcsc_device(channel_id: Sequence[int]) -> CtapDevice:
    """Grab a PC/SC device from python-fido2."""
    channel_key = get_channel_key(channel_id)

    if channel_key not in channels_to_devices:
        start_time = time.time()
        while time.time() < start_time + 10:
            devices = list(CtapPcscDevice.list_devices())
            if len(devices) == 0:
                time.sleep(0.1)
                continue
            device = devices[0]
            channels_to_devices[channel_key] = device
            return device
        # TODO: return timeout (0x05) here
        raise ValueError("No PC/SC device found within a reasonable time!")

    return channels_to_devices[channel_key]


def handle_cbor(channel: Sequence[int], buffer: bytes) -> Sequence[int]:
    """Handling an incoming CBOR command."""
    ctap = get_pcsc_device(channel)
    logging.debug(f"Sending CBOR to device {ctap}: {buffer}")
    try:
        res = ctap.call(cmd=CommandType.CBOR, data=buffer)
        return [x for x in res]
    except CtapError as e:
        logging.info(f"Got CTAP error response from device: {e}")
        return [e.code]


def handle_cancel(channel: Sequence[int], buffer: bytes) -> Sequence[int]:
    channel_key = get_channel_key(channel)
    if channel_key in channels_to_state:
        del channels_to_state[channel_key]
    if channel_key in channels_to_devices:
        del channels_to_devices[channel_key]
    return []


def handle_wink(channel: Sequence[int], buffer: bytes) -> Sequence[int]:
    """Do nothing; this can't be done over PC/SC."""
    return []


def handle_msg(channel: Sequence[int], buffer: bytes) -> Sequence[int]:
    """Process a U2F/CTAP1 message."""
    device = get_pcsc_device(channel)
    res = device.call(CTAPHID.MSG, buffer)
    return [x for x in res]


def handle_ping(channel: Sequence[int], buffer: bytes) -> Sequence[int]:
    """Handle an echo request."""
    return [x for x in buffer]


def handle_keepalive(channel: Sequence[int], buffer: bytes) -> Sequence[int]:
    """Placeholder: always returns that the device is processing."""
    return [1]


command_handlers: Dict[CommandType, Callable[[Sequence[int], bytes], Sequence[int]]] = {
    CommandType.MSG: handle_msg,
    CommandType.INIT: handle_init,
    CommandType.CBOR: handle_cbor,
    CommandType.CANCEL: handle_cancel,
    CommandType.WINK: handle_wink,
    CommandType.PING: handle_ping,
    CommandType.KEEPALIVE: handle_keepalive
}


def encode_response_packets(channel: Sequence[int], cmd: CommandType, data: Sequence[int]) -> Sequence[bytes]:
    """Chunk response data to be delivered over USB."""
    offset_start = 0
    seq = 0
    responses = []
    while offset_start < len(data):
        if seq == 0:
            capacity = 64 - 7
            chunk = data[offset_start:offset_start + capacity]
            data_len_upper = len(data) >> 8
            data_len_lower = len(data) % 256
            response = [x for x in channel] + [cmd | 0x80, data_len_upper, data_len_lower] + chunk
        else:
            capacity = 64 - 5
            chunk = data[offset_start:offset_start + capacity]
            response = [x for x in channel] + [seq - 1] + chunk

        while len(response) < 64:
            response.append(0x00)

        responses.append(bytes(response))
        offset_start += capacity
        seq += 1

    return responses


def get_channel_key(channel: Sequence[int]) -> str:
    return bytes(channel).hex()


def send_error(device: uhid.UHIDDevice, channel: Sequence[int], error_type: int) -> None:
    responses = encode_response_packets(channel, CommandType.ERROR, [error_type])
    for response in responses:
        device.send_input(response)


def finish_receiving(device: uhid.UHIDDevice, channel: Sequence[int]):
    """When finished receiving packets, act on them."""
    channel_key = get_channel_key(channel)
    cmd, _, _, data = channels_to_state[channel_key]
    handle_cancel(channel, b"")

    try:
        if cmd in command_handlers:
            response_body = command_handlers[cmd](channel, data)
            responses = encode_response_packets(channel, cmd, response_body)
        else:
            send_error(device, channel, 0x01)
            return
    except Exception as e:
        logging.warning(f"Error: {e}")
        send_error(device, channel, 0x7F)
        return

    for response in responses:
        device.send_input(response)


def parse_subsequent_packet(data: bytes) -> Tuple[Sequence[int], int, bytes]:
    """Parse a non-initial packet."""
    return data[1:5], data[5], bytes(data[6:])


def process_hid_message(device: uhid.UHIDDevice, buffer: Sequence[int], report_type: uhid._ReportType):
    """Core method: handle incoming HID messages."""
    recvd_bytes = bytes(buffer)
    logging.debug(f"GOT MESSAGE (type {report_type}): {recvd_bytes.hex()}")

    if is_initial_packet(recvd_bytes):
        channel, lc, cmd, data = parse_initial_packet(recvd_bytes)
        channel_key = get_channel_key(channel)
        logging.debug(f"CMD {cmd.name} CHANNEL {channel_key} len {lc} (recvd {len(data)}) data {data.hex()}")
        channels_to_state[channel_key] = cmd, lc, -1, data
        if lc == len(data):
            # Complete receive
            finish_receiving(device, channel)
    else:
        channel, seq, new_data = parse_subsequent_packet(recvd_bytes)
        channel_key = get_channel_key(channel)
        if channel_key not in channels_to_state:
            send_error(device, channel, 0x0B)
            return
        cmd, lc, prev_seq, existing_data = channels_to_state[channel_key]
        if seq != prev_seq + 1:
            handle_cancel(channel, b"")
            send_error(device, channel, 0x04)
            return
        remaining = lc - len(existing_data)
        data = bytes([x for x in existing_data] + [x for x in new_data[:remaining]])
        channels_to_state[channel_key] = cmd, lc, seq, data
        logging.debug(f"After receive, we have {len(data)} bytes out of {lc}")
        if lc == len(data):
            finish_receiving(device, channel)


def wrap_process_hid_with_device_obj(device: uhid.UHIDDevice) -> Callable:
    """Pass a UHIDDevice to the process_hid_message method."""
    return lambda x, y: process_hid_message(device, x, y)


async def run_device() -> None:
    """Asynchronously run the event loop."""
    device = uhid.UHIDDevice(
        vid=0x9999, pid=0x9999, name='FIDO2 Virtual USB Device', report_descriptor=[
            0x06, 0xD0, 0xF1,  # Usage Page (FIDO)
            0x09, 0x01,  # Usage (CTAPHID)
            0xa1, 0x01,  # Collection (Application)
                0x09, 0x20,  # Usage (Data In)
                    0x15, 0x00,  # Logical min (0)
                    0x26, 0xFF, 0x00,  # Logical max (255)
                    0x75, 0x08,  # Report Size (8)
                    0x95, 0x40,  # Report count (64 bytes per packet)
                    0x81, 0x02,  # Input(HID_Data | HID_Absolute | HID_Variable)
                0x09, 0x21,  # Usage (Data Out)
                    0x15, 0x00,  # Logical min (0)
                    0x26, 0xFF, 0x00,  # Logical max (255)
                    0x75, 0x08,  # Report Size (8)
                    0x95, 0x40,  # Report count (64 bytes per packet)
                    0x91, 0x02,  # Output(HID_Data | HID_Absolute | HID_Variable)
            0xc0,        # End Collection
        ],
        backend=uhid.AsyncioBlockingUHID,
        version=0,
        bus=uhid.Bus.USB
    )

    device.receive_output = wrap_process_hid_with_device_obj(device)

    await device.wait_for_start_asyncio()


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    loop = asyncio.get_event_loop()
    loop.run_until_complete(run_device())
    loop.run_forever()
