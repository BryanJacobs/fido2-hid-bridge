# FIDO2 HID Bridge

This repository contains sources for a Linux virtual USB-HID
FIDO2 device.

This device will receive FIDO2 CTAP2.1 commands, and forward them
to an attached PC/SC authenticator.

This allows using authenticators over PC/SC from applications
that only support USB-HID, such as Firefox; with this program running
you can use NFC authenticators or Smartcards.

## Setup

You'll need to install dependencies:

```shell
poetry install
```

And then build the redistributable:

```shell
poetry run package
```

This will produce a `dist/fido2-hid-bridge` that you can run. You might need to be root
or otherwise get access to raw HID devices (permissions on `/dev/uhid`):

```shell
sudo -E ./dist/fido2-hid-bridge
```

## Implementation Details

This uses the Linux kernel UHID device facility, and the `python-fido2` library.
It relays USB-HID packets to PC/SC.

Nothing more to it than that.
