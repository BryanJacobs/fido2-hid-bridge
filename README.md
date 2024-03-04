# FIDO2 HID Bridge

This repository contains sources for a Linux virtual USB-HID
FIDO2 device.

This device will receive FIDO2 CTAP2.1 commands, and forward them
to an attached PC/SC authenticator.

This allows using authenticators over PC/SC from applications
that only support USB-HID, such as Firefox; with this program running
you can use NFC authenticators or Smartcards.

Note that this is a very early-stage application, but it does work with
Chrome and Firefox.

## Running It

You'll need to install dependencies:

```shell
poetry install
```

And then launch the application in the created virtualenv. You might need to be root
or otherwise get access to raw HID devices (permissions on `/dev/uhid`):

```shell
sudo -E ./.venv/bin/fido2-hid-bridge
```

## Alternative installation

You can also install the project via pipx

```shell
pipx install git+https://github.com/BryanJacobs/fido2-hid-bridge
```

The argument '--system-site-packages' is advised when you already have installed python dependecies system wide (e.g. pyscard).

Assuming pipx is configured correctly simply lauch:

```shell
sudo -E fido2-hid-bridge
```

## Implementation Details

This uses the Linux kernel UHID device facility, and the `python-fido2` library.
It relays USB-HID packets to PC/SC.

Nothing more to it than that.
