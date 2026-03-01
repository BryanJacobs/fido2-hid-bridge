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

## Requirements

- Python 3.12+
- Linux with UHID support (`/dev/uhid`)
- PC/SC daemon (`pcscd`) running
- For Python 3.14+: Uses `asyncio.run()` with signal handling and systemd notification support

## Running It

### Classic Linux Distributions

You'll need to install dependencies:

```shell
poetry install
```

And then launch the application in the created virtualenv. You might need to be root
or otherwise get access to raw HID devices (permissions on `/dev/uhid`):

```shell
sudo -E ./.venv/bin/fido2-hid-bridge
```

### Alternative installation (pipx)

You can also install the project via pipx:

```shell
pipx install git+https://github.com/BryanJacobs/fido2-hid-bridge
```

The argument `--system-site-packages` is advised when you already have installed python dependencies system wide (e.g. pyscard).

Assuming pipx is configured correctly simply launch:

```shell
sudo -E fido2-hid-bridge
```

## Immutable OS (Fedora Silverblue, Bazzite, etc.)

On immutable operating systems, the installation and service setup differs from classic distributions:

### Key Differences

| Aspect | Classic Distro | Immutable OS |
|--------|---------------|--------------|
| **System modification** | Can modify `/etc`, `/usr` directly | System is read-only |
| **Package installation** | System package manager | User-space tools, containers, or overlays |
| **Service location** | `/etc/systemd/system/` | `~/.config/systemd/user/` (user services) |
| **Device access** | Usually `input` group membership | Often handled via ACLs on `/dev/uhid` |
| **Python packages** | System or venv in `/opt` | User install (`pip --user`) or project directory |

### Installation on Immutable OS

1. **Clone the repository** to your home directory:
   ```shell
   cd ~
   git clone https://github.com/BryanJacobs/fido2-hid-bridge.git
   cd fido2-hid-bridge
   ```

2. **Install dependencies locally**:
   ```shell
   pip3 install --user sd-notify
   # OR add to pyproject.toml and use poetry if available
   ```

3. **Verify device access**:
   ```shell
   ls -la /dev/uhid
   getfacl /dev/uhid  # Check if your user has ACL permissions
   ```

### User Service for Immutable OS

Immutable OS work best with **user services** that don't require modifying system directories:

```shell
# Copy the user service file
mkdir -p ~/.config/systemd/user
cp fido2-hid-bridge-immutable.service ~/.config/systemd/user/fido2-hid-bridge.service

# Reload systemd user daemon
systemctl --user daemon-reload

# Enable and start the service
systemctl --user enable fido2-hid-bridge.service
systemctl --user start fido2-hid-bridge.service

# Check status
systemctl --user status fido2-hid-bridge.service
```

The provided `fido2-hid-bridge-immutable.service` includes:
- `Type=notify` - waits for the service to signal readiness
- Signal handling for graceful shutdown
- Automatic restart on failure
- Works with Python 3.14+ asyncio changes

## Systemd Service Files

Two service files are provided:

### `fido2-hid-bridge.service` (Classic/System-wide)

For traditional distributions where you can install to `/opt` or system locations:
- Runs as system service
- Requires root or specific user/group configuration
- Install to `/etc/systemd/system/`

### `fido2-hid-bridge-immutable.service` (Immutable OS)

For Fedora Silverblue, Bazzite, and other immutable distributions:
- Runs as user service
- No system directory modifications needed
- Uses `Type=notify` for proper lifecycle management
- Install to `~/.config/systemd/user/`

## Implementation Details

This uses the Linux kernel UHID device facility, and the `python-fido2` library.
It relays USB-HID packets to PC/SC.

Key components:
- `CTAPHIDDevice` - Virtual HID device using UHID
- `run_device()` - Async main loop with signal handling
- Signal handlers - Graceful shutdown on SIGTERM/SIGINT
- sd_notify - Systemd notification for service readiness

Nothing more to it than that.