import PyInstaller.__main__
from pathlib import Path
import os

this_dir = Path(__file__).parent.absolute()

def build():
    PyInstaller.__main__.run([
        os.path.join(this_dir, 'fido2-hid-bridge.spec')
    ])

