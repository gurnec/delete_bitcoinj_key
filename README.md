# delete\_bitcoinj\_key.pyw #

 * a simple Python script which deletes addresses and their private keys from bitcoinj-based wallets
 * supported on Windows and Linux
 * supports:
     * [MultiBit Classic](https://multibit.org/)
     * [Bitcoin Wallet for Android](https://play.google.com/store/apps/details?id=de.schildbach.wallet) encrypted backups
     * [KnC Wallet for Android](https://kncwallet.com/) encrypted backups
     * [Hive for OS X](https://hivewallet.com/#native)
 * refuses to delete BIP32 addresses/keys (created by MultiBit HD or Bitcoin Wallet for Android v4+)

## Installation ##

Just download the latest version from <https://github.com/gurnec/delete\_bitcoinj\_key/archive/master.zip> and unzip it to a location of your choice. There’s no installation procedure for the Python script itself, however there are additional requirements below depending on your operating system.

### Windows ###

 * The latest version of Python 2.7, either the 32-bit version or the 64-bit version. Currently this is the “Python 2.7.8 Windows Installer” for the 32-bit version, or the “Python 2.7.8 Windows X86-64 Installer” for the 64-bit version (which is preferable if you have a 64-bit version of Windows), both available here: <https://www.python.org/download/>
 * Google Protobuf for Python – choose one of the following two installation methods:
     * Automated installation: right-click on the included *install-windows-requirements.ps1* file and choose *Run with Powershell*. Automated installation typically only works with Windows Vista SP1 and higher (Win7, Win8), but it doesn't hurt to try with other versions of Windows.
     * Manual installation:
         1. Follow the instructions to [download and install Python pip](https://pip.pypa.io/en/latest/installing.html#install-pip).
         2. Open a command prompt (Start -> Run, type `cmd` and click OK).
         3. Type this at the command prompt: `C:\Python27\Scripts\pip install protobuf`, and then press the `Enter` key.

### Linux ###

 * Python 2.7.x – most distributions include this pre-installed.
 * Tkinter for Python – some distributions include this pre-installed, check your distribution’s package management system to see if this is available. It is often called “python-tk”.
 * Google Protobuf for Python - check your distribution’s package management system to see if this is available. It is often called “python-protobuf”.If not, try installing it by using PyPI, for example on Debian-like distributions:

        sudo apt-get install python-pip
        sudo pip install protobuf

Before running delete\_bitcoinj\_key.pyw for the first time, you must enable the execute permission on the file (right click -> Properties, or use `chmod` at the command line).

## How to Use ##

Simply double-click delete\_bitcoinj\_key.pyw and choose your wallet file in the file selection dialog.

## Credits ##

Third-party libraries distributed with delete\_bitcoinj\_key.pyw include:

 * aespython, please see [aespython/README.txt](aespython/README.txt) for
 more information

 * bitcoinj wallet protobuf, please see [wallet.proto](wallet.proto)
 for more information
