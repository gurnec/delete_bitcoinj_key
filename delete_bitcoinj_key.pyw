#!/usr/bin/python

# delete_bitcoinj_key.py
# Copyright (C) 2014 Christopher Gurnee
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
# notice, this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright
# notice, this list of conditions and the following disclaimer in the
# documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

# If you find this program helpful, please consider a small
# donation to the developer at the following Bitcoin address:
#
#           1Lj3kXWTuYaRxvLndi6VZKj8AYa3KP929B
#
#                      Thank You!

__version__ =  '0.3.0'

from warnings import warn
import hashlib, sys, getpass, os, os.path
import aespython.key_expander, aespython.aes_cipher, aespython.cbc_mode
import wallet_pb2
import Tkinter as tk
import ttk, tkFileDialog, tkSimpleDialog, tkMessageBox

sha256 = hashlib.sha256
md5    = hashlib.md5


dec_digit_to_base58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
base58_digit_to_dec = { b58:dec for dec,b58 in enumerate(dec_digit_to_base58) }

def hash160_to_base58check(hash160_bytes, version_byte):
    """convert from a hash160 public address to its base58check form

    :param hash160_bytes: ripemd160(sha256()) hash of the pubkey or redeemScript
    :type hash160_bytes: str
    :param version_byte: address's version byte
    :type version_byte: str
    :return: check-code appended base58-encoded address
    :rtype: str
    """
    assert len(hash160_bytes) == 20
    assert len(version_byte)  == 1

    all_bytes =  version_byte + hash160_bytes
    all_bytes += sha256(sha256(all_bytes).digest()).digest()[:4]

    int_rep = long(all_bytes.encode('hex'), 16)
    base58_rep = ''
    while int_rep:
        int_rep, remainder = divmod(int_rep, 58)
        base58_rep += dec_digit_to_base58[remainder]

    zero_count = next(zeros for zeros,byte in enumerate(all_bytes) if byte != '\0')
    return '1' * zero_count + "".join(reversed(base58_rep))

def base58check_to_hash160(base58_rep):
    """convert from a base58check address to its hash160 form

    :param base58_rep: check-code appended base58-encoded address
    :type base58_rep: str
    :return: ripemd160(sha256()) hash of the pubkey/redeemScript and the version byte
    :rtype: (str, str)
    """
    base58_stripped = base58_rep.lstrip('1')

    int_rep = 0
    for base58_digit in base58_stripped:
        int_rep *= 58
        int_rep += base58_digit_to_dec[base58_digit]

    # Convert hex to raw bytes (they ugly Python 2 way)
    hex_rep = hex(int_rep)[2:]  # The [2:] skips the leading '0x'.
    if hex_rep.endswith('L'):   # Almost always true, this
        hex_rep = hex_rep[:-1]  # removes the 'L' appended to longs.
    if len(hex_rep) % 2 == 1:    # The hex decoder below requires
        hex_rep = '0' + hex_rep  # exactly 2 chars per byte.
    all_bytes  = hex_rep.decode('hex').rjust(1 + 20 + 4, '\0')

    zero_count = next(zeros for zeros,byte in enumerate(all_bytes) if byte != '\0')
    if len(base58_rep) - len(base58_stripped) != zero_count:
        warn('prepended zeros mismatch for address ' + base58_rep)

    version_byte, hash160_bytes, check_bytes = all_bytes[:1], all_bytes[1:-4], all_bytes[-4:]
    if sha256(sha256(version_byte + hash160_bytes).digest()).digest()[:4] != check_bytes:
        raise ValueError("base58 check code mismatch for address '{}'".format(base58_rep))

    return hash160_bytes, version_byte

def pubkey_to_hash160(pubkey_bytes):
    """convert from a raw public key or redeemScript to its a hash160 form

    :param pubkey_bytes: SEC 1 EllipticCurvePoint OctetString or redeemScript
    :type pubkey_bytes: str
    :return: ripemd160(sha256(pubkey_bytes))
    :rtype: str
    """
    assert len(pubkey_bytes) == 33 or len(pubkey_bytes) == 65
    return hashlib.new('ripemd160', sha256(pubkey_bytes).digest()).digest()


def is_wallet_encrypted(wallet_file):
    """determine if a bitcoinj wallet file is encrypted (OpenSSL style)

    :param wallet_file: an open bitcoinj wallet file
    :type wallet_file: file
    :return: True if wallet_file is encrypted else False
    :rtype: bool
    """
    wallet_file.seek(0)
    magic_bytes = wallet_file.read(12)
    try:
        return magic_bytes.decode('base64').startswith(b"Salted__")
    except Exception:
        return False


key_expander = aespython.key_expander.KeyExpander(256)

def load_wallet(wallet_file, password = None):
    """load and optionally decrypt (OpenSSL style) a bitcoinj wallet file

    :param wallet_file: an open bitcoinj wallet file
    :type wallet_file: file
    :param password: password (required iff wallet_file is encrypted)
    :type password: unicode
    :return: the Wallet protobuf message
    :rtype: wallet_pb2.Wallet
    """

    wallet_file.seek(0)

    if password is None:
        plaintext = wallet_file.read()

    else:
        # Read in and decode the base64-encoded lines
        try:
            ciphertext = wallet_file.read().decode('base64')
        except IOError:
            raise
        except Exception as e:
            raise ValueError('not an encrypted wallet backup: ' + str(e))
        if not ciphertext.startswith('Salted__'):
            raise ValueError('not an encrypted wallet backup: file magic not found')
        assert len(ciphertext) % 16 == 0

        # Derive the encryption key and IV
        salted_pw = password.encode('UTF-8') + ciphertext[8:16]
        key1 = md5(salted_pw).digest()
        key2 = md5(key1 + salted_pw).digest()
        iv   = md5(key2 + salted_pw).digest()

        # Decrypt the wallet
        block_cipher  = aespython.aes_cipher.AESCipher( key_expander.expand(map(ord, key1 + key2)) )
        stream_cipher = aespython.cbc_mode.CBCMode(block_cipher, 16)
        stream_cipher.set_iv(bytearray(iv))
        plaintext = bytearray()
        for i in xrange(16, len(ciphertext), 16):
            plaintext.extend( stream_cipher.decrypt_block(map(ord, ciphertext[i:i+16])) )
        del ciphertext
        padding_len = plaintext[-1]
        # check for PKCS7 padding
        if not (1 <= padding_len <= 16 and plaintext.endswith(chr(padding_len) * padding_len)):
            raise ValueError('incorrect password')
        plaintext = str(plaintext[:-padding_len])

    # Parse the wallet protobuf
    pb_wallet = wallet_pb2.Wallet()
    try:
        pb_wallet.ParseFromString(plaintext)
    except Exception as e:
        raise ValueError('not a wallet file: ' + str(e))
    return pb_wallet


def save_wallet(pb_wallet, wallet_file, password = None):
    """

    :param pb_wallet: a Wallet protobuf message
    :type pb_wallet: wallet_pb2.Wallet
    :param wallet_file: a file opened for writing
    :type wallet_file: file
    :param password: UTF-8 password if encryption is desired, else None
    :type password: str or NoneType
    """

    # Serialize the wallet protobuf
    plaintext = pb_wallet.SerializeToString()

    if password is None:
        wallet_file.write(plaintext)

    else:
        # Derive a new encryption key and IV
        salt = os.urandom(8)
        salted_pw = password + salt
        key1 = md5(salted_pw).digest()
        key2 = md5(key1 + salted_pw).digest()
        iv   = md5(key2 + salted_pw).digest()

        # Encrypt the wallet
        block_cipher  = aespython.aes_cipher.AESCipher( key_expander.expand(map(ord, key1 + key2)) )
        stream_cipher = aespython.cbc_mode.CBCMode(block_cipher, 16)
        stream_cipher.set_iv(bytearray(iv))
        padding_len = 16 - len(plaintext) % 16
        plaintext += chr(padding_len) * padding_len  # append the PKCS7 padding
        ciphertext = bytearray('Salted__' + salt)  # start with the openssl magic and salt
        for i in xrange(0, len(plaintext), 16):
            ciphertext.extend( stream_cipher.encrypt_block(map(ord, plaintext[i:i+16])) )
        del plaintext
        ciphertext = str(ciphertext)

        # Encode and save base64 lines (each at most 76 characters long after encoding)
        line_len = 76 // 4 * 3  # 57
        for i in xrange(0, len(ciphertext), line_len):
            wallet_file.write(ciphertext[i:i+line_len].encode('base64'))  # includes the trailing '\n'


def delete_keys(pb_wallet, hash160_bytes_list):
    """deletes one or more addresses/keys from a bitcoinj wallet

    :param pb_wallet: a Wallet protobuf message
    :type pb_wallet: wallet_pb2.Wallet
    :param hash160_bytes_list: a list of hash160 form addresses whose keys to delete
    :type hash160_bytes_list: list of [str]
    :return: the count of addresses/keys deleted
    :rtype: int
    """
    hash160_bytes_set = set(hash160_bytes_list)
    found = i = 0
    while i < len(pb_wallet.key):
        key = pb_wallet.key[i]
        if key.HasField("public_key"):
            hash160 = pubkey_to_hash160(key.public_key)
            if hash160 in hash160_bytes_set:
                if key.type == wallet_pb2.Key.ORIGINAL or key.type == wallet_pb2.Key.ENCRYPTED_SCRYPT_AES:
                    del pb_wallet.key[i]
                    found += 1
                    continue
                else:
                    raise ValueError("found but can't delete BIP32 key for " + hash160_to_base58check(hash160, '\0'))
        i += 1
    return found


def run_from_command_line():
    assert len(sys.argv) > 1
    if any(arg.startswith('-') for arg in sys.argv[1:]):
        sys.exit('usage: delete_bitcoinj_key.py encrypted-wallet-backup [bitcoin-address-1 bitcoin-address-2 ...]')

    # Make sure the output file doesn't already exist
    wallet_filename = sys.argv[1]
    dot_pos = wallet_filename.rfind('.')
    if dot_pos == -1:
        dot_pos = len(wallet_filename)
    new_wallet_filename = wallet_filename[:dot_pos] + "-key-deleted" + wallet_filename[dot_pos:]
    if os.path.exists(new_wallet_filename):
        sys.exit("output file '{}' already exists, won't overwrite".format(new_wallet_filename))

    if len(sys.argv) == 2:
        base58check_list = [ raw_input("Please enter a single address whose key you'd like to delete: ") ]
    else:
        base58check_list = sys.argv[2:]

    hash160_bytes_list = [ base58check_to_hash160(a)[0] for a in base58check_list ]  # ignore the version_byte

    wallet = None
    password = None
    with open(wallet_filename, 'rb') as wallet_file:
        is_encrypted = is_wallet_encrypted(wallet_file)
        while True:
            if is_encrypted:
                encoding = sys.stdin.encoding or ''
                if 'utf' not in encoding.lower():
                    warn('terminal does not support UTF; passwords with non-ASCII chars might not work')
                # Replace getpass.getpass with raw_input if there's trouble reading non-ASCII characters
                password = getpass.getpass('Wallet backup password: ')
                if isinstance(password, str) and encoding:
                    password = password.decode(encoding)  # convert from terminal's encoding to unicode
            try:
                wallet = load_wallet(wallet_file, password)
                break
            except ValueError as e:
                if e.args[0] == 'incorrect password':
                    print e
                else:
                    sys.exit(e)

    found = delete_keys(wallet, hash160_bytes_list)
    if not found:
        sys.exit('no matching key(s) found')

    assert not os.path.exists(new_wallet_filename)
    with open(new_wallet_filename, 'wb') as new_wallet_file:
        save_wallet(wallet, new_wallet_file, password)

    print 'Found and removed', found, 'key' if found == 1 else 'keys'


class DeleteBitcoinjKey(object):

    def __init__(self, root):

        self.root          = root   # need to call .destroy() on this later.
        self.wallet        = None   # the wallet protobuf message object.
        self.wallet_dir    = None   # the last directory used by load or save.
        self.is_dirty      = False  # are there any unsaved changes?
        self.label         = ttk.Label()
        frame              = ttk.Frame()
        self.address_list  = tk.Listbox(frame, selectmode=tk.EXTENDED)
        scrollbar          = ttk.Scrollbar(frame)
        load_wallet_button = ttk.Button(text='Load Wallet Backup...', command=self.load_wallet_clicked)
        delete_keys_button = ttk.Button(text='Delete Selected Keys',  command=self.delete_keys_clicked)
        save_wallet_button = ttk.Button(text='Save Wallet Backup...', command=self.save_wallet_clicked)
        size_grip          = ttk.Sizegrip()

        padding = 8
        self.label        .pack()
        frame             .pack(fill=tk.BOTH, expand=True, padx=padding, pady=padding)
        self.address_list .pack(side=tk.LEFT,  fill=tk.BOTH, expand=True)
        scrollbar         .pack(side=tk.RIGHT, fill=tk.Y)
        load_wallet_button.pack(side=tk.LEFT,  padx=padding, pady=padding, ipadx=padding//2, ipady=padding//2)
        delete_keys_button.pack(side=tk.LEFT,  padx=padding, pady=padding, ipadx=padding//2, ipady=padding//2)
        size_grip         .pack(side=tk.RIGHT, anchor=tk.SW)
        save_wallet_button.pack(side=tk.RIGHT, padx=padding, pady=padding, ipadx=padding//2, ipady=padding//2)
        self.address_list.config(yscrollcommand=scrollbar.set)
        scrollbar        .config(command=self.address_list.yview)
        root.protocol("WM_DELETE_WINDOW", self.close_window)

        self.load_wallet_clicked()


    def update_address_list(self):
        assert self.wallet
        self.address_list.delete(0, tk.END)
        for key in self.wallet.key:
            if (key.type == wallet_pb2.Key.ORIGINAL or key.type == wallet_pb2.Key.ENCRYPTED_SCRYPT_AES) \
                    and key.HasField("public_key"):
                self.address_list.insert(tk.END, hash160_to_base58check(pubkey_to_hash160(key.public_key), "\0"))


    def load_wallet_clicked(self):

        wallet_file = tkFileDialog.askopenfile('rb', title='Load wallet backup file', initialdir=self.wallet_dir)
        if not wallet_file:
            return
        self.wallet_dir = os.path.dirname(wallet_file.name)

        password = None
        with wallet_file:
            is_encrypted = is_wallet_encrypted(wallet_file)
            while True:
                if is_encrypted:
                    password = tkSimpleDialog.askstring('Password', "Please enter the password of the wallet backup:", show='*')
                    if not password:
                        return
                try:
                    self.wallet = load_wallet(wallet_file, password)
                    break
                except ValueError as e:
                    tkMessageBox.showerror('Error', str(e))
                    if e.args[0] != 'incorrect password':
                        return
        self.password = password  # use the same password when saving it later
        self.update_address_list()
        if self.address_list.size():
            self.label['text'] = "Please select the address(es) whose key(s) you'd like to delete"
        else:
            self.label['text'] = 'No deletable keys were found in the loaded wallet'

    def delete_keys_clicked(self):

        selected_indices = self.address_list.curselection()
        if not selected_indices:
            tkMessageBox.showerror('Error', 'no addresses are selected')
            return

        delete_keys(self.wallet, (base58check_to_hash160(self.address_list.get(i))[0] for i in selected_indices))
        self.is_dirty = True
        self.update_address_list()


    def save_wallet_clicked(self):

        if not self.wallet:
            tkMessageBox.showerror('Error', 'no wallet is currently loaded')
            return

        wallet_file = tkFileDialog.asksaveasfile('wb', title='Save wallet backup file', initialdir=self.wallet_dir)
        if not wallet_file:
            return False
        self.wallet_dir = os.path.dirname(wallet_file.name)

        with wallet_file:
            save_wallet(self.wallet, wallet_file, self.password)
        self.is_dirty = False
        return True


    def close_window(self):

        if not self.is_dirty:
            self.root.destroy()
            return

        answer = tkMessageBox.askyesnocancel('Save changes?',
            'You have unsaved changes, would you like to save them now?\n(Choose No to exit)',
            default=tkMessageBox.YES)
        if answer:             # Yes was clicked
            if self.save_wallet_clicked():
                self.root.destroy()
        elif answer is False:  # No was clicked
            self.root.destroy()
        # else answer is None and Cancel was clicked


if __name__ == '__main__':
    if len(sys.argv) > 1:
        run_from_command_line()
    else:
        root = tk.Tk(className='Bitcoinj Key Deleter')
        DeleteBitcoinjKey(root)
        root.mainloop()
