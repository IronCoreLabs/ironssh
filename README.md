![][logo]

This repository was archived on May 5, 2022. We encourage you to investigate our [IronHide utility](https://github.com/IronCoreLabs/ironhide) for a newer way to protect files stored on persistent file stores.


# IronSFTP - End-to-end secure file transfer

_An alternative to **sftp** and **scp** that keeps files encrypted after they're uploaded and allows sharing of files with cryptographic enforcement. See the [project homepage][homepage] for more details._

This project is a fork of the *openssh/openssh-portable* project from [OpenSSH](http://openssh.com). While most of the project is unchanged, specific additions have been made to create new executables that provide end-to-end security when transferring files to remote servers.

While *sftp* and *scp* use *ssh* to keep files secure while they are being transferred over the network, once those files hit the remote server, they are no longer protected. The **ironsftp** executable provides additional security. When you put a file on the server using **ironsftp**, the file is encrypted before it is uploaded, and it stays that way on the server. When you get a file from the server, it is downloaded then decrypted. So the file remains secure until it is at the place you want to use it - on your local machine.

The extension `.iron` is used to denote secured files. If you run **ironsftp** and `put foo.c` on the server, the file will first be encrypted and written to `foo.c.iron`, then that encrypted file will be written to the remote server. When you `get foo.c.iron` from the server, if that file can be downloaded, **ironsftp** will decrypt the file and write `foo.c` on your local machine. As a convenience, if you `get foo.c` but that file is not available on the server, **ironsftp** will try to download and decrypt `foo.c.iron`.

The process operates the same as *sftp*, but your files are protected on the remote server.

## Key Management

In order to use **ironsftp**, you must have an SSH key in the `~/.ssh/` directory on your local machine. When you start **ironsftp** the first time, it looks for your public and private SSH keys. If you specified an identity file (using the _-i idfile_ option), **ironsftp** will use that file. Otherwise, it will check for files in the following order: `id_rsa`, `id_ed25519`, `id_dsa`, and `id_ecdsa`. If it finds the key file and its corresponding `.pub` file, it copies them to `~/.ssh/ironcore/id_iron` and `id_iron.pub`. These files are only used for securing new signing and encryption keys, so you will either need to have the key registered with `ssh-agent` or you will need to enter the passphrase for the SSH key once in each session where upload or download any files. **NOTE**: due to the way that the DSA and ECDSA algorithms are used to sign data, **ironsftp** cannot use `ssh-agent` to unlock keys if you use one of these SSH identities. You will need to enter the passphrase once in each SSH session. It is thus recommended that you use an RSA or Ed25519 identity. After you run **ironsftp**, if you would like to change the SSH identity file, just delete `~/.ssh/.ironpubkey` and the `~/.ssh/ironcore` directories, then rerun **ironsftp** with the _-i idfile_ option.

During this initial setup, **ironsftp** generates an Ed25519 key pair that it will use for signing files and a Curve25519 key pair that it will use for encrypting files. These private keys are locked using a passphrase generated using the SSH identity just discussed. The public and private keys are stored in a GPG-compatible format in the `~/.ssh/ironcore` directory.

When you use **ironsftp** to connect to a server, your public key information is uploaded to `~/.ironpubkey`. This provides a convenient mechanism for other users connecting to the server to retrieve your public *ironcore* keys. In particular, if another user connects to the server using **ironsftp**, she can use your public key information to securely share files with you, as described in the next section.

## Secure Sharing

You are also able to share these secure files with other users. When you connect to a server, by default, each file that you upload will be encrypted so that only you can read it. However, if other users on that server have connected to it using **ironsftp**, their public key information will be available in `~login/.ironpubkey`. You can use new **ironsftp** commands to add recipients, so that any subsequent files you upload in that session will be encrypted to those users in addition to you. For example, suppose you are logged in as *gumby*:
```
  % ironsftp BigServer
  Connected to BigServer.

  ironsftp> showrcpt
  Currently registered recipients:
    gumby
  ironsftp> addrcpt pokey
  Added login pokey to the recipient list
  ironsftp> addrcpt mrhand
  Unable to retrieve public keys for user mrhand.
  ironsftp> showrcpt
  Currently registered recipients:
    gumby
    pokey
  ironsftp> put foo
  Uploading foo to /home/gumby/foo.iron
  ironsftp>
```

The file `foo.iron` on the server is encrypted so that both you and *pokey* can retrieve and decrypt it. Suppose pokey does
```
  % ironsftp BigServer
  Connected to BigServer.

  ironsftp> get foo
  Fetching /home/pokey/foo.iron to foo.iron
  Data was encrypted to user gumby
  Message was signed by user gumby, key ID 1234567890ABCDEF.
```

The file *foo.c.iron* will be decrypted automatically, and the file *foo* will be created. If a user other than *gumby* or *pokey* downloads the file, she would get a message like this
```
  ironsftp> get foo
  Fetching /private/tmp/sftp.c.iron to sftp.c.iron
  WARNING: The file "foo" is encrypted, but access is not granted to you,
  so the unencrypted contents cannot be retrieved.
```

The user would still have *foo.iron* in the current directory, but it would not be readable.

## GnuPG Compatibility
The keys used by **ironsftp** are stored in the same format that GnuPG uses - public keys are all in *~/.ssh/ironcore/pubring.gpg*, and the corresponding secret keys are in individual files in *~/.ssh/ironcore/private-keys-v1.d*.  All files encrypted by **ironsftp** can be read by *gpg* as well. (Since we are using elliptic curve cryptography to encrypt the data, you will need a *gpg* version 2.1.7 or greater, which in turn requires libgcrypt version 1.7 or later.) If you have a modern version of *gpg*, you can run something like this to decrypt a file encrypted by **ironsftp**:
```
  gpg --homedir ~/.ssh/ironcore -d --output foo foo.iron
```

## Installation

See the [project page installation section][homepageinstall] for supported operating systems and installation details.

[logo]: https://ironcorelabs.com/img/products/ironsftp.png
[homepage]: https://ironcorelabs.com/products/ironsftp
[homepageinstall]: https://ironcorelabs.com/products/ironsftp#installation
