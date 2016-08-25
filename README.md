# IronSSH - End-to-end secure file transfer

This project is a fork of the *openssh/openssh-portable* project. While most of the project is unchanged, specific additions have been made to create new executables that provide end-to-end security when transferring files to remote servers.

While *sftp* and *scp* use *ssh* to keep files secure while they are being transferred over the network, once those files hit the remote server, they are no longer protected. The **ironsftp** executable provides additional security. When you put a file on the server using **ironsftp**, the file is encrypted before it is uploaded, and it stays that way on the server. When you get a file from the server, it is downloaded then decrypted. So the file remains secure until it is at the place you want to use it - on your local machine.

The extension '.iron' is used to denote secured files. If you run **ironsftp** and put 'foo.c' on the server, it will be written remotely as 'foo.c.iron'. When you get 'foo.c', **ironsftp** will look for 'foo.c', but if it doesn't find that file, it will try to download 'foo.c.iron'. If that is successful, it will decrypt that file and write 'foo.c' on your local machine. The process operates the same as *sftp*, but your files are protected on the remote server.

## Key Management

In order to use **ironsftp**, you must currently have an RSA key in the *~/.ssh/id_rsa* file on your local machine. When you start **ironsftp** the first time, it reads your public and private RSA keys (which may prompt you to enter the passphrase for the private key), then copies them into new key files under *~/.ssh/ironcore/*. The RSA key is used for signing encrypted files. **ironsftp** also generates a Curve25519 key pair - this key is stored in the same place and is used to encrypt data.

When you use **ironsftp** to connect to a server, your public key information is uploaded to `~/.ironpubkey`.

## Secure Sharing

You are also able to share these secure files with other users. When you connect to a server, by default, each file that you upload will be encrypted so that only you can read it. However, if other users on that server have connected to it using **ironsftp**, their public key information will be available in `~<login>/.ironpubkey`. You can use new **ironsftp** commands to add recipients, so that any subsequent files you upload will be encrypted to those users in addition to you. For example, suppose you are logged in as *gumby*:
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

The file *foo.iron* on the server is encrypted so that both you and *pokey* can retrieve and decrypt it. Suppose pokey does
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

