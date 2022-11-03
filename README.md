## Usage

The build scripts will take care of putting your module where it needs to be, `/lib/security`, so the next thing to do is edit config files.

The config files are located in `/etc/pam.d/` and the one I edited was `/etc/pam.d/common-auth`.

The test application tests auth and account functionality (although account isn't very interesting). At the top of the pam file (or anywhere), put these lines:

	auth sufficient mypam.so
	account sufficient mypam.so

## Install

```
sudo apt-get install libqrencode-dev
````

## License

https://github.com/beatgammit/simple-pam MIT License
https://github.com/brainhub/SHA3IUF MIT License
https://github.dev/kokke/tiny-AES-c Unlicense
https://github.com/google/google-authenticator-libpam Apache License 2.0

## Network

### Frame structure
```
|Frame(128)----------------------------------------------------------------------|
|Header(32)|Encrypted Packet(96)-------------------------------------------------|
           |Packet Buffer(64)-------------------------------------------|Hash(32)|
           |Packet Type(1)|Session ID(8)|Packet Payload(55-n)|Padding(n)|
```

### Packet structure
```
#### 0 - H2D Challenge
(nothing)


#### 1 - D2H Challenge Response
(nothing)


#### 2 - D2H Renew Backup Code
Backup Code(5) * 10


#### 254 - Session ID Error Code


#### 255 - Checksum Error Code

```

(SHOULD I?)
Session ID works as a counter, and is incremented by 1 every time a new session is started. It is used to identify the session, and to prevent replay attacks.
