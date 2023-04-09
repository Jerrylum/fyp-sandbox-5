## Usage

Use to install the pam module. The build scripts will take care of putting your module where it needs to be, `/lib/security`, so the next thing to do is edit config files.
```
sudo ./build.sh
```

The config files are located in `/etc/pam.d/` and the one I edited was `/etc/pam.d/common-auth`.
```
nano /etc/pam.d/common-auth
```


At the top of the pam file (or anywhere), put these lines:

```
auth sufficient libkeyfobpam.so
```
OR
```
auth required libkeyfobpam.so
```

## Install

```
sudo apt-get install libqrencode-dev
```

## Test

```
mkdir build && cd build && cmake .. && make

cmake --build build; ./build/mysandbox
```

## License

https://github.com/beatgammit/simple-pam MIT License

https://github.com/brainhub/SHA3IUF MIT License

https://github.dev/kokke/tiny-AES-c Unlicense

https://github.com/google/google-authenticator-libpam Apache License 2.0
