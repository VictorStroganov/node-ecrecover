# node-ecrecover
Node.js package to work with signatures/

## Установка и настройка пакета

Установить КриптоПро CSP: https://cryptopro.ru/downloads

На данный момент используется версия КриптоПро CSP 4.0 R2.

### Ubuntu

npm install node-cryptopro

### Windows

npm install --global --production windows-build-tools

npm install node-cryptopro


## Компиляция .so/.dll библиотеки

### Ubuntu

1) Установить lsb-cprocsp-devel из дистрибутива КриптоПро CSP или КриптоПро OCSP SDK (https://www.cryptopro.ru/products/pki/ocsp/sdk/downloads), например так:

cd linux-amd64_deb

sudo dpkg -i lsb-cprocsp-devel_4.0.0-4_all.deb

2) cd node-ecrecover/src/go/src/ecrecover

3) export CGO_CFLAGS=$CGO_CFLAGS" -DUNIX"

4) go install crypto_csp

5) go build -o ecrecover.so -buildmode=c-shared ecrecover.go

6) mv ./ecrecover.so ../../../../lib


### Windows

1) Установить КриптоПро OCSP SDK (https://www.cryptopro.ru/products/pki/ocsp/sdk/downloads).

2) Установить переменные окружения:

set PATH=%PATH%C:\Program Files (x86)\Crypto Pro\SDK\include

set INCLUDE=%INCLUDE%C:\Program Files (x86)\Crypto Pro\SDK\include

set LIBPATH=%LIBPATH%C:\Program Files (x86)\Crypto Pro\SDK\lib\amd64

set LIBPATH=%LIBPATH%C:\Program Files (x86)\Crypto Pro\SDK\lib

3) Скомпилировать:

cl.exe /D_USRDLL /D_WINDLL nodeCryptopro.c /link /DLL /OUT:nodeCryptopro.dll