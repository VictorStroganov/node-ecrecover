# node-ecrecover
Node.js package to work with multichain compatible signatures/addresses

## Установка и настройка пакета

Установить КриптоПро CSP: https://cryptopro.ru/downloads

На данный момент используется версия КриптоПро CSP 4.0 R2.

### Ubuntu

npm install node-ecrecover

### Windows

npm install --global --production windows-build-tools

npm install node-ecrecover


## Компиляция .so/.dll библиотеки

### Ubuntu

1) Установить lsb-cprocsp-devel из дистрибутива КриптоПро CSP или КриптоПро OCSP SDK (https://www.cryptopro.ru/products/pki/ocsp/sdk/downloads), например так:

cd linux-amd64_deb

sudo dpkg -i lsb-cprocsp-devel_4.0.0-4_all.deb

2) cd {path-to-node-ecrecover}/src/go/src/ecrecover

3) Установить переменные окружения:

export GOPATH=~/work/new-node-ecrecover/src/go

export CGO_CFLAGS=$CGO_CFLAGS" -DUNIX"

4) go install crypto_csp

5) go build -o ecrecover.so -buildmode=c-shared ecrecover.go

6) mv ./ecrecover.so ../../../../lib


### Windows

1) Установить КриптоПро OCSP SDK (https://www.cryptopro.ru/products/pki/ocsp/sdk/downloads).

2) Установить TDM-GCC-64 (http://tdm-gcc.tdragon.net/download) для компиляции C.

3) Установить переменные окружения:

set GOPATH={path-to-node-ecrecover}\src\go

set CC=C:\TDM-GCC-64\bin\gcc.exe

set C_INCLUDE_PATH=C:\Program Files (x86)\Crypto Pro\SDK\include

4) Перейти в {path-to-node-ecrecover}/src/go/src/ecrecover

5) Скомпилировать:

go install crypto_csp

go build -o ecrecover.dll -buildmode=c-shared ecrecover.go

6) Переместить ecrecover.dll из {path-to-node-ecrecover}/src/go/src/ecrecover в {path-to-node-ecrecover}/lib
