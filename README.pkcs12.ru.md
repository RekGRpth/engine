# PKCS#12 (PFX) с алгоритмами ГОСТ

Поддержка экспорта и импорта PFX-контейнеров с алгоритмами ГОСТ
через стандартный `openssl pkcs12`. Поддерживаются две схемы PBE
и внешнего MAC:

- **Legacy GOST PBE (RFC 7292 + ГОСТ 28147-89)** — шифр `gost89`
  (или `gost89-cbc`), PBE-обвязка по RFC 7292; внешний MAC —
  HMAC по одному из ГОСТ-хэшей: 34.11-94, Streebog-256, Streebog-512.
- **RFC 9337 / RFC 9548 (ТК-26)** — шифры Кузнечик и Магма в режиме
  CTR-ACPKM под PBES2 + PBKDF2; PRF в PBKDF2 — HMAC-Streebog-256
  или HMAC-Streebog-512; внешний MAC — KDF по RFC 9548 §3
  (PBKDF2 с `dkLen=96`, ключ HMAC — последние 32 октета 96-байтной
  выдачи).

Поставляются две независимые реализации:

- **Engine** (`gost.so`, ENGINE_API) — работает на OpenSSL 3.x без
  патчей libcrypto.
- **Provider** (`gostprov.so`, provider-API) — работает на OpenSSL
  3.4, 3.6 и 4.0; на 4.x это единственный вариант. Для соответствия
  RFC 9337/9548 в provider-режиме обязателен патч libcrypto
  `patches/pkcs12/openssl-pkcs12-provider-pbe-${MAJOR}.${MINOR}.patch`
  (см. раздел [Provider-режим](#provider-режим-openssl-3x-и-4x)).

Дополнительно: provider умеет читать PFX-файлы с проприетарным
CryptoPro keybag PBE OID `1.2.840.113549.1.12.1.80` (только
декодирование, см. раздел [Декодирование проприетарного keybag'а CryptoPro](#декодирование-проприетарного-keybagа-cryptopro-12840113549112180)).

## Использование CLI

`openssl pkcs12` берёт алгоритмы из активного `openssl.cnf`
(путь — через `OPENSSL_CONF=<path>`). Минимальные конфиги:

Engine-режим (`gost.so`, OpenSSL 3.x):

```ini
openssl_conf = openssl_def
[openssl_def]
engines = engines
[engines]
gost = gost_conf
[gost_conf]
default_algorithms = ALL
```

Provider-режим (`gostprov.so`, OpenSSL 3.4 / 3.6 / 4.0):

```ini
openssl_conf = openssl_def
[openssl_def]
providers = providers
[providers]
gostprov = provider_conf
default = provider_conf
[provider_conf]
activate = 1
```

Готовые примеры — `test/engine.cnf` и `test/provider.cnf`. Путь к
`gost.so` / `gostprov.so` задаётся переменными окружения
`OPENSSL_ENGINES` и `OPENSSL_MODULES` соответственно. Полный
обзор движковых ENGINE_CMD-параметров (`PBE_PARAMS`,
`CRYPT_PARAMS`, `GOST_PK_FORMAT`) и список алгоритмов — в
`README.gost` корня репозитория.

### Legacy GOST PBE (RFC 7292 + ГОСТ 28147-89)

```sh
openssl pkcs12 -export \
    -inkey priv.pem -in cert.pem \
    -keypbe gost89 -certpbe gost89 \
    -macalg md_gost94 \
    -out bundle.p12
```

### RFC 9337 / 9548 (ТК-26)

```sh
openssl pkcs12 -export \
    -inkey priv.pem -in cert.pem \
    -keypbe kuznyechik-ctr-acpkm \
    -certpbe kuznyechik-ctr-acpkm \
    -macalg md_gost12_512 \
    -out bundle.p12
```

`-keypbe` / `-certpbe` принимают любое из четырёх имён шифров
CTR-ACPKM:

- `kuznyechik-ctr-acpkm`
- `kuznyechik-ctr-acpkm-omac`
- `magma-ctr-acpkm`
- `magma-ctr-acpkm-omac`

`-macalg` принимает имена ГОСТ-хэшей: `md_gost94`, `md_gost12_256`,
`md_gost12_512`.

## Переменные окружения

Базовая команда экспорта:

```sh
openssl pkcs12 -export \
    -inkey priv.pem -in cert.pem \
    -keypbe kuznyechik-ctr-acpkm \
    -certpbe kuznyechik-ctr-acpkm \
    -macalg md_gost12_512 \
    -out bundle.p12
```

### `GOST_PBE_HMAC` — выбор PRF для PBKDF2

По умолчанию PRF — HMAC-Streebog-512, в PBKDF2 пишется OID
`1.2.643.7.1.1.4.2`. Переключение на HMAC-Streebog-256:

```sh
GOST_PBE_HMAC=md_gost12_256 openssl pkcs12 -export \
    -inkey priv.pem -in cert.pem \
    -keypbe kuznyechik-ctr-acpkm \
    -certpbe kuznyechik-ctr-acpkm \
    -macalg md_gost12_512 \
    -out bundle.p12
```

В DER-результате PRF OID становится `1.2.643.7.1.1.4.1`. Принимает
`md_gost12_256`, `md_gost12_512`, `md_gost94`. Влияет на все четыре
шифра CTR-ACPKM и на `gost89*`.

### `LEGACY_GOST_PKCS12` — KDF внешнего MAC

По умолчанию (переменная не задана) применяется KDF из RFC 9548 §3
(PBKDF2 с `dkLen=96`, последние 32 октета — ключ HMAC). Если
получатель не поддерживает RFC 9548, можно вернуться к KDF из
RFC 7292 §B.2:

```sh
LEGACY_GOST_PKCS12=1 openssl pkcs12 -export \
    -inkey priv.pem -in cert.pem \
    -keypbe kuznyechik-ctr-acpkm \
    -certpbe kuznyechik-ctr-acpkm \
    -macalg md_gost12_512 \
    -out bundle.p12
```

OID-ы в MacData при этом не меняются — отличается только способ
получения ключа HMAC.

## OID-ы в PFX по RFC 9337 / 9548

| Поле                              | OID                       | Имя                                                |
|-----------------------------------|---------------------------|----------------------------------------------------|
| Внешний PBES2 для key bag         | `1.2.840.113549.1.5.13`   | `pbes2`                                            |
| KDF в PBES2 для key bag           | `1.2.840.113549.1.5.12`   | `pbkdf2`                                           |
| PRF в PBKDF2 (256-бит)            | `1.2.643.7.1.1.4.1`       | `id-tc26-hmac-gost-3411-12-256`                    |
| PRF в PBKDF2 (512-бит)            | `1.2.643.7.1.1.4.2`       | `id-tc26-hmac-gost-3411-12-512` (по умолчанию)     |
| Шифр PBES2 (Магма)                | `1.2.643.7.1.1.5.1.1`     | `id-tc26-cipher-gostr3412-2015-magma-ctracpkm`     |
| Шифр PBES2 (Магма+OMAC)           | `1.2.643.7.1.1.5.1.2`     | `id-tc26-cipher-gostr3412-2015-magma-ctracpkm-omac`                             |
| Шифр PBES2 (Кузнечик)             | `1.2.643.7.1.1.5.2.1`     | `id-tc26-cipher-gostr3412-2015-kuznyechik-ctracpkm`                             |
| Шифр PBES2 (Кз+OMAC)              | `1.2.643.7.1.1.5.2.2`     | `id-tc26-cipher-gostr3412-2015-kuznyechik-ctracpkm-omac`                        |
| Хэш во внешнем MacData (256)      | `1.2.643.7.1.1.2.2`       | `id-tc26-gost3411-12-256`                          |
| Хэш во внешнем MacData (512)      | `1.2.643.7.1.1.2.3`       | `id-tc26-gost3411-12-512` (по умолчанию)           |

Cert bag оборачивается в `encryptedData` ContentInfo
(`1.2.840.113549.1.7.6`) и шифруется тем же набором PBES2, что и
key bag.

## Поддерживаемые шифры по режимам

| Шифр                          | Engine 3.4 | Engine 3.6 | Provider 3.4 | Provider 3.6 | Provider 4.0 |
|-------------------------------|:----------:|:----------:|:------------:|:------------:|:------------:|
| `kuznyechik-ctr-acpkm`        | ✓ | ✓ | ✓ | ✓ | ✓ |
| `kuznyechik-ctr-acpkm-omac`   | ✓ | ✓ | — | — | — |
| `magma-ctr-acpkm`             | ✓ | ✓ | ✓ | ✓ | ✓ |
| `magma-ctr-acpkm-omac`        | ✓ | ✓ | — | — | — |

На OpenSSL 4.0 engine-API в upstream удалён, поэтому колонки
`Engine 4.0` нет.

Штатная проверочная матрица — provider-режим × шифры без OMAC ×
3 версии OpenSSL (3.4 / 3.6 / 4.0) × 2 хэша внешнего MAC = 12 тестов,
все 12 проходят. Воспроизводится скриптом
`docker/dev_pkcs12/scripts/engine_to_csp_matrix.sh` (см.
[`docker/dev_pkcs12/README.ru.md`](docker/dev_pkcs12/README.ru.md)).

Импорт OMAC-шифров в CryptoPro CSP 5.0.13003 проверен в
engine-режиме: `certmgr -install -pfx` принимает PFX с
`PrivateKey Link: Yes` и кодом возврата `0x00000000`.

## Provider-режим (OpenSSL 3.x и 4.x)

Тот же формат RFC 9337 / 9548 можно получить через **провайдер**
ГОСТ (`gostprov.so`) вместо engine-модуля (`gost.so`). Provider-режим —
единственный вариант на OpenSSL 4.0+, где engine-режим удалён; на
3.x доступны оба режима, и они выпускают **структурно идентичные**
PFX (отличаются только поля, которые по спецификации обязаны
быть случайными).

### Патч libcrypto (обязателен в provider-режиме)

Provider-режим для RFC 9337/9548 требует патча libcrypto
`patches/pkcs12/openssl-pkcs12-provider-pbe-${MAJOR}.${MINOR}.patch` —
без него `openssl pkcs12 -export` под `provider.cnf` падает с
`cipher has no object identifier`. Поставляются варианты для
OpenSSL 3.4, 3.6 и 4.0.

Описание по хункам и пошаговая инструкция по наложению —
в [`patches/pkcs12/README.ru.md`](patches/pkcs12/README.ru.md).

### Выбор режима

Engine-режим (по умолчанию на 3.x):

```sh
export OPENSSL_CONF=/path/to/engine.cnf  # подгружает gost.so через [engine_section]
openssl pkcs12 -export ...
```

Provider-режим (обязателен на 4.x, опционален на 3.x):

```sh
export OPENSSL_CONF=/path/to/provider.cnf  # активирует gostprov через [providers]
openssl pkcs12 -export ...
```

Флаги CLI (`-keypbe kuznyechik-ctr-acpkm`, `-macalg md_gost12_512`
и т. п.) не меняются — меняется только конфиг-файл. Рабочие
примеры есть в `test/engine.cnf` и `test/provider.cnf`.

## Декодирование проприетарного keybag'а CryptoPro (`1.2.840.113549.1.12.1.80`)

**Только декодирование.** Провайдер умеет читать PFX-файлы,
выпущенные `certmgr -export -pfx` из CryptoPro CSP, у которых
key bag использует проприетарный PBE с OID
`1.2.840.113549.1.12.1.80`. OID находится в ветке
`pkcs-12-pbeIds`, но не относится к алгоритмам RFC 7292 — это
собственное расширение CryptoPro, появившееся до RFC 9337.

Декодирование доступно только в provider-режиме, engine-режим
не поддержан.

Когда встречается этот keybag: при экспорте через
`certmgr -export -pfx` из CSP легаси-контейнера ГОСТ 2001 /
ГОСТ 2012-256/512, созданного через `csptest -newkeyset … -exportable`.
Cert bag упакован в стандартный конверт `pbeWithSHAAnd40BitRC2-CBC`
(OID из RFC 7292 — `1.2.840.113549.1.12.1.6`); проприетарный
PBE `.80` использует только key bag.

### Использование CLI

Декодирование работает в provider-режиме. Минимальный `gostfull.cnf`:

```ini
HOME = .
openssl_conf = openssl_def

[openssl_def]
providers = provider_section

[provider_section]
default  = default_sect
legacy   = legacy_sect
gostprov = gostprov_sect

[default_sect]
activate = 1
[legacy_sect]
activate = 1
[gostprov_sect]
module   = /opt/openssl/lib64/ossl-modules/gostprov.so
activate = 1
```

```sh
OPENSSL_CONF=/path/to/gostfull.cnf \
    openssl pkcs12 \
        -in   legacy-csp-export.pfx \
        -password pass:123456 \
        -nodes \
        -out  recovered.pem
```

На выходе — стандартный PEM-bundle (`-----BEGIN CERTIFICATE-----`
и `-----BEGIN PRIVATE KEY-----`). Восстановленный приватный ключ
— это обычный PKCS#8 `PrivateKeyInfo`, корректно проходящий через
`openssl pkey -in recovered.pem -outform DER`.

### Проверка

Скрипт `docker/dev_pkcs12/scripts/cryptopro_keybag_decode.sh` создаёт
exportable-keyset ГОСТ 2012-256 в CSP, экспортирует PFX через
`certmgr -export -pfx`, прогоняет его через `openssl pkcs12` в
каждом provider-стэке (`dev-3.4`, `dev-3.6`, `dev-4.0`) и сверяет:
PEM-маркеры присутствуют, восстановленный ключ проходит через
`openssl pkey`, SHA-1 сертификата совпадает с thumbprint'ом из CSP.

Скрипт запускается с хоста (внутри dev-контейнера не работает —
docker-in-docker не предусмотрен), поэтому в ctest внутри
контейнера не входит. Запись `uMy` и контейнер CSP удаляются при любом
завершении; сам PFX остаётся в `docker/dev_pkcs12/cryptopro/data/<seed>.pfx`
— это позволяет разобрать его при ошибке. Подготовка стэка — см.
[`docker/dev_pkcs12/README.ru.md`](docker/dev_pkcs12/README.ru.md).

### Кодирование (encode) не реализовано

Поддержано только декодирование. Стандартный путь экспорта PFX
из engine-модуля и провайдера — RFC 9337 / 9548 (см. раздел
[RFC 9337 / 9548 (ТК-26)](#rfc-9337--9548-тк-26)).

## Литература

- RFC 9337 — *Generating Password-Based Keys Using the GOST
  Algorithms* — <https://www.rfc-editor.org/rfc/rfc9337.html>.
  PBKDF2 / PBES2 / PBMAC1 с HMAC-Streebog-256/512 и
  Кузнечиком и Магмой CTR-ACPKM. §7.3 определяет
  `Gost3412-15-Encryption-Parameters`.
- RFC 9548 — *Generating Transport Key Containers (PFX) Using the
  GOST Algorithms* — <https://www.rfc-editor.org/rfc/rfc9548.html>.
  Формат PKCS#12 для ключей ГОСТ + целостность, включая KDF
  внешнего MAC из §3 (PBKDF2 с `dkLen=96`, последние 32 октета —
  ключ HMAC).
- RFC 7292 — *PKCS #12: Personal Information Exchange Syntax*.
  KDF из Appendix B.2 — это легаси-путь, доступный через
  `LEGACY_GOST_PKCS12=1`.
- RFC 8018 — *PKCS #5: Password-Based Cryptography Specification
  Version 2.1*. PBES2 / PBKDF2 / правила итераций и соли.
