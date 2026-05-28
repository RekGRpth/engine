# Патчи OpenSSL для PKCS#12 по RFC 9337 / RFC 9548

Патчи к исходникам OpenSSL, закрывающие пробелы libcrypto, из-за
которых `openssl pkcs12 -export` по RFC 9337 / 9548 c
симметричными ГОСТ-шифрами не работает в provider-режиме.
Описание самих патчей — ниже; запуск проверочных матриц в
локальном dev-окружении — в разделе
[Проверочные матрицы](#проверочные-матрицы).

## Патчи

### `openssl-pkcs12-provider-pbe-{3.4,3.6,4.0}.patch`

Три патча по версиям, закрывающие пробелы в libcrypto при
экспорте PKCS#12 по RFC 9337 / 9548 с симметричными ГОСТ-шифрами
из провайдера. Обязательны на OpenSSL 4.0 (engine-API убран из
`apps/pkcs12.c`) и на 3.x — когда явно подгружена
provider-конфигурация.

Все три патча вносят одни и те же концептуальные изменения,
адаптированные к номерам строк конкретного релиза; функционально —
один и тот же набор резервных хунков. Сами хунки:

| Файл                          | Хунк                                                       | Эффект                                                                                                                |
|-------------------------------|------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------|
| `crypto/evp/digest.c`         | резерв `OBJ_txt2nid` в `set_legacy_nid`                    | digest'ы из провайдера разрешают NID через OID/SN, когда не отрабатывал legacy `EVP_add_digest`                       |
| `crypto/evp/evp_enc.c`        | резерв `OBJ_txt2nid` в `set_legacy_nid`                    | симметрика: шифры из провайдера разрешают NID и без legacy `EVP_add_cipher`                                           |
| `crypto/evp/evp_enc.c`        | `EVP_CTRL_PBE_PRF_NID` → `pbe-prf-nid` `OSSL_PARAM`        | `PKCS5_pbe2_set_iv_ex` умеет считать NID PRF из provider-ctx (иначе PRF по умолчанию становится `NID_hmacWithSHA256`) |
| `crypto/evp/evp_lib.c`        | `evp_cipher_param_to_asn1_ex` / `..._asn1_to_param_ex`     | провайдер с собственной формой AlgorithmIdentifier (RFC 9337 §7.3 SEQUENCE { ukm }) получает возможность подставить свой DER |
| `crypto/evp/evp_lib.c`        | слот `cipher-with-mac` в `evp_cipher_cache_constants`      | провайдеры умеют объявлять `EVP_CIPH_FLAG_CIPHER_WITH_MAC` для потока трейлинг-тэгов в `PKCS12_pbe_crypt_ex` (INACTIVE) |
| `crypto/pkcs12/p12_decr.c`    | резерв по `mac_len` в `PKCS12_pbe_crypt_ex`                | подбирает `mac_len` из возвращаемого значения ctrl-вызова, когда provider-трансляция libcrypto теряет engine'овую перегрузку `*(int *)ptr` (INACTIVE) |

Два **INACTIVE**-хунка (продвижение флага `cipher-with-mac` в
`evp_lib.c` и резерв по `mac_len` в `p12_decr.c`) — архитектурное
предусловие для PKCS#12 OMAC в provider-режиме. Конечная
активация упирается в `gost2015_acpkm_omac_init`
(`gost_gost2015.c:158`): он вызывает устаревшие
`EVP_get_digestbynid` / `EVP_PKEY_new_mac_key`, оба возвращают
NULL под провайдером — `kuznyechik-mac` и `magma-mac`
зарегистрированы как `EVP_MAC` (`gost_prov_mac.c:343`). Снятие
блокировки требует рефакторинга на `EVP_MAC_fetch` в исходниках
engine-модуля; до этого хунки остаются неактивным кодом. См.
блок INACTIVE в начале каждого патча — там описано, какой
именно рефакторинг нужен.

Не-INACTIVE хунки нужны для не-OMAC шифров RFC 9337 / 9548
(`kuznyechik-ctr-acpkm`, `magma-ctr-acpkm`) под `openssl pkcs12
-export`, когда симметричная криптография приходит из
провайдера.

## Порядок применения

Скрипт `docker/dev_pkcs12/scripts/entrypoint.sh` накладывает
патчи автоматически на первом запуске контейнера, на
смонтированные исходники OpenSSL под
`docker/dev_pkcs12/openssl/{3.4.0,3.6.0,4.0.0}/`:

1. **Только 3.6** — `../openssl-tls1.3.patch` (`git apply -p2`)
   накладывается первым. Это предусловие: pkcs12-патч для 3.6
   снимался против дерева, где TLS 1.3-изменения upstream'а уже
   были; без них хунки `evp_enc.c` не накладываются. На 3.4 и
   4.0 не нужен.
2. **Все стэки** — `openssl-pkcs12-provider-pbe-${MAJOR}.${MINOR}.patch`
   (3.4 — строго через `git apply -p2`; 3.6 и 4.0 — через
   `patch -p2 --fuzz=3` для компенсации сдвигов upstream).

После этого OpenSSL конфигурируется и собирается out-of-tree в
именованный том на каждую версию (`/opt/openssl`); gost-engine
и gostprov собираются с этим префиксом.

## Проверочные матрицы

Поставляются две матрицы:

- **Tier-1 в provider-режиме** — 12 тестов (3 стэка × 2 шифра ×
  2 хэша внешнего MAC) полного цикла `openssl pkcs12 -export` →
  `certmgr -install -pfx` в CryptoPro CSP. Подтверждает, что
  пропатченный libcrypto + gostprov выпускают форму PFX, которую
  CSP принимает с сохранением связи с ключом.
- **Регрессия ctest** — регрессионный набор по каждому стэку:
  21/21 (3.4) / 21/21 (3.6) / 9/9 (4.0).

### Подготовка

1. Docker и docker compose v2.
2. Репозиторий клонирован где-то на хосте; если путь отличается
   от ожидаемого, поправьте его в
   `docker/dev_pkcs12/scripts/engine_to_csp_matrix.sh`.
3. Исходники upstream-OpenSSL монтируются в
   `docker/dev_pkcs12/openssl/{3.4.0,3.6.0,4.0.0}/`. Подходят
   свежие клоны upstream-тегов `openssl-3.4.0`, `openssl-3.6.0`
   и дерева разработки 4.0; `docker/dev_pkcs12/openssl/`
   исключён из репозитория через .gitignore. tls1.3-патч на 3.6
   ждёт дерево 3.6; pkcs12-патчи — соответствующие исходники под
   свою версию.
4. Сервис `cryptopro` собран и поднят
   (`docker/dev_pkcs12/docker-compose.yml`; образ собирается из
   проприетарного `linux-amd64_deb.tgz`, который репозиторий
   не включает). Без него регрессия ctest всё равно работает,
   а Tier-1 матрица не запускается: импортировать PFX некуда.

### Холодный старт

```sh
cd <путь-к-репо>
docker compose -f docker/dev_pkcs12/docker-compose.yml build dev-3.4 dev-3.6 dev-4.0 cryptopro
docker compose -f docker/dev_pkcs12/docker-compose.yml up -d dev-3.4 dev-3.6 dev-4.0 cryptopro
```

`entrypoint.sh` на первом запуске в каждом dev-контейнере:

1. Накладывает версионные патчи на исходники OpenSSL.
2. Конфигурирует и собирает OpenSSL в `/opt/openssl`
   (именованный том — последующие старты этот шаг пропускают).
3. cmake-конфигурирует и собирает gost-engine + gostprov с этим
   OpenSSL-префиксом; ставит `gost.so` (только 3.x) и
   `gostprov.so` в `/opt/openssl/lib64/{engines-3,ossl-modules}/`.
4. Пишет `/opt/openssl/gost-engine.cnf` (используется как
   `OPENSSL_CONF` по умолчанию на 3.x в engine-режиме) и
   `/opt/openssl/gost-provider.cnf` (provider-режим — опционален
   на 3.x через env-override; по умолчанию на 4.0).

Первичная сборка выполняется один раз на каждый именованный том.
Чтобы запустить её заново (например, после правки патча),
удалите тома:

```sh
docker compose -f docker/dev_pkcs12/docker-compose.yml down dev-3.4 dev-3.6 dev-4.0
docker volume rm \
    dev_pkcs12_openssl-prefix-3.4 dev_pkcs12_openssl-build-3.4 dev_pkcs12_gost-engine-build-3.4 \
    dev_pkcs12_openssl-prefix-3.6 dev_pkcs12_openssl-build-3.6 dev_pkcs12_gost-engine-build-3.6 \
    dev_pkcs12_openssl-prefix-4.0 dev_pkcs12_openssl-build-4.0 dev_pkcs12_gost-engine-build-4.0
docker compose -f docker/dev_pkcs12/docker-compose.yml up -d dev-3.4 dev-3.6 dev-4.0
```

### Проверка провайдера (одна команда)

Перед запуском матрицы убедитесь, что `gostprov` грузится под
provider-конфигом на каждом стэке:

```sh
for svc in dev-3.4 dev-3.6 dev-4.0; do
    echo "=== $svc ==="
    docker compose -f docker/dev_pkcs12/docker-compose.yml exec -T \
        -e OPENSSL_CONF=/opt/openssl/gost-provider.cnf \
        "$svc" /opt/openssl/bin/openssl list -providers
done
```

Ожидается: `gostprov` и `default` отображаются как
`status: active` на всех трёх стэках.

### Tier-1 матрица (engine → CSP, provider-режим, 12 тестов)

```sh
./docker/dev_pkcs12/scripts/engine_to_csp_matrix.sh
```

Что происходит в каждом тесте:

1. `openssl genpkey -algorithm gost2012_256 -pkeyopt paramset:A`.
2. `openssl req -x509 -new -key key.pem -subj /CN=<seed> -days 365`.
3. `openssl pkcs12 -export -keypbe <шифр> -certpbe <шифр>
   -macalg <macalg> -password pass:123456`.
4. Захватывается SHA-1 сертификата на стороне engine-модуля.
5. PFX копируется на хост через `docker cp` (хост монтирует его
   в контейнер `cryptopro` на `/workspace/data`).
6. `certmgr -install -pfx -file <pfx> -pin 123456 -newpin 123456
   -carrier '\\.\HDIMAGE\<seed>' -silent`.
7. `certmgr -list -dn CN=<seed>` — проверяется, что `SHA1
   Thumbprint` совпадает с сертификатом на стороне engine-модуля
   и присутствует `PrivateKey Link: Yes`.
8. Очистка: сертификат удаляется из `uMy` в CSP, контейнер
   keyset'а тоже удаляется.

Оси матрицы:

- **Стэки**: `dev-3.4`, `dev-3.6`, `dev-4.0` — provider-режим
  включается через `OPENSSL_CONF=/opt/openssl/gost-provider.cnf`.
- **Шифры**: `kuznyechik-ctr-acpkm`, `magma-ctr-acpkm`. Варианты
  с OMAC (`*-acpkm-omac`) в provider-режим не входят — см. блок
  INACTIVE в начале каждого pkcs12-pbe патча.
- **`-macalg`**: `md_gost12_256`, `md_gost12_512`.

Итого 12 тестов. Ожидается:

```
===============================================
  Tier 1 — engine → CSP, 12 cells
  PASS:  12   (CSP accepted PFX with key link)
  FAIL:  0   (any failure is hard fail)
===============================================
```

Шаг 0 каждого теста проверяет, что `gostprov` активен под
заданным `OPENSSL_CONF`, ещё до `genkey`: если провайдер не
загрузится, тест падает с `PROVIDER SANITY FAIL`. FAIL в любом
тесте — hard fail; XFAIL-оси нет.

### Регрессия ctest

Прогон по каждому стэку изнутри соответствующего контейнера:

```sh
docker compose -f docker/dev_pkcs12/docker-compose.yml exec dev-3.4 \
    bash -lc 'cd build && ctest --output-on-failure -j$(nproc)'

docker compose -f docker/dev_pkcs12/docker-compose.yml exec dev-3.6 \
    bash -lc 'cd build && ctest --output-on-failure -j$(nproc)'

docker compose -f docker/dev_pkcs12/docker-compose.yml exec dev-4.0 \
    bash -lc 'cd build && ctest --output-on-failure -j$(nproc)'
```

Ожидаемые результаты:

| Стэк      | Тестов проходит |
|-----------|-----------------|
| dev-3.4   | 21 / 21         |
| dev-3.6   | 21 / 21         |
| dev-4.0   |  9 /  9         |

Счёт на 4.0 ниже, потому что engine-only ctest'ы там не
зарегистрированы (`-DGOST_BUILD_ENGINE=OFF` на 4.0 — engine-API
убран из OpenSSL 4.0).

Полная проверка (строгие предупреждения + ctest + cppcheck +
valgrind, дольше):

```sh
docker compose -f docker/dev_pkcs12/docker-compose.yml exec dev-3.4 \
    bash /workspace/src/docker/dev_pkcs12/scripts/run-full-check.sh
```

### Сверка форм PFX между engine и provider (опционально)

На 3.x `openssl pkcs12 -export` выпускает структурно идентичные
PFX независимо от того, откуда приходит симметрика — из
engine-модуля или из провайдера. Это проверяет ctest
`pkcs12_rfc9337_cross_mode_parity`: побайтовое сравнение даёт
0 расхождений на 346 структурных байтах (различаются только
поля, обязанные по спецификации быть случайными).

Перезапуск:

```sh
docker compose -f docker/dev_pkcs12/docker-compose.yml exec dev-3.4 \
    bash -lc 'cd build && ctest --output-on-failure -R pkcs12_rfc9337_cross_mode_parity'
```

То же на `dev-3.6`. На `dev-4.0` неприменимо: engine-режима нет.
