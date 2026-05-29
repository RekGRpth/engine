# Окружение разработки

Самодостаточный dev-стек для сборки и проверки engine-модуля и
провайдера сразу на трёх версиях OpenSSL без вмешательства в хост:
три сборочных контейнера (OpenSSL 3.4 / 3.6 / 4.0) и соседний
контейнер CryptoPro CSP для cross-валидации.

## Структура

```
docker/dev_pkcs12/
├── docker-compose.yml          ← оркестратор (5 сервисов)
├── Dockerfile.dev              ← сборочный контейнер engine/провайдера
├── Dockerfile.test             ← минимальный контейнер для ctest
├── cryptopro/                  ← соседний контейнер CryptoPro CSP 5.0
│   ├── Dockerfile.cryptopro
│   ├── entrypoint.cryptopro.sh
│   ├── readme.{dockerfile,certmgr,keygen}.md
│   ├── data/                   ← обменник PFX (bind-mount во все dev-сервисы)
│   └── test_gamma/             ← seed для программного RNG CPSD
└── scripts/
    ├── entrypoint.sh           ← сборка OpenSSL под каждую версию + наложение патча
    ├── fetch-openssl.sh        ← скачать исходники OpenSSL 3.4.0 / 3.6.0 / 4.0.0
    ├── run-full-check.sh       ← пересборка с -Werror + ctest + cppcheck + valgrind
    ├── cryptopro_keybag_decode.sh  ← CSP → engine, проприетарный keybag `.80`
    └── engine_to_csp_matrix.sh ← engine → CSP, RFC 9337/9548, 12 тестов
```

## Подготовка

1. **Исходники OpenSSL** — `docker-compose.yml` монтирует
   `docker/dev_pkcs12/openssl/{3.4.0,3.6.0,4.0.0}/` в dev-контейнеры как
   `/workspace/openssl-src`. Скачайте исходники один раз:

   ```sh
   docker/dev_pkcs12/scripts/fetch-openssl.sh           # все три
   docker/dev_pkcs12/scripts/fetch-openssl.sh 3.4.0     # выборочно
   ```

2. **Архив CryptoPro CSP** *(опционально, нужен только для тестов
   со стороны CSP)* — проприетарный комплект CSP в этот репозиторий
   **не** включён. Скачайте Linux-сборку deb-only (после бесплатной
   регистрации) с <https://cryptopro.ru/products/csp/downloads> и
   положите по пути
   `docker/dev_pkcs12/cryptopro/cryptopro_linux-amd64_deb_*.tgz` до сборки
   сервиса `cryptopro`.

## Запуск

```sh
# Все пять сервисов:
docker compose -f docker/dev_pkcs12/docker-compose.yml up -d

# Один стэк:
docker compose -f docker/dev_pkcs12/docker-compose.yml up -d dev-3.4
docker compose -f docker/dev_pkcs12/docker-compose.yml up -d dev-3.6
docker compose -f docker/dev_pkcs12/docker-compose.yml up -d dev-4.0
```

`entrypoint.sh` собирает соответствующий OpenSSL в `/opt/openssl`
внутри контейнера (кэшируется в named-volume под каждую версию),
накатывает `patches/pkcs12/openssl-pkcs12-provider-pbe-${MAJOR}.${MINOR}.patch`,
после чего конфигурирует и устанавливает gost-engine / gost-provider.

## Запуск тестов

ctest по каждому стэку (`dev-3.4`, `dev-3.6`, `dev-4.0`):

```sh
docker compose -f docker/dev_pkcs12/docker-compose.yml exec dev-3.4 \
    sh -c 'cd build && ctest --output-on-failure'
```

Cross-валидация со стороны CSP (требует поднятого сервиса
`cryptopro`):

```sh
docker/dev_pkcs12/scripts/cryptopro_keybag_decode.sh    # CSP → engine, проприетарный keybag
docker/dev_pkcs12/scripts/engine_to_csp_matrix.sh       # engine → CSP, RFC 9337/9548, 12 тестов
```

## Завершение

```sh
docker compose -f docker/dev_pkcs12/docker-compose.yml down                # named volumes сохраняются
docker compose -f docker/dev_pkcs12/docker-compose.yml down -v             # вместе с кэшем сборки OpenSSL
```
