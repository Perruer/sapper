<p align="center"><img src="images/sapper_mark.svg" width="96" alt="Sapper"></p>

<h1 align="center">Sapper</h1>

<p align="center">
  <b>Находит, где уязвимый пакет сидит во всех ваших продуктах, и показывает, что чинить первым.</b>
</p>

<p align="center">
  <a href="https://github.com/Perruer/sapper/actions/workflows/ci.yml"><img src="https://github.com/Perruer/sapper/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/Perruer/sapper/releases"><img src="https://img.shields.io/github/v/release/Perruer/sapper" alt="Release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue" alt="Apache-2.0"></a>
</p>

<p align="center"><a href="README.md">English</a> · Русский</p>

---

Загрузите в Sapper SBOM всего, что вы выпускаете, и данные об уязвимостях, которым доверяете. Он построит единый граф зависимостей и за миллисекунды ответит:

- какие из наших продуктов задевает эта CVE, напрямую или через другие пакеты, и по какому пути;
- какие уязвимости уже эксплуатируются (CISA KEV) или вероятно будут (EPSS) — их чинить первыми;
- какие продукты уже закрыты VEX-заявлением.

Sapper — один бинарник с локальной базой SQLite. Ничего не уходит из вашей сети: каждый источник данных — это файл, который вы ему даёте.

Это продолжение [Minefield](https://github.com/bitbomdev/minefield) от BitBom, заархивированного в августе 2025 года. Графовый движок и кэш на roaring bitmaps взяты из Minefield ([статья](docs/paper.md)).

```
$ sapper report --limit 4
┌──────────────────────────────────────┬──────────┬─────────────────────┬───────┬──────────┬──────────────────────────────────────────────────────────────────────┐
│            VULNERABILITY             │ SEVERITY │         KEV         │  EPSS │ PRODUCTS │                             EXAMPLE PATH                             │
├──────────────────────────────────────┼──────────┼─────────────────────┼───────┼──────────┼──────────────────────────────────────────────────────────────────────┤
│ GHSA-qppj-fm5r-hxr3 / CVE-2023-44487 │ MODERATE │ yes, due 2023-10-31 │ 1.000 │ 4        │ cloudprober > golang.org/x/net@v0.0.0-20210503060351-7fd8e65b6420    │
│ GHSA-45x7-px36-x8w8 / CVE-2023-48795 │ MODERATE │                     │ 0.933 │ 2        │ cloudprober > golang.org/x/crypto@v0.0.0-20201012173705-84dcc777aaee │
│ GHSA-4v7x-pqxf-cx7m / CVE-2023-45288 │ MODERATE │                     │ 0.920 │ 4        │ cloudprober > golang.org/x/net@v0.0.0-20210503060351-7fd8e65b6420    │
│ GHSA-39qc-96h7-956f / CVE-2019-9512  │ HIGH     │                     │ 0.834 │ 2        │ credstore > golang.org/x/net@v0.0.0-20181217023233-e147a9138326      │
└──────────────────────────────────────┴──────────┴─────────────────────┴───────┴──────────┴──────────────────────────────────────────────────────────────────────┘
```

<sub>Тестовые SBOM из репозитория, база Go с osv.dev, каталог KEV и оценки EPSS на сентябрь 2026. Пути сокращены.</sub>

## Чем отличается от Minefield

| | Minefield | Sapper 1.0 |
| --- | --- | --- |
| Отчёт по уязвимостям | — | `sapper report`: затронутые продукты, путь до каждого, таблица/Markdown/JSON |
| Приоритизация | — | CISA KEV, EPSS, OpenVEX |
| Записи одной уязвимости (GHSA, GO, CVE) | отдельные результаты | одна находка |
| Сборка | нужен cgo и компилятор C (SQLite) | один статический бинарник на чистом Go |
| База по умолчанию | в памяти, теряется при перезапуске | файл в папке данных пользователя |
| Хранилище SQLite | произвольные данные «not implemented» | реализовано |
| Зависимости из SBOM | связи dependsOn в CycloneDX терялись; с актуальным protobom связи «X_OF» читались задом наперёд | все связи зависимостей, в правильную сторону |
| Диапазоны версий | события сравнивались в неправильном порядке; версии ECOSYSTEM — как строки | по правилам OSV; 10.0 > 9.1, 1.0rc1 < 1.0 |
| Загрузка базы Go с osv.dev (9351 запись) | минуты, весь граф перечитывался на каждую запись | секунды |
| ZIP-архивы | распаковывались во временную папку и не удалялись | читаются в памяти |
| `sapper llm` | только OpenAI, нужна векторная база на диске сервера | любой OpenAI-совместимый API, включая Ollama |
| Зависимости | x/net и x/text с уязвимостями | актуальные; govulncheck чистый |
| Релизы | ни одного тега | бинарники для Linux, macOS и Windows; мультиархитектурный образ |

Полный список — в [журнале изменений](CHANGELOG.md).

## Установка

Скачайте бинарник из [релизов](https://github.com/Perruer/sapper/releases) (Linux, macOS, Windows; amd64 и arm64), или:

```bash
go install github.com/Perruer/sapper@latest
```

или запустите сервер в Docker:

```bash
docker run -d -p 127.0.0.1:8089:8089 -v sapper-data:/data ghcr.io/perruer/sapper
```

## Быстрый старт

```bash
sapper server &                                   # база — в папке данных пользователя

sapper ingest sbom ./sboms                        # CycloneDX или SPDX, JSON; файлы, папки или .zip
sapper ingest osv ./Go-all.zip                    # записи OSV, например https://osv-vulnerabilities.storage.googleapis.com/Go/all.zip
sapper ingest kev known_exploited_vulnerabilities.json
sapper ingest epss epss_scores-current.csv.gz
sapper ingest vex ./our-product.openvex.json      # по желанию
sapper cache                                      # предвычисляет граф для запросов и рейтингов

sapper report                                     # всё, самое срочное сверху
sapper report CVE-2023-44487 --format markdown    # одна уязвимость: продукты и пути
sapper report --kev-only --format json > kev.json
```

Откуда брать данные:

| Данные | Источник |
| --- | --- |
| SBOM | ваша сборка (Syft, cdxgen, Trivy, экспорт графа зависимостей GitHub...) |
| Записи OSV | [osv.dev](https://google.github.io/osv.dev/data/): `https://osv-vulnerabilities.storage.googleapis.com/<Ecosystem>/all.zip` |
| CISA KEV | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json |
| EPSS | https://epss.empiricalsecurity.com/epss_scores-current.csv.gz |
| VEX | ваши документы [OpenVEX](https://github.com/openvex/spec) |

Уязвимости загружайте после SBOM, а EPSS — после уязвимостей: сохраняются оценки только тех CVE, что есть в графе.

## Отчёт

`sapper report` показывает все уязвимости, которые доходят до продукта. Продукт — это узел, от которого ничего не зависит (обычно корневой компонент SBOM). Для каждой уязвимости выводятся уязвимые пакеты, все затронутые продукты с кратчайшим путём до каждого, степень опасности из бюллетеня, данные KEV (дата добавления, срок исправления, использование в вымогателях) и оценка EPSS.

Порядок: сначала уязвимости из KEV, затем по EPSS, затем по числу продуктов. Продукты, которые VEX помечает `not_affected` или `fixed`, выносятся в отдельный список. Фильтры: `--kev-only`, `--min-epss 0.1`, `--limit 20`. Форматы: `table`, `markdown`, `json`.

Вывод в Markdown и JSON подходит для тикетов и документации по соответствию требованиям, например для обработки уязвимостей и отчётности, которых Cyber Resilience Act ЕС требует от производителей. Sapper даёт факты, а что именно сообщать — решаете вы.

## Запросы к графу

```bash
sapper query custom "dependents library pkg:golang/golang.org/x/net@v0.23.0"
sapper query custom "dependencies vuln pkg:github.com/google/cadvisor@"
sapper query custom "dependents library pkg:A xor dependents library pkg:B"
sapper query globsearch "*GHSA*"
sapper leaderboard custom "dependents library"      # пакеты по числу зависящих от них
```

Запрос — это `dependencies|dependents <тип> <имя>`, где тип — `library` или `vuln`; запросы объединяются через `and`, `or`, `xor` и скобки. Имена — это package URL, как они записаны в ваших SBOM.

`sapper llm` превращает вопросы на обычном языке в такие запросы и работает с любым OpenAI-совместимым API:

```bash
SAPPER_LLM_API_KEY=sk-... sapper llm                                   # OpenAI
sapper llm --base-url http://localhost:11434/v1 --model qwen2.5-coder  # Ollama, без ключа
```

## Хранилище

По умолчанию сервер использует SQLite: `sapper.db` в `$SAPPER_DATA_DIR` или в папке данных пользователя (`~/.local/share/sapper`, `~/Library/Application Support/sapper`, `%LOCALAPPDATA%\sapper`). `--storage-path` задаёт другой файл, `--use-in-memory` держит базу в памяти. Для общего сервера подходит и Redis: `--storage-type redis --storage-addr host:6379`.

Сервер слушает `localhost:8089`, команды CLI обращаются к нему (`--addr`). API — [Connect](https://connectrpc.com/) (gRPC и JSON поверх HTTP), описан в [api/v1/service.proto](api/v1/service.proto).

## Разработка

```bash
go test ./...          # юнит- и сквозные тесты; Redis запускается прямо в процессе
make build             # bin/sapper
make generate          # после изменения api/v1/service.proto (нужен buf)
```

## Поддержать проект

Я поддерживаю Sapper в свободное время. Если он сэкономил вам день разбора CVE, можно поддержать проект:

- [Boosty](https://boosty.to/mikio_kuroki/donate)
- USDT / TRX (TRC-20): `TXUBW4e88SDTfrnJRKfbhYfFcggufbonc1`
- USDT / USDC / ETH (ERC-20): `0x1378491169064702786b2E5b58c6375776177E8A`
- TON / USDT (TON): `UQAhI7EKzoa-JuKOfv0ULMzA3FrmpxsDkXj8Qevwj2z1cMRN`

## Лицензия

[Apache-2.0](LICENSE), как у Minefield. Sapper — продолжение [Minefield](https://github.com/bitbomdev/minefield) от BitBom, см. [NOTICE](NOTICE). Исходный README сохранён в [docs/upstream-README.md](docs/upstream-README.md). Sapper не связан с BitBom и не одобрен ею.
