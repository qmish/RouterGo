# RouterGo

Прототип программного роутера на Go с модульной архитектурой. Проект закладывает основу для L3‑маршрутизации, NAT, firewall, QoS, REST API и метрик.

## Требования

- Go 1.20+ (для установки зависимостей и сборки)

## Сборка и запуск

```bash
go mod tidy
go build -o router cmd/router/main.go
./router --config config/config.yaml
```

Генерация ключей P2P:

```bash
go build -o p2pkeygen cmd/p2pkeygen/main.go
./p2pkeygen --pub p2p_public.key --priv p2p_private.key
```

## Конфигурация

Пример конфигурации находится в `config/config.yaml`.
По умолчанию политики firewall задаются в `firewall_defaults` (input/output/forward).
Для QoS доступен параметр `drop_policy` (tail/head) при заполнении очереди.

## REST API

- `GET /api/routes` — список маршрутов
- `POST /api/firewall` — добавление правила
- `GET /api/firewall` — список правил firewall (с количеством срабатываний)
- `GET /api/firewall/defaults` — политики по умолчанию
- `GET /api/firewall/stats` — статистика по цепочкам
- `POST /api/firewall/reset` — сброс статистики firewall
- `POST /api/firewall/defaults` — обновление политики по умолчанию
- `GET /api/ids/rules` — список IDS правил
- `POST /api/ids/rules` — добавление IDS правила
- `GET /api/ids/alerts` — список IDS алертов
- `POST /api/ids/reset` — сброс IDS состояния
- `GET /api/nat` — список правил NAT (с количеством срабатываний)
- `POST /api/nat/reset` — сброс статистики NAT
- `POST /api/nat` — добавление правила NAT
- `GET /api/qos` — список классов QoS
- `POST /api/qos` — добавление класса QoS
- `POST /api/config/apply` — применить конфигурацию (self-heal)
- `POST /api/config/rollback` — откат к последнему снапшоту
- `GET /api/config/snapshots` — список снапшотов
- `GET /api/dashboard/top/bandwidth` — топ потребителей трафика
- `GET /api/dashboard/sessions/tree` — дерево сессий
- `GET /api/dashboard/alerts` — алерты в реальном времени
- `/dashboard` — статические страницы Web Dashboard
- `GET /api/p2p/peers` — список P2P соседей
- `GET /api/p2p/routes` — синхронизированные маршруты
- `POST /api/p2p/reset` — сброс состояния P2P
- `GET /api/proxy/stats` — статистика прокси/кэша
- `POST /api/proxy/cache/clear` — очистка кэша
- `GET /api/enrich/ip?ip=1.1.1.1` — обогащение IP (GeoIP/ASN/Threat)
- `GET /api/stats` — базовая статистика (rx/tx/пакеты/байты/ошибки/дропы/причины/классы QoS/конфиг/p2p/proxy)

## Формат ключей P2P

- Файлы `p2p_public.key` и `p2p_private.key` содержат HEX‑строку без префиксов.
- `p2p_public.key` — 32 байта (64 hex‑символа).
- `p2p_private.key` — 64 байта (128 hex‑символов).

## Примеры конфигурации

P2P с подписями:

```yaml
p2p:
  enabled: true
  peer_id: node-1
  discovery: true
  listen_addr: :5355
  multicast_addr: 224.0.0.251:5355
  sync_interval: 10
  peer_ttl_seconds: 30
  private_key_file: p2p_private.key
  public_key_file: p2p_public.key
```

Интеграции:

```yaml
integrations:
  timeout_seconds: 3
  geoip:
    enabled: true
    mmdb_path: GeoLite2-City.mmdb
    http_url: ""
    http_token: ""
  asn:
    enabled: true
    token: "IPINFO_TOKEN"
  threat_intel:
    enabled: true
    api_key: "ABUSEIPDB_KEY"
  logs:
    enabled: true
    loki_url: "http://localhost:3100/loki/api/v1/push"
    elastic_url: "http://localhost:9200/routergo/_doc"
  metrics:
    enabled: true
    remote_write_url: "http://localhost:9090/api/v1/write"
    interval_seconds: 10
```

## Примечания

- Для Linux и Windows предусмотрены отдельные заглушки PacketIO; низкоуровневый захват пакетов требует прав и платформенных библиотек.
- Метрики доступны на `/metrics`.
