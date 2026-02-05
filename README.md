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
- `GET /api/ha/status` — статус HA (роль/пиры)
- `GET /api/ha/state` — текущее состояние (для синхронизации)
- `POST /api/ha/state` — применить состояние (failover)
- `GET /api/observability/traces` — последние API‑трейсы
- `GET /api/observability/alerts` — последние алерты
- `GET /api/stats` — базовая статистика (rx/tx/пакеты/байты/ошибки/дропы/причины/классы QoS/конфиг/p2p/proxy)

## План: раздел настроек UI

Архитектура:
- Главное меню: «Настройки» → {категория}
- Каждая категория — отдельная страница с кратким описанием, панелью действий (Сохранить, Отменить, Справка) и поиском по параметрам.

### 1) Интерфейсы
- URL: `/settings/interfaces`
- Таблица: Имя, Статус (Up/Down), IP/маска, MAC, Скорость, Тип (WAN/LAN/Guest/VPN)
- Кнопки: Включить/Отключить, Редактировать (модалка), Добавить интерфейс
- Форма: IP/маска, DHCP клиент, VLAN ID, MTU (1500), Описание

### 2) Маршрутизация
- URL: `/settings/routing`
- Статические маршруты: Destination, Gateway, Interface, Metric, Comment; Добавить/Удалить
- Динамическая маршрутизация: OSPF/BGP/RIP, AS Number, Router ID
- Политики маршрутизации: правила по источнику/назначению/протоколу/порту → таблица маршрутизации X
- Форма маршрута: Destination, Gateway, Interface, Metric, Comment

### 3) Firewall
- URL: `/settings/firewall`
- Вкладки: Зоны (WAN/LAN/Guest), Правила, Цепочки (INPUT/FORWARD/OUTPUT)
- Правила: Zone, Protocol, Port, Source, Destination, Action, Status + фильтры
- Форма: Зона, Протокол (TCP/UDP/ICMP/ALL), Порт/диапазон, Источник, Назначение, Action (ACCEPT/DROP/REJECT/LOG), Статус, Комментарий

### 4) NAT
- URL: `/settings/nat`
- Подразделы: SNAT, DNAT, Masquerade
- SNAT: Interface, Source, Translation IP, Comment; Добавить SNAT
- DNAT: Interface, Destination Port, Translation IP:Port, Protocol, Comment; Добавить DNAT
- Masquerade: чекбокс на интерфейсе
- Формы SNAT/DNAT: интерфейс, источник/порт, перевод в IP или IP:Port, протокол, комментарий

### 5) VPN
- URL: `/settings/vpn`
- Site-to-Site (IPsec/WireGuard): Name, Local Subnet, Remote Subnet, Status; Добавить/Скачать конфиг
- Remote Access (OpenVPN/WireGuard): User, Protocol, IP, Connected Since; Добавить пользователя/Сертификат
- Client VPN: подключение к внешнему VPN (.ovpn/.conf)
- Формы: туннель (подсети, ключи, endpoint), remote access (пользователь, пароль, сертификат, разрешенные подсети)

### 6) DHCP
- URL: `/settings/dhcp`
- Серверы: Interface, Range, Lease Time, DNS Servers; Добавить
- Резервации: MAC, IP, Hostname, Comment; Добавить
- Опции: Router, DNS, Domain Name
- Формы: диапазон, время аренды, DNS, домен, резервации по MAC

### 7) QoS
- URL: `/settings/qos`
- Классы: Name, Priority, Bandwidth Limit, DSCP; Добавить
- Правила классификации: Source, Destination, Protocol, Port, Class; Добавить
- Очереди: визуальный график распределения полосы
- Формы: класс (приоритет, лимит, DSCP), правило (src/dst, протокол, порт, класс)

### 8) Мониторинг и логи
- URL: `/settings/monitoring`
- Статистика интерфейсов: графики Rx/Tx, ошибки, дропы, realtime
- Логи firewall: Timestamp, Rule, Action, Source, Destination + фильтры
- Сессии NAT: Internal IP:Port, External IP:Port, Protocol, Timeout
- Системные логи: поток `/var/log/syslog` + поиск

### 9) Система и безопасность
- URL: `/settings/system`
- Обновления: проверка, загрузка .deb/.rpm
- Резервное копирование: создать/восстановить/расписание
- Пользователи: Username, Role, Last Login + формы
- SSL/TLS: загрузка сертификата и ключа
- Время: NTP серверы, часовой пояс

### 10) API и интеграции
- URL: `/settings/api`
- API ключи: Key, Scope, Created, Revoke; Генерация ключа
- Webhook: список URL, Добавить endpoint
- Экспорт конфигурации: JSON, YAML, CLI скрипт

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

HA (active-passive):

```yaml
ha:
  enabled: true
  node_id: node-1
  priority: 100
  heartbeat_interval_seconds: 2
  hold_seconds: 6
  bind_addr: :5356
  multicast_addr: 224.0.0.252:5356
  peers:
    - http://127.0.0.1:8080
  state_sync_interval_seconds: 5
  state_endpoint_path: /api/ha/state
```

Observability:

```yaml
observability:
  enabled: true
  traces_limit: 1000
  pprof_enabled: false
  pprof_path: /debug/pprof
  alerts_enabled: true
  alerts_limit: 1000
  alert_interval_seconds: 10
  drops_threshold: 100
  errors_threshold: 10
  ids_alerts_threshold: 5
```

При включённом `pprof_enabled` доступны профили по пути `pprof_path` (например, `/debug/pprof/`).

Performance:

```yaml
performance:
  egress_batch_size: 16
  egress_idle_sleep_millis: 2
```

## Примечания

- Для Linux и Windows предусмотрены отдельные заглушки PacketIO; низкоуровневый захват пакетов требует прав и платформенных библиотек.
- Метрики доступны на `/metrics`.
