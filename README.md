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
- `GET /api/stats` — базовая статистика (rx/tx/пакеты/байты/ошибки/дропы/причины/классы QoS/конфиг/p2p)

## Примечания

- Для Linux и Windows предусмотрены отдельные заглушки PacketIO; низкоуровневый захват пакетов требует прав и платформенных библиотек.
- Метрики доступны на `/metrics`.
