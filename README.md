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
- `POST /api/firewall/defaults` — обновление политики по умолчанию
- `GET /api/nat` — список правил NAT (с количеством срабатываний)
- `POST /api/nat` — добавление правила NAT
- `GET /api/qos` — список классов QoS
- `POST /api/qos` — добавление класса QoS
- `GET /api/stats` — базовая статистика (пакеты/байты/ошибки/дропы/причины/классы QoS)

## Примечания

- Для Linux и Windows предусмотрены отдельные заглушки PacketIO; низкоуровневый захват пакетов требует прав и платформенных библиотек.
- Метрики доступны на `/metrics`.
