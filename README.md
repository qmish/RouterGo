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

## REST API

- `GET /api/routes` — список маршрутов
- `POST /api/firewall` — добавление правила
- `GET /api/firewall` — список правил firewall
- `GET /api/firewall/defaults` — политики по умолчанию
- `POST /api/firewall/defaults` — обновление политики по умолчанию
- `GET /api/nat` — список правил NAT
- `POST /api/nat` — добавление правила NAT
- `GET /api/qos` — список классов QoS
- `POST /api/qos` — добавление класса QoS
- `GET /api/stats` — базовая статистика (пакеты/байты/ошибки)

## Примечания

- Для Linux и Windows предусмотрены отдельные заглушки PacketIO; низкоуровневый захват пакетов требует прав и платформенных библиотек.
- Метрики доступны на `/metrics`.
