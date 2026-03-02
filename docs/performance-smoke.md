# Stage 1 Performance Smoke

Быстрый базовый smoke-test для packet pipeline (routing + NAT + firewall + QoS dequeue).

## Команда

```bash
go test -run TestSmokePacketPipelineThroughput -v ./cmd/router
```

## Baseline (2026-03-02)

- iterations: `50000`
- processed: `50000`
- dropped: `0`
- elapsed: `34.2019ms`
- pps: `1461907.09`
- drop_rate: `0.00%`

## Notes

- Тест не заменяет полноценный synthetic load test с реальным PacketIO.
- Используется как быстрый регрессионный индикатор для Stage 1.
