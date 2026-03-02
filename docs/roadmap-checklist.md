# RouterGo Roadmap Checklist (Q2 2026)

Этот файл фиксирует поэтапный план разработки и текущий прогресс.
Статус обновляется по факту изменений в коде и тестах.

## Stage 1 - P0 Dataplane Correctness

- [x] NAT переписывает реальные байты пакета (`Packet.Data`) и пересчитывает checksums (IPv4 header + TCP/UDP; IPv6 TCP/UDP).
- [x] Route lookup влияет на фактический выбор `EgressInterface` в packet pipeline.
- [x] Убрано ограничение single-interface: packet loop запускается для нескольких интерфейсов.
- [x] Egress выбирает writer по `EgressInterface` (с fallback на default writer).
- [x] Добавлены интеграционные тесты "NAT + routing + firewall" на packet pipeline.
- [x] Нагрузочный smoke-test для pps/latency/drop rate.

## Stage 2 - P0 Config Safety

- [x] `validate -> plan -> apply` для применения конфигурации.
- [x] Атомарное применение конфигурации (all-or-nothing).
- [x] Гарантированный rollback к консистентному snapshot.
- [x] Тесты невалидного конфига и rollback сценариев.

## Stage 3 - P0 Persistence and Audit

- [ ] Персистентное хранение правил/политик/снапшотов.
- [ ] Версионирование конфигов и diff между версиями.
- [ ] Audit trail изменений (кто/когда/что).
- [ ] Backup/restore и проверка восстановления.

## Stage 4 - Security Baseline

- [ ] RBAC для API/UI.
- [ ] API keys со scope и ротацией.
- [ ] TLS/mTLS hardening для управляющего контура.
- [ ] Security checks в CI (dependency scanning + policy gate).

## Stage 5 - Product UX and Pilot Readiness

- [ ] Завершение всех страниц settings/dashboard.
- [ ] Setup wizard первичной настройки.
- [ ] Presets для типовых сценариев.
- [ ] Pilot-pack (quickstart, runbook, troubleshooting) и KPI пилота.

## Progress Log

- [x] 2026-03-02: Создан `docs/roadmap-checklist.md` и зафиксирован поэтапный план.
- [x] 2026-03-02: В `cmd/router/main.go` route lookup начал выставлять `pkt.EgressInterface`.
- [x] 2026-03-02: В `cmd/router/main.go` packet loop переведен на несколько интерфейсов (multi-ingress).
- [x] 2026-03-02: В `cmd/router/main.go` egress отправка переведена на writer resolver по `EgressInterface`.
- [x] 2026-03-02: Добавлены тесты в `cmd/router/main_test.go` и `cmd/router/egress_test.go` для новых сценариев маршрутизации egress.
- [x] 2026-03-02: Добавлен интеграционный тест pipeline `NAT + routing + firewall` в `cmd/router/main_test.go`.
- [x] 2026-03-02: В `pkg/nat/nat.go` добавлен NAT rewrite на уровне `Packet.Data` и пересчет checksums.
- [x] 2026-03-02: Добавлены тесты `TestApplySNATRewritesIPv4UDPData` и `TestApplyDNATRewritesIPv4UDPData` в `pkg/nat/nat_test.go`.
- [x] 2026-03-02: Добавлен `TestSmokePacketPipelineThroughput` (`cmd/router/smoke_test.go`) и зафиксирован baseline в `docs/performance-smoke.md`.
- [x] 2026-03-02: Реализован API-процесс `validate -> plan -> apply` (`POST /api/config/plan`, обновлен `/api/config/apply`) с тестами.
- [x] 2026-03-02: Усилен atomic apply (plan+revision), rollback сделан стековым и консистентным; добавлены тесты невалидного apply/plan и rollback без snapshot.
