# UPSTREAM — зафиксированные версии REALITY/uTLS

Фиксация от 2026-10-08. Источник: go.mod Xray-core v26.3.27.

## Xray-core
- Repo: https://github.com/XTLS/Xray-core
- Tag: v26.3.27
- SHA:  d2758a023cdf4174a5a5faaff66e487d4342ba0
- Дата релиза: 2026-03-27
- Лицензия: MPL-2.0

## XTLS/REALITY
- Repo: https://github.com/xtls/reality
- Версия (из go.mod): v0.0.0-20260322125925-9234c772ba8f
- Полный SHA: 9234c772ba8f181f31c3e81dc2b4177322e5a9a9
- Дата пина: 2026-03-22
- Размер модуля: ~16.7 КБ
- Примечание: пинится Xray-core. Свежие коммиты (сентябрь 2026) требуют X25519MLKEM768 и несовместимы с uTLS v1.8.3 от 01.03.2026. НЕ обновлять отдельно.

## uTLS
- Repo: https://github.com/refraction-networking/utls
- Версия: v1.8.3-0.20260301010127-aa6edf4b11af
- SHA: aa6edf4b11af
- Дата пина: 2026-03-01

## Публичный API REALITY (Xray-обёртка, transport/internet/reality/reality.go)

    func Server(c net.Conn, config *reality.Config) (net.Conn, error)
    func UClient(c net.Conn, config *Config, ctx context.Context, dest net.Destination) (net.Conn, error)

Обе функции принимают готовый net.Conn и возвращают проверенный net.Conn.
REALITY спроектирован как библиотека, форк НЕ требуется.

## Зависимость, требующая решения

Xray-обёртка UClient принимает `net.Destination` из `xray-core/common/net`.
Варианты на этапе интеграции:
1. Подключить xray-core/common/net как лёгкую зависимость (без тяжёлых частей Xray).
2. Форкнуть обёртку, заменив net.Destination на string (одна правка).

Решение отложено до начала интеграции.

## Правила обновления
- Обновлять Xray-core, REALITY и uTLS только вместе, как одну связку.
- После обновления: сборка Windows + Linux, положительный handshake, отрицательный handshake, отсутствие утечки прикладных данных.
- Не использовать плавающие версии и latest.
