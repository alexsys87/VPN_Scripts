# deploy-hysteria2.sh — Hysteria2 (QUIC/UDP)

Разворачивает Hysteria2: ставит сервер, создаёт пользователей и TLS-сертификат, пишет конфиг, systemd-юнит и правила файрвола (UDP), при желании настраивает port hopping, проверяет работу самотестом (клиент `hysteria` в режиме клиента) и выдаёт ссылки `hysteria2://`.

## Установка одной командой

```bash
curl -fsSL https://raw.githubusercontent.com/alexsys87/VPN_Scripts/main/deploy-hysteria2.sh | sudo bash
```

С параметрами:

```bash
curl -fsSL https://raw.githubusercontent.com/alexsys87/VPN_Scripts/main/deploy-hysteria2.sh \
  | sudo bash -s -- --port 8443 --clients 5
```

Результат: ссылки `hysteria2://…` в терминале и в `/root/hysteria2-deploy/links.txt`; клиентский конфиг — `/root/hysteria2-deploy/client.yaml`.

## Параметры

| Параметр | По умолчанию | Описание |
|---|---|---|
| `--port PORT` | `443` | порт прослушивания (**UDP**) |
| `--ip IP` | из ссылок Xray, иначе авто | внешний IP для ссылок |
| `--clients N` | `3` | число пользователей |
| `--name PREFIX` | `hy2` | префикс имён/меток |
| `--domain DOMAIN` | — | сертификат Let's Encrypt (certbot standalone, нужен порт 80/tcp; домен должен указывать на сервер) |
| `--email EMAIL` | — | e-mail для ACME (только вместе с `--domain`) |
| `--hostname HOST` | маска-домен Xray, иначе `www.bing.com` | SNI/имя в самоподписанном сертификате |
| `--cert FILE --key FILE` | — | свой сертификат и ключ (нужен `--hostname`; несовместимо с `--domain`) |
| `--masq URL` | авто | сайт, на который проксируются не-Hysteria HTTP/3 посетители |
| `--obfs` | — | обфускация Salamander (скрывает QUIC, отключает HTTP/3-маскировку, нужен поддерживающий клиент) |
| `--hop RANGE` | — | UDP port hopping, например `20000-50000` |
| `--bin PATH` | — | локальный бинарник hysteria |
| `--workdir DIR` | `/root/hysteria2-deploy` | `links.txt`, `client.yaml`, бэкапы |
| `--force` | — | пересоздать пользователей, пароли, ключ obfs и самоподписанный сертификат |
| `--uninstall` | — | удалить только Hysteria2 (Xray и TrustTunnel не затрагиваются) |
| `--check` | — | диагностика, включая живой тест туннеля и состояние Xray/TrustTunnel |
| `--fix` | — | автоисправление (рестарт, hardening, файрвол, port hopping, продление LE-сертификата); пароли не меняет |
| `--no-harden` | — | не применять hardening |
| `--skip-test` | — | не запускать самотест |
| `--dry-run` | — | сгенерировать конфиг и ссылки, систему не менять |

Версию можно зафиксировать: `HY_VERSION=2.14.0 bash deploy-hysteria2.sh`.

## Как сменить порт

Запустите скрипт ещё раз с новым `--port`:

```bash
sudo bash deploy-hysteria2.sh --port 8443
```

Порт хранится в `/etc/hysteria/.deploy-state`, поэтому:

- **без** `--port` повторный запуск оставляет текущий порт;
- **с** `--port` порт меняется, а пользователи, пароли, сертификат, режим сертификата, диапазон `--hop`, `--obfs` и `--masq` сохраняются.

Что нужно учесть:

- Порт UDP. В файрволе (в том числе у хостера) открывайте именно **UDP**.
- Если используется port hopping, правило перенаправления привязано к порту (`REDIRECT --to-ports <PORT>`). После смены порта проверьте, что активно правило на новый порт, и удалите устаревшее:
  ```bash
  iptables -t nat -S PREROUTING | grep hysteria-hop
  ```
- Правило файрвола для старого порта вручную не удаляется — закройте его сами (`ufw status`, `iptables -S INPUT`).
- Скрипт откажется от порта, конфликтующего с Xray или TrustTunnel.
- Раздайте клиентам новые ссылки из `links.txt`.

## Как обновить Hysteria 2 на сервере

Повторный запуск скрипта с нужной версией скачивает новый бинарник (если установленная версия отличается), а пользователи, пароли, сертификат, порт и port hopping **сохраняются** — ссылки клиентов остаются рабочими. **Не используйте `--force`**: он пересоздаёт пароли.

```bash
# 0) бэкап бинарника (откат конфига скрипт делает сам, бинарника — нет)
cp -a /usr/local/bin/hysteria /usr/local/bin/hysteria.bak

# 1) обновление: версия — https://github.com/apernet/hysteria/releases (тег app/vX.Y.Z)
curl -fsSL https://raw.githubusercontent.com/alexsys87/VPN_Scripts/main/deploy-hysteria2.sh \
  | sudo env HY_VERSION=2.14.0 bash
```

Если скрипт уже скачан: `sudo env HY_VERSION=2.14.0 bash deploy-hysteria2.sh`. Если версия в самом скрипте уже актуальна, `HY_VERSION` можно не указывать.

Проверка:

```bash
/usr/local/bin/hysteria version
systemctl is-active hysteria-server
sudo bash deploy-hysteria2.sh --check
```

Откат бинарника: `install -m 0755 /usr/local/bin/hysteria.bak /usr/local/bin/hysteria && systemctl restart hysteria-server`.

Hysteria 2 — один бинарник и для сервера, и для клиента (самотест использует его же), отдельно клиент обновлять не нужно.

## Примеры

```bash
# Let's Encrypt для домена
sudo bash deploy-hysteria2.sh --domain vpn.example.com --email admin@example.com

# Свой сертификат
sudo bash deploy-hysteria2.sh --cert /path/fullchain.pem --key /path/key.pem --hostname vpn.example.com

# Port hopping: клиенты используют диапазон, сервер слушает один порт
sudo bash deploy-hysteria2.sh --port 443 --hop 20000-50000

# Salamander-обфускация
sudo bash deploy-hysteria2.sh --obfs

# Диагностика и починка
sudo bash deploy-hysteria2.sh --check
sudo bash deploy-hysteria2.sh --fix

# Ротация паролей
sudo bash deploy-hysteria2.sh --force

# Удаление
sudo bash deploy-hysteria2.sh --uninstall
```

## Сертификаты

| Режим | Как включить | Особенности |
|---|---|---|
| Самоподписанный (по умолчанию) | без параметров, опционально `--hostname` | в ссылку добавляются `insecure=1` и `pinSHA256`, клиент всё равно проверяет сервер; клиенты без поддержки `pinSHA256` работают как insecure |
| Let's Encrypt | `--domain` (+ `--email`) | нужен свободный порт 80/tcp на время выпуска; продление через deploy-hook; проверяется и чинится через `--check`/`--fix` |
| Свой | `--cert` + `--key` + `--hostname` | — |

## Port hopping

`--hop 20000-50000` добавляет правило iptables/nft, перенаправляющее весь UDP-диапазон на основной порт сервера. Диапазон должен лежать в 1024–65535 и не пересекаться с прослушиваемыми UDP-портами. Правила помечены тегом `hysteria-hop` и удаляются при `--uninstall`.

## Файлы и сервис

| Что | Где |
|---|---|
| Конфиг | `/etc/hysteria/config.yaml` |
| Состояние установки | `/etc/hysteria/.deploy-state` |
| Бинарник | `/usr/local/bin/hysteria` |
| Сервис | `hysteria-server` — `systemctl status hysteria-server`, `journalctl -u hysteria-server -n 50` |
| Hardening | `/etc/sysctl.d/99-hysteria-hardening.conf` (буферы UDP, MTU probing, BBR/fq) |
| Ссылки, клиентский конфиг, бэкапы | `/root/hysteria2-deploy/` |

## Заметки

- Работает на Debian/Ubuntu (systemd), amd64 и arm64.
- Маскировка работает по UDP (HTTP/3); TCP 443 остаётся за Xray.
- Все добавленные правила файрвола помечены тегом `hysteria`; при `--uninstall` удаляются только они.
