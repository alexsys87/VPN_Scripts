# deploy-trusttunnel.sh — TrustTunnel

Разворачивает endpoint TrustTunnel (протокол AdGuard VPN: HTTP/1.1 + HTTP/2 поверх TLS по TCP и HTTP/3 поверх QUIC по UDP): ставит сервер, создаёт пользователей и TLS-сертификат, пишет `vpn.toml`, `hosts.toml`, `credentials.toml`, systemd-юнит и правила файрвола (TCP+UDP), проверяет работу официальным CLI-клиентом (HTTP/2 и HTTP/3) и выдаёт deep-ссылки `tt://`.

## Установка одной командой

```bash
curl -fsSL https://raw.githubusercontent.com/alexsys87/VPN_Scripts/main/deploy-trusttunnel.sh | sudo bash
```

С параметрами:

```bash
curl -fsSL https://raw.githubusercontent.com/alexsys87/VPN_Scripts/main/deploy-trusttunnel.sh \
  | sudo bash -s -- --port 9443 --clients 5
```

Результат: ссылки `tt://…` в терминале и в `/root/trusttunnel-deploy/links.txt`.

## Параметры

| Параметр | По умолчанию | Описание |
|---|---|---|
| `--port PORT` | `8443` | порт прослушивания, **TCP и UDP** (443/tcp занят Xray) |
| `--ip IP` | из ссылок Xray, иначе авто | внешний IP для ссылок |
| `--clients N` | `3` | число пользователей |
| `--name PREFIX` | `tt` | префикс имён пользователей/меток |
| `--domain DOMAIN` | — | сертификат Let's Encrypt (certbot standalone, нужен 80/tcp; домен должен указывать на сервер) |
| `--email EMAIL` | — | e-mail для ACME |
| `--hostname HOST` | случайный `www.<x>.com` | TLS-имя (SNI) для самоподписанного сертификата |
| `--cert FILE --key FILE` | — | свой сертификат и ключ |
| `--dns UPSTREAM` | `tls://1.1.1.1` | DNS-апстрим, прописываемый в клиентские ссылки |
| `--archive FILE` | — | локальный `trusttunnel-*.tar.gz` вместо скачивания |
| `--workdir DIR` | `/root/trusttunnel-deploy` | `links.txt` и бэкапы |
| `--force` | — | пересоздать пользователей, пароли и самоподписанный сертификат |
| `--uninstall` | — | удалить только TrustTunnel (Xray, его правила и hardening остаются) |
| `--check` | — | диагностика, включая совместную работу с Xray |
| `--fix` | — | автоисправление (рестарт, hardening, порты в файрволе, продление LE-сертификата); конфиги и пароли не меняет |
| `--no-harden` | — | не применять hardening |
| `--skip-test` | — | не запускать самотест клиентом |
| `--dry-run` | — | сгенерировать конфиги (и ссылки, если бинарник уже есть), систему не менять |

Версии можно зафиксировать переменными окружения: `TT_VERSION` (по умолчанию `1.3.1`) и `TT_CLIENT_VERSION` (по умолчанию `1.3.0`).

## Как сменить порт

Запустите скрипт ещё раз с новым `--port`:

```bash
sudo bash deploy-trusttunnel.sh --port 9443
```

Порт хранится в `/opt/trusttunnel/.deploy-state`:

- **без** `--port` повторный запуск оставляет текущий порт;
- **с** `--port` порт меняется (в `vpn.toml` — `listen_address = "0.0.0.0:<порт>"`), а пользователи, пароли, сертификат и hostname сохраняются.

Что нужно учесть:

- Порт открывается и для **TCP**, и для **UDP**; то же самое сделайте во внешнем файрволе хостера.
- Скрипт откажется от порта, который использует Xray, и вообще от занятого порта.
- Правило файрвола для старого порта автоматически не удаляется — закройте вручную (`ufw status`, `iptables -S INPUT`).
- Ссылки `tt://` содержат порт — раздайте клиентам новые из `links.txt`.
- Менять только `listen_address` вручную в `vpn.toml` не рекомендуется: файрвол и ссылки останутся со старым портом. Используйте повторный запуск скрипта.

## Как обновить TrustTunnel на сервере

Повторный запуск скрипта с нужными версиями скачивает новый endpoint (если установленная версия отличается), а пользователи, пароли, сертификат, hostname и порт **сохраняются** — ссылки `tt://` остаются рабочими. **Не используйте `--force`**: он пересоздаёт пароли и самоподписанный сертификат.

```bash
# 0) бэкап бинарника (откат конфига скрипт делает сам, бинарника — нет)
cp -a /opt/trusttunnel/trusttunnel_endpoint /opt/trusttunnel/trusttunnel_endpoint.bak

# 1) обновление: версии — https://github.com/TrustTunnel/TrustTunnel/releases
#    и https://github.com/TrustTunnel/TrustTunnelClient/releases (только стабильные, без -rc/-beta)
curl -fsSL https://raw.githubusercontent.com/alexsys87/VPN_Scripts/main/deploy-trusttunnel.sh \
  | sudo env TT_VERSION=1.3.1 TT_CLIENT_VERSION=1.3.0 bash
```

Если скрипт уже скачан: `sudo env TT_VERSION=1.3.1 TT_CLIENT_VERSION=1.3.0 bash deploy-trusttunnel.sh`. Если версии в самом скрипте уже актуальны, переменные можно не указывать.

- **Endpoint** (`TT_VERSION`) — серверный бинарник `/opt/trusttunnel/trusttunnel_endpoint`, он заменяется на сервере.
- **CLI-клиент** (`TT_CLIENT_VERSION`) на сервере постоянно не хранится: он скачивается во временную папку при каждом запуске только для самотеста (HTTP/2 и HTTP/3) и удаляется. «Обновление» клиента — это новое значение `TT_CLIENT_VERSION` при запуске. Приложения на устройствах пользователей обновляются отдельно.

Проверка:

```bash
/opt/trusttunnel/trusttunnel_endpoint --version
systemctl is-active trusttunnel
sudo bash deploy-trusttunnel.sh --check
```

Откат бинарника: `install -m 0755 /opt/trusttunnel/trusttunnel_endpoint.bak /opt/trusttunnel/trusttunnel_endpoint && systemctl restart trusttunnel`.

## Примеры

```bash
# Let's Encrypt для реального домена (лучшая маскировка)
sudo bash deploy-trusttunnel.sh --domain vpn.example.com --email admin@example.com

# Свой сертификат
sudo bash deploy-trusttunnel.sh --cert /path/fullchain.pem --key /path/key.pem

# Другой DNS для клиентов
sudo bash deploy-trusttunnel.sh --dns tls://9.9.9.9

# Установка из локального архива
sudo bash deploy-trusttunnel.sh --archive ./trusttunnel-linux-x86_64.tar.gz

# Диагностика и починка
sudo bash deploy-trusttunnel.sh --check
sudo bash deploy-trusttunnel.sh --fix

# Ротация паролей
sudo bash deploy-trusttunnel.sh --force

# Удаление
sudo bash deploy-trusttunnel.sh --uninstall
```

## Сертификаты

| Режим | Как включить | Особенности |
|---|---|---|
| Самоподписанный (по умолчанию) | без параметров, опционально `--hostname` | встраивается в ссылку `tt://` (поддерживается CLI-клиентом и актуальными приложениями TrustTunnel) |
| Let's Encrypt | `--domain` (+ `--email`) | нужен 80/tcp на время выпуска; продление через deploy-hook; для максимальной маскировки |
| Свой | `--cert` + `--key` | — |

## Файлы и сервис

| Что | Где |
|---|---|
| Каталог установки и конфиги | `/opt/trusttunnel/` — `vpn.toml`, `hosts.toml`, `credentials.toml` |
| Состояние установки | `/opt/trusttunnel/.deploy-state` |
| Бинарник | `/opt/trusttunnel/trusttunnel_endpoint` |
| Сервис | `trusttunnel` — `systemctl status trusttunnel`, `journalctl -u trusttunnel -n 50` |
| Hardening | `/etc/sysctl.d/99-trusttunnel-hardening.conf` (UDP-буферы ≥ 7 МБ для QUIC, MTU probing, BBR/fq; MSS clamp — только если его ещё нет у Xray) |
| Ссылки и бэкапы | `/root/trusttunnel-deploy/` |

## Заметки

- Работает на Debian/Ubuntu (systemd), x86_64 и aarch64.
- Все добавленные правила файрвола помечены тегом `trusttunnel`; при `--uninstall` удаляются только они.
- Здоровье Xray проверяется до и после установки, но конфиг, юнит, файрвол и sysctl Xray скрипт не меняет.
