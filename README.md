# SimpleDesk Server

SimpleDesk ist ein Fork des kostenlosen RustDesk-Servers ([rustdesk/rustdesk-server](https://github.com/rustdesk/rustdesk-server)) unter derselben Lizenz (AGPL-3.0). Ziel: Alles läuft über Port 443, auch wenn eine Firewall nur Webseiten durchlässt.

## Änderungen gegenüber dem RustDesk-Server

- Geräte können sich auch über TCP und WebSocket anmelden, nicht nur über UDP. Die Verbindung bleibt offen, der Server schickt alle 20 Sekunden ein Lebenszeichen, und Anfragen anderer Geräte kommen über diese Verbindung.
- Neuer Schalter `WS_ONLY=Y` für hbbs und hbbr: Nur die WebSocket-Ports (21118 und 21119) lauschen auf der Bind-Adresse, alle anderen Ports nur auf 127.0.0.1. Verbindungen laufen dann immer über das Relay.
- Ein Gerät kann seine ID ändern (`--set-id`).
- Web-Panel in hbbs auf Port 21114: Einrichten, Anmelden, Geräteliste mit Online-Status, persönliches Adressbuch. Abschalten mit `PANEL=N`.
- API für den Client auf demselben Port: Anmelden mit dem Panel-Konto und persönliches Adressbuch mit Einträgen und Tags. Heartbeat und Systeminfo werden ruhig beantwortet.

## Web-Panel einrichten

Beim ersten Start ohne Admin schreibt hbbs einen Setup-Code ins Log, zum Beispiel `docker logs hbbs`. Auf der ersten Seite des Panels gibst du den Code ein und legst den Admin an. Danach gilt der Code nicht mehr.

## Anmeldung über Eider oder einen anderen OIDC-Anbieter

Panel und Client können sich über OpenID Connect anmelden, zum Beispiel über Eider. Dann prüft der Anbieter Passwort und zweiten Faktor, SimpleDesk bekommt nur den Namen. Einstellungen für hbbs:

| Variable | Bedeutung |
|---|---|
| `OIDC_ISSUER` | Adresse des Anbieters, zum Beispiel `https://eider.example`. Ohne sie ist die Anmeldung über einen Anbieter aus. |
| `OIDC_CLIENT_ID` | Client-ID beim Anbieter, Standard `simpledesk` |
| `OIDC_CLIENT_SECRET` | Geheimnis des Clients beim Anbieter |
| `OIDC_NAME` | Name auf dem Knopf, Standard `Eider` |
| `PANEL_URL` | öffentliche Adresse des Panels, zum Beispiel `https://remote.example`. Die Rücksprung-Adresse ist `PANEL_URL/oidc/callback`. |

Der Anbieter muss Discovery, den Code-Flow mit PKCE (S256) und ein ID-Token mit HS256 und dem Client-Geheimnis können. Ein Konto aus dem Anbieter hat hier kein eigenes Passwort.

## Betrieb nur über Port 443

1. hbbs und hbbr mit `WS_ONLY=Y` starten.
2. Einen Reverse Proxy mit HTTPS davorsetzen: `/ws/id` an Port 21118, `/ws/relay` an Port 21119 und alles andere (`/`) an Port 21114 für das Web-Panel. Der Proxy muss `X-Real-IP` setzen.
3. Die Ports 21114, 21118 und 21119 dürfen nur für den Proxy erreichbar sein, nicht aus dem Internet. Der Server übernimmt die IP aus `X-Real-IP` ungeprüft.
4. In jedem RustDesk-Client `allow-websocket` auf `Y` setzen und als API-Server `https://<deine Domain>` eintragen. Der SimpleDesk-Client hat das schon eingebaut.

---

# RustDesk Server Program

[![build](https://github.com/rustdesk/rustdesk-server/actions/workflows/build.yaml/badge.svg)](https://github.com/rustdesk/rustdesk-server/actions/workflows/build.yaml)

[**Download**](https://github.com/rustdesk/rustdesk-server/releases)

[**Manual**](https://rustdesk.com/docs/en/self-host/)

[**Configuration & environment variables**](docs/environment-variables.md)

[**FAQ**](https://github.com/rustdesk/rustdesk/wiki/FAQ)

[**How to migrate OSS to Pro**](https://rustdesk.com/docs/en/self-host/rustdesk-server-pro/installscript/#convert-from-open-source)

Self-host your own RustDesk server, it is free and open source.

> [!IMPORTANT]
> **Need more features?** [RustDesk Server Pro](https://rustdesk.com/pricing.html) might suit you better.
>
> **Want to develop your own server?** Start with [rustdesk-server-demo](https://github.com/rustdesk/rustdesk-server-demo), a simpler starting point than this repository.

## How to build manually

```bash
cargo build --release
```

Three executables will be generated in target/release.

- hbbs - RustDesk ID/Rendezvous server
- hbbr - RustDesk relay server
- rustdesk-utils - RustDesk CLI utilities

You can find updated binaries on the [Releases](https://github.com/rustdesk/rustdesk-server/releases) page.

## Configuration

`hbbs` and `hbbr` can be configured with command-line flags, environment
variables, or an `.env` / config file. Run `hbbs --help` or `hbbr --help` to see
the available flags.

The most common options:

| Option | Flag | Env var | Applies to | Purpose |
| --- | --- | --- | --- | --- |
| Key | `-k` | `KEY` | hbbs, hbbr | `hbbs` loads/generates one by default |
| Bind address | `-b` | `BIND` | hbbs, hbbr | Local IP address to listen on (default: all interfaces; requires 1.1.17+) |
| Port | `-p` | `PORT` | hbbs, hbbr | Listening port (hbbs `21116`, hbbr `21117`) |
| Relay servers | `-r` | `RELAY-SERVERS` | hbbs | Override when the relay uses a different address or a non-standard port |
| Force relay | — | `ALWAYS_USE_RELAY` | hbbs | `Y` disables direct connections |
| Log level | — | `RUST_LOG` | hbbs, hbbr | e.g. `debug` (default `info`) |

See **[docs/environment-variables.md](docs/environment-variables.md)** for the
full list of variables, the file/flag/env precedence rules, database and relay
bandwidth tuning, Docker image variables, and examples.

## Installation

Please follow this [doc](https://rustdesk.com/docs/en/self-host/rustdesk-server-oss/)
