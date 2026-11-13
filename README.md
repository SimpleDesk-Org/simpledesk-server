# SimpleDesk Server

SimpleDesk ist ein Fork des kostenlosen RustDesk-Servers ([rustdesk/rustdesk-server](https://github.com/rustdesk/rustdesk-server)) unter derselben Lizenz (AGPL-3.0). Ziel: Alles läuft über Port 443, auch wenn eine Firewall nur Webseiten durchlässt.

## Änderungen gegenüber dem RustDesk-Server

- Geräte können sich auch über TCP und WebSocket anmelden, nicht nur über UDP. Die Verbindung bleibt offen, der Server schickt alle 20 Sekunden ein Lebenszeichen, und Anfragen anderer Geräte kommen über diese Verbindung.
- Neuer Schalter `WS_ONLY=Y` für hbbs und hbbr: Nur die WebSocket-Ports (21118 und 21119) lauschen auf der Bind-Adresse, alle anderen Ports nur auf 127.0.0.1. Verbindungen laufen dann immer über das Relay.
- Ein Gerät kann seine ID ändern (`--set-id`).
- Web-Panel in hbbs auf Port 21114: Anmelden über Eider, Geräteliste mit Online-Status, Besitzer und Gruppe, eigenes und geteilte Adressbücher, für Admins die Seite „Benutzer“. Abschalten mit `PANEL=N`.
- API für den Client auf demselben Port: Anmelden über Eider im Browser, eigenes und geteilte Adressbücher mit Einträgen und Tags. Heartbeat und Systeminfo werden ruhig beantwortet. `GET /api/simpledesk/server-info` nennt ohne Anmeldung den Key des Servers (wie in `id_ed25519.pub`), damit der Client sich beim ersten Start selbst einrichten kann.
- Neuer Schalter `LOGIN_REQUIRED=Y` (im Docker-Image Standard): Verbinden darf nur, wer im Client angemeldet ist und das Gerät steuern darf (siehe unten). Der Server prüft den Token, den der Client mit jeder Verbindungsanfrage schickt. Ohne Anmeldung sieht man „Bitte melde dich in SimpleDesk an“, ohne Recht „Du darfst dieses Gerät nicht steuern.“ Das gilt auch für den normalen RustDesk-Client. Geräte, auf die man zugreift, brauchen keine Anmeldung.

## Anmeldung über Eider oder einen anderen OIDC-Anbieter

Es gibt keine Konten mit Benutzername und Passwort in SimpleDesk. Panel und Client melden sich über OpenID Connect an, zum Beispiel über Eider. Der Anbieter prüft Passwort, zweiten Faktor und Lizenz, SimpleDesk bekommt nur den Namen. Einstellungen für hbbs:

| Variable | Bedeutung |
|---|---|
| `OIDC_ISSUER` | Adresse des Anbieters, zum Beispiel `https://eider.example`. Ohne sie kann sich niemand anmelden. |
| `OIDC_CLIENT_ID` | Client-ID beim Anbieter, Standard `simpledesk` |
| `OIDC_CLIENT_SECRET` | Geheimnis des Clients beim Anbieter |
| `OIDC_NAME` | Name auf dem Knopf, Standard `Eider` |
| `PANEL_URL` | öffentliche Adresse des Panels, zum Beispiel `https://remote.example`. Die Rücksprung-Adresse ist `PANEL_URL/oidc/callback`. |

Der Anbieter muss Discovery, den Code-Flow mit PKCE (S256) und ein ID-Token mit HS256 und dem Client-Geheimnis können. Ein Konto aus dem Anbieter hat hier kein eigenes Passwort.

## Admins, Rechte und Ablauf der Anmeldung

| Variable | Bedeutung |
|---|---|
| `ADMIN_USERS` | Admins, mit Komma getrennt, zum Beispiel `felix,it-admin`. Es sind die Benutzernamen bei Eider, groß oder klein ist egal. |
| `TOKEN_DAYS` | So viele Tage bleibt der Client nach der Anmeldung angemeldet. Standard `14`. |
| `PANEL_SESSION_HOURS` | So viele Stunden bleibt das Panel nach der Anmeldung angemeldet. Standard `8`. |

**Setz `ADMIN_USERS` vor dem Update.** Ohne Admins kann niemand die Seite „Benutzer“ öffnen, und Geräte ohne Besitzer kann mit `LOGIN_REQUIRED=Y` niemand mehr steuern.

- **Admins** sehen und steuern alle Geräte, auch Geräte ohne Besitzer. Sie haben im Panel die Seite „Benutzer“. Admin ist nur, wer in `ADMIN_USERS` steht. Im Panel kann man Admins nicht sperren.
- **Benutzer** sehen und steuern nur ihre eigenen Geräte und die Geräte ihrer Gruppen.
- **Besitzer:** Ein Gerät gehört dem, der sich zuletzt im Client darauf anmeldet. Meldet sich ein Admin an, bleibt der Besitzer gleich. Auf der Seite „Geräte“ können Admins Besitzer und Gruppe von Hand setzen.
- **Gruppen** legen Admins auf der Seite „Benutzer“ an. Dort fügen sie auch Leute hinzu.
- **Abmelden** (Seite „Benutzer“) beendet alle Anmeldungen einer Person in Clients und Panel. Danach kann sie sich wieder anmelden. **Sperren** meldet sie ab, und sie kommt nicht mehr herein, bis ein Admin sie entsperrt.
- **Ablauf:** Eider gibt keine Refresh-Tokens heraus. SimpleDesk prüft die Lizenz also nur bei der Anmeldung. Verliert jemand bei Eider die Lizenz, bleibt er höchstens `TOKEN_DAYS` Tage angemeldet. Soll es sofort gelten, klick auf „Sperren“. Ist die Anmeldung abgelaufen, meldet sich der Client von selbst ab.

## Geteilte Adressbücher

Im Panel unter „Adressbuch“ legt jeder geteilte Adressbücher an und teilt sie mit Benutzern oder Gruppen:

- **lesen:** ansehen und verbinden
- **schreiben:** zusätzlich Einträge und Tags ändern
- **voll:** zusätzlich teilen, umbenennen und löschen

Wer ein Adressbuch anlegt, und alle Admins haben „voll“. Der Client zeigt die geteilten Adressbücher neben dem eigenen. Passwörter, die jemand in einem geteilten Adressbuch speichert, sehen alle, mit denen es geteilt ist. Das eigene Adressbuch sieht nur man selbst, auch kein Admin.

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
