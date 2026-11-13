# SimpleDesk Roadmap

SimpleDesk ist ein Fork von RustDesk (Server, Client und gemeinsamer Code). Ziel: eine Fernwartung, die komplett über Port 443 läuft, nur mit dem eigenen Server spricht und alle Funktionen der RustDesk-Pro-Version selbst gebaut mitbringt. Von RustDesk Pro wird nichts kopiert, alles wird neu geschrieben.

## Repos

| Repo | Fork von | Inhalt |
|---|---|---|
| [simpledesk-server](https://github.com/SimpleDesk-Org/simpledesk-server) | rustdesk/rustdesk-server | ID-Server (hbbs) und Relay (hbbr), später API und Web-Panel |
| [simpledesk](https://github.com/SimpleDesk-Org/simpledesk) | rustdesk/rustdesk | Client |
| [simpledesk-common](https://github.com/SimpleDesk-Org/simpledesk-common) | rustdesk/hbb_common | gemeinsamer Code von Client und Server |

Gearbeitet wird jeweils auf dem Branch `simpledesk`.

## Fertig

- Anmeldung der Geräte über WebSocket (Port 443), nicht nur über UDP
- Schalter `WS_ONLY=Y`: nach außen nur die WebSocket-Ports, alles läuft über das Relay
- ID ändern (`--set-id`)
- Docker-Image `ghcr.io/simpledesk-org/simpledesk-server`
- Server fragt nicht mehr täglich bei RustDesk nach Updates
- Client: eingebauter Server, Key und API statt RustDesk-Servern
- Client: Update-Check und Updates nur aus den eigenen Releases, mit eigenem Signaturschlüssel
- Client: keine öffentlichen STUN-Server mehr (Google, Cloudflare und andere)
- Client: Lizenz-Konfigurationen von RustDesk werden nicht mehr angenommen, Custom-Client-Konfigurationen nur mit SimpleDesk-Schlüssel
- Client: Links zu rustdesk.com zeigen auf die Projektseite
- Eigener Server läuft mit dem SimpleDesk-Image (remote.felixthedev.com)
- Anmeldung nur über Eider (OIDC), live mit www.klg-orga.de. SimpleDesk hat keine Konten mit Benutzername und Passwort.
- Verbinden nur mit Anmeldung (`LOGIN_REQUIRED=Y`)
- Server-Info für die Ersteinrichtung des Clients (`/api/simpledesk/server-info`)
- Anmeldungen laufen ab: Client nach `TOKEN_DAYS` (14), Panel nach `PANEL_SESSION_HOURS` (8)
- Rollen Admin (`ADMIN_USERS`) und Benutzer, Seite „Benutzer“ mit Abmelden, Sperren und Gruppen
- Geräte haben Besitzer und Gruppe. Benutzer sehen und steuern nur ihre Geräte und die ihrer Gruppen, Admins alle.
- Geteilte Adressbücher mit den Rechten lesen, schreiben und voll (Client und Panel)
- IDs vergibt nur ein Admin (`IDS_BY_ADMIN=Y`): neue Geräte im Panel, „ID vergeben“ und „ID ändern“, das Gerät übernimmt die ID über den Heartbeat
- Panel verlinkt auf jeder Seite den Quellcode (AGPL)
- Online-Status über WebSocket: hbbs beantwortet die Abfrage auch auf `/ws/id` (vorher war jedes Gerät „Offline“)
- Status Aktiv, AFK (`AFK_MINUTES`) und Offline mit „seit“, im Panel und über `/api/simpledesk/peer-status`
- Seite „Protokoll“: Verbindungen, Dateien, Alarme und Änderungen im Panel (`AUDIT_DAYS`)
- Alarm-Mails über SMTP, auch wenn ein neues Gerät auf seine ID wartet

## Als Nächstes

1. Client-Build und Windows-Installer über GitHub Actions (läuft)
2. Client: Anmeldefenster beim Start, nur "Mit Eider anmelden"
3. Echter Test mit zwei Clients
4. Client: Icons und Installer mit SimpleDesk-Namen
5. Client: nur noch erlaubte Server (Allowlist für klg-orga.de und felixthedev.com)
6. Client: Liste „Zugängliche Geräte“ (`/api/peers`) mit den eigenen Geräten und denen der Gruppen
7. Client: `simpledesk_idle_secs` im Heartbeat schicken und Aktiv, AFK und Offline an den Geräten zeigen

## Pro-Funktionen

| Funktion | Stand |
|---|---|
| Verbindung über WebSocket/HTTPS | fertig |
| ID ändern | fertig |
| Eigener Client mit festen Einstellungen | Grundlage fertig (SimpleDesk-Schlüssel), Generator fehlt |
| Web-Panel | Anmelden über Eider, Geräte mit Status, Besitzer und Gruppe, Adressbücher, Protokoll, Benutzer und Gruppen |
| Login im Client mit Konto | über Eider im Browser, Anmeldefenster im Client wird gebaut |
| Login mit 2FA | über Eider |
| Geräteverwaltung und Online-Status | Status Aktiv, AFK und Offline, Besitzer und Gruppe fertig (Anzeige im Client folgt), Löschen und Deaktivieren offen |
| Adressbuch | persönliche und geteilte Adressbücher fertig (Client und Panel) |
| Audit-Log (Verbindungen, Dateien, Alarme) | fertig: Seite „Protokoll“, auch Änderungen im Panel |
| Zugriffsrechte, Rollen Admin und Control | Admin und Benutzer, Gruppen, Gerätebesitzer und Sperren fertig |
| Zentrale Einstellungen für alle Clients | offen |
| Geräte zentral einrichten | offen |
| Mehrere Relays, das nächste automatisch | offen |
| OIDC (Eider) | fertig und live, einziger Weg zum Anmelden |
| LDAP (AD) | offen |
| SMTP für Mails | Alarm-Mails und „neues Gerät wartet“ fertig |
| Web-Client selbst hosten | untersucht: nicht nur mit offenem Code möglich (siehe unten) |

Das Web-Panel wird mit axum und askama gebaut (wie Eider) und läuft in hbbs.

## Web-Client selbst hosten? (untersucht, nichts gebaut)

**Ergebnis:** Nicht nur mit offenem Code (AGPL). Es fehlt der wichtigste Teil.

- Im offenen Client-Repo steckt nur die Oberfläche des Web-Clients (Flutter/Dart in `flutter/lib/web/`). Die eigentliche Arbeit macht ein JavaScript-Teil, den die Oberfläche aufruft (`setByName`, `getByName`): Verbindung über WebSocket, Verschlüsselung, Bild entpacken. Ohne ihn läuft `flutter build web` nicht.
- Diesen JavaScript-Teil gibt es nicht mehr als Quellcode. RustDesk hat ihn im Juni 2024 in „v1“ und „v2“ geteilt. v2 kam nie ins Repo, v1 wurde im Juli 2025 gelöscht (Commit `5faf0ad3`). Der Build von RustDesk hat fertige Dateien ohne Quellcode heruntergeladen (`web_deps.tar.gz`). Den neuen Web-Client gibt RustDesk nur fertig gebaut heraus, mit RustDesk Server Pro.
- Offen ist nur der alte Stand v1 in der Git-Geschichte. Er ist von 2022 bis 2024, kann wenig und passt nicht mehr zum heutigen Client. Für SimpleDesk müsste man ihn auf den heutigen Stand bringen und Anmeldung über Eider und „nur WebSocket“ einbauen.
- Fertige Dateien von RustDesk nehmen wir nicht: kein Quellcode, und nicht unser Code.

Wenn wir den Web-Client wollen, ist das ein eigenes Projekt: den JavaScript-Teil aus v1 neu aufbauen. Der Server hätte schon alles, was er dafür braucht (`/ws/id`, `/ws/relay` und die API über Port 443).
