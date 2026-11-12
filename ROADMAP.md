# SimpleDesk Roadmap

SimpleDesk ist ein Fork von RustDesk (Server, Client und gemeinsamer Code). Ziel: eine Fernwartung, die komplett über Port 443 läuft, nur mit dem eigenen Server spricht und alle Funktionen der RustDesk-Pro-Version selbst gebaut mitbringt. Von RustDesk Pro wird nichts kopiert, alles wird neu geschrieben.

## Repos

| Repo | Fork von | Inhalt |
|---|---|---|
| [simpledesk-server](https://github.com/felixthedevgit/simpledesk-server) | rustdesk/rustdesk-server | ID-Server (hbbs) und Relay (hbbr), später API und Web-Panel |
| [simpledesk](https://github.com/felixthedevgit/simpledesk) | rustdesk/rustdesk | Client |
| [simpledesk-common](https://github.com/felixthedevgit/simpledesk-common) | rustdesk/hbb_common | gemeinsamer Code von Client und Server |

Gearbeitet wird jeweils auf dem Branch `simpledesk`.

## Fertig

- Anmeldung der Geräte über WebSocket (Port 443), nicht nur über UDP
- Schalter `WS_ONLY=Y`: nach außen nur die WebSocket-Ports, alles läuft über das Relay
- ID ändern (`--set-id`)
- Docker-Image `ghcr.io/felixthedevgit/simpledesk-server`
- Server fragt nicht mehr täglich bei RustDesk nach Updates
- Client: eingebauter Server, Key und API statt RustDesk-Servern
- Client: Update-Check und Updates nur aus den eigenen Releases, mit eigenem Signaturschlüssel
- Client: keine öffentlichen STUN-Server mehr (Google, Cloudflare und andere)
- Client: Lizenz-Konfigurationen von RustDesk werden nicht mehr angenommen, Custom-Client-Konfigurationen nur mit SimpleDesk-Schlüssel
- Client: Links zu rustdesk.com zeigen auf die Projektseite

## Als Nächstes

1. Echter Test mit zwei Clients
2. Eigenen Server auf das SimpleDesk-Image umstellen
3. Client-Build und Release über GitHub Actions (zuerst Windows)
4. Client umbenennen in SimpleDesk (Name, Icons, Installer)
5. Client: nur noch erlaubte Server (Allowlist für klg-orga.de und felixthedev.com)

## Pro-Funktionen

| Funktion | Stand |
|---|---|
| Verbindung über WebSocket/HTTPS | fertig |
| ID ändern | fertig |
| Eigener Client mit festen Einstellungen | Grundlage fertig (SimpleDesk-Schlüssel), Generator fehlt |
| Web-Panel | angefangen: Einrichten, Login, Geräteliste |
| Login mit 2FA | offen |
| Geräteverwaltung und Online-Status | Online-Status fertig, Verwalten offen |
| Adressbuch | offen |
| Audit-Log (Verbindungen, Dateien, Alarme) | offen |
| Zugriffsrechte, Rollen Admin und Control | offen |
| Zentrale Einstellungen für alle Clients | offen |
| Geräte zentral einrichten | offen |
| Mehrere Relays, das nächste automatisch | offen |
| OIDC (z. B. Microsoft) und LDAP (AD) | offen |
| SMTP für Mails | offen |
| Web-Client selbst hosten | offen |

Das Web-Panel wird mit axum und askama gebaut (wie Eider) und läuft in hbbs.
