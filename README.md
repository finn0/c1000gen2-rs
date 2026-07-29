# c1000gen2-rs

A small, read-only Rust client for monitoring an Anker SOLIX C1000 Gen 2
portable power station (PN `A1763` / `A1765` / `AS100`) in near real time,
via Anker's cloud login + MQTT broker.

It logs into your Anker account, finds the C1000 Gen 2 device, connects to
Anker's cloud MQTT broker over mutual TLS, and decodes the device's `0421`
status messages into a typed, human-readable report: battery SOC/SOH/temp,
AC/DC input/output power, per-port USB status, switch states, and config
limits.

This is **not** a general-purpose Anker Solix client. It's deliberately
scoped down to one device family and to monitoring only:

- No device control commands (only the read-only "realtime trigger" keepalive
  needed to make the device keep streaming live data).
- No cloud energy-history polling (the C1000 Gen 2 doesn't expose much there
  anyway — this device family lives almost entirely on the MQTT side).
- No Home Assistant integration layer.

## Origin

This project is extracted and ported from
[thomluther/anker-solix-api](https://github.com/thomluther/anker-solix-api),
an unofficial, reverse-engineered Python library and CLI toolkit for the
Anker Solix ecosystem (Solarbank, inverters, smart meters, portable power
stations, EV chargers, and more). That project also powers the
[ha-anker-solix](https://github.com/thomluther/ha-anker-solix) Home Assistant
integration.

`c1000gen2-rs` re-implements, in Rust, just the subset of that library needed
to authenticate, connect to the MQTT broker, and decode the C1000 Gen 2's
binary status protocol — as a small, dependency-light standalone tool/library
rather than a full port of the Python project.

Like the upstream project, this is unofficial and not affiliated with,
endorsed by, or supported by Anker in any way. Anker's cloud API and MQTT
protocol can change at any time without notice, which may break this tool.

## Usage

Credentials are read from environment variables (or a local `.env` file in
the working directory), falling back to an interactive prompt if unset:

```
ANKERUSER=you@example.com
ANKERPASSWORD=your-anker-password
ANKERCOUNTRY=US
```

Then run:

```
cargo run
```

The demo CLI logs in, lists devices on the account, locates the C1000 Gen 2,
connects to MQTT, and prints a full status report every few seconds until
Ctrl+C.

A successful login's session token is cached locally under `.authcache/` (one
file per account email) so subsequent runs skip the login round-trip until
the token expires. This directory is gitignored and, like `.env`, should
never be committed or shared — both contain live credentials/tokens for your
Anker account.

## Notes

1. When dockerizing the app, remember to mount the cache directory
   `.authcache`.

## License

MIT — see [LICENSE](LICENSE). Ported from `anker-solix-api`, also MIT
licensed.
