# Release codenames

Every Switchboard release gets a codename from the history of the telephone
exchange, the original switchboard. Names go in alphabetical order, so the
letter shows which release is newer. The version number stays the real
identifier; the codename is a label.

| Version | Codename | Meaning |
|---|---|---|
| v0.1.0 | Almon | Almon Strowger, inventor of the automatic telephone exchange (1891) |
| v0.2.0 | Bakelite | The plastic of classic telephone handsets |
| next | Crossbar | The crossbar switch, the exchange generation after Strowger's |
| | Dialtone | The tone that says the line is ready |
| | Exchange | The central office that connects calls |
| | Fiber | Optical fiber trunks |

Rules:

- One word, alphabetical, from telephone exchange history.
- Check the name is not a trademark of a mail or telephony product before using it.
- Put it in the CHANGELOG header: `## v0.3.0 "Crossbar"`. The release workflow
  reads it from there for the release title, the release notes and
  `switchboard version`.
