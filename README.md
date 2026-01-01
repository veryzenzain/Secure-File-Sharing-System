# Secure File Sharing System (Go)

End-to-end encrypted file storage + sharing client built for an **untrusted** backend (Datastore/Keystore). The server can read/modify/snapshot everything, so the client is responsible for confidentiality, integrity, sharing, and revocation.

## Highlights

- **User authentication** with password-based key derivation and tamper-detecting user state
- **Confidential + integrity-protected** file contents and metadata (server can’t read or silently modify)
- **Efficient appends**: bandwidth scales with *append size*, not total file size
- **Secure sharing** via signed/encrypted invitations (supports re-sharing)
- **Owner-driven revocation** (revokes a user + their downstream share tree)


## Threat Model (what we defend against)

- Datastore adversary can **list / read / modify** any stored values and take **snapshots** to compare changes.
- Keystore is public and only stores **public keys** (no secrets).
- No concurrency: assume only one API call runs at a time, and attacks only happen *between* calls.
- Design is **stateless** across runs: no persistent local state; everything needed to resume is stored remotely.


## Public API

This implementation exposes the standard client API:

- `InitUser(username, password)`
- `GetUser(username, password)`
- `(*User) StoreFile(filename, content)`
- `(*User) LoadFile(filename)`
- `(*User) AppendToFile(filename, content)`
- `(*User) CreateInvitation(filename, recipientUsername)`
- `(*User) AcceptInvitation(senderUsername, invitationPtr, filename)`
- `(*User) RevokeAccess(filename, recipientUsername)`


## Repo Layout

- `client/`
  - `client.go` — core implementation (all required API methods + helpers)
- `client_test/`
  - `client_test.go` — integration tests (black-box style)
  - `client_unittest.go` — optional unit tests for design-specific helpers

