# Distributed Wallet Recovery through Dead-Man-Switch Activation and Collaborative Signing

This project is a prototype of a distributed wallet recovery system developed for the course **Advanced Programming of Cryptographic Methods**.

The goal of the system is to prevent the permanent loss of access to a non-custodial cryptographic wallet while avoiding any single point of failure. Instead of storing or reconstructing the wallet private key in full, the system distributes the signing capability among a set of recovery participants and a dedicated Recovery Server.

Recovery is enabled only when a predefined recovery condition is satisfied, such as prolonged inactivity of the wallet owner or the expiration of a predefined deadline. Once recovery is activated, the Recovery Server and a threshold number of recovery participants can collaboratively generate a valid wallet signature without reconstructing the wallet secret.

## Overview

The system implements the following recovery policy:

```text
Recovery Server AND k-out-of-n Shareholders
```

This means that a valid recovery operation requires:

- the mandatory participation of the Recovery Server;
- the participation of at least `k` out of `n` selected Shareholders.

This policy prevents two undesirable situations:

1. the Recovery Server cannot recover the wallet alone;
2. the Shareholders cannot bypass the dead-man-switch without the server.

The project combines:

- a Linear Secret Sharing Scheme (LSSS) to enforce the recovery policy;
- verifiable share distribution through public commitments;
- a Schnorr-style collaborative signing protocol over Edwards25519;
- an authenticated end-to-end key exchange protocol for share transfer;
- local encrypted client storage;
- a client-server architecture implemented in Go.

## Main Features

- Distributed wallet recovery without reconstructing the wallet secret.
- Mandatory Recovery Server participation.
- Threshold-based recovery among selected Shareholders.
- Dead-man-switch activation based on inactivity or expiration time.
- Verifiable recovery shares.
- Authenticated end-to-end encrypted share transfer.
- Local encrypted client database.
- JSON-based prototype server storage.
- Unit and integration tests for the cryptographic core and the key exchange protocol.

## Architecture

The system consists of two main components.

### Recovery Server

The server is responsible for:

- registering users;
- storing public signing keys;
- storing wallet metadata;
- monitoring recovery activation conditions;
- relaying encrypted setup messages between users;
- participating in collaborative signing only after recovery activation.

The server is required for recovery, but it is not trusted with the confidentiality of Shareholders' recovery shares.

### Client

Each client is responsible for:

- registering a user;
- storing local encrypted data;
- managing contacts;
- creating wallets;
- distributing recovery shares;
- receiving and verifying recovery shares;
- participating in collaborative signing after recovery activation.

Each client maintains a local encrypted database protected through a password-derived key.

## Cryptographic Components

The project uses the following cryptographic mechanisms:

- **LSSS / VSS layer**: implemented over the scalar field of Edwards25519.
- **Collaborative signing**: implemented as a Schnorr-style threshold signing protocol.
- **Edwards25519**: used for scalar and group operations.
- **Ed25519**: used for long-term authentication keys.
- **X25519**: used for ephemeral Diffie-Hellman key agreement.
- **HKDF-SHA256**: used to derive symmetric keys from Diffie-Hellman shared secrets.
- **XChaCha20-Poly1305**: used for authenticated encryption of recovery shares.
- **Argon2id**: used to derive a local encryption key from the client password.
- **ChaCha20-Poly1305**: used to protect the local client database.

## Project Structure

```text
.
├── cmd/
│   ├── client/              # Client entry point
│   └── server/              # Server entry point
│
├── internal/
│   ├── api/                 # HTTP handlers, DTOs and API utilities
│   ├── core/                # Core data structures and logging utilities
│   ├── crypto/              # LSSS, VSS and collaborative signing logic
│   ├── keyexchange/         # Authenticated end-to-end key exchange protocol
│   └── store/               # JSON-based prototype persistence layer
│
├── test/                    # Integration and protocol tests
├── Makefile                 # Build and execution utilities
├── go.mod
└── README.md
```

## Requirements

The following tools are required:

- Go
- Make
- OpenSSL

No external database or service is required. The server uses local JSON files for prototype storage.

## Build

To build both the server and the client:

```bash
make build-all
```

To build only the server:

```bash
make build-server
```

To build only the client:

```bash
make build-client
```

The client executable is placed inside the `client_dir` directory.

## Run the Server

To build and run the server:

```bash
make run-server
```

Alternatively, after building it:

```bash
./server
```

When started, the server creates the local data directory used to store users, wallet metadata and protocol state.

## Run the Client

After building the client, move into a clean client directory and run:

```bash
./client
```

On first execution, the client asks the user to choose a username and a password.

The password is used to derive a symmetric key through Argon2id. This key is then used to encrypt the local client database.

On later executions, the same password is required to decrypt the local database.

To simulate multiple users, run independent client instances from different directories. Each user must have a separate local `client_db.json` file.

## Typical Usage Flow

A typical execution of the prototype is the following:

1. Start the Recovery Server.
2. Start one client instance for each user.
3. Register each user with a distinct username and password.
4. Add the required contacts on each client.
5. Create a wallet from the Dealer client.
6. Distribute recovery shares to the selected Shareholders.
7. Wait until a recovery condition is satisfied.
8. Start the collaborative signing procedure from the Shareholder clients.

A collaborative signing operation requires the Recovery Server and at least `k` Shareholders.

## Testing

The project includes tests for both:

- the LSSS / VSS / collaborative signing layer;
- the authenticated key exchange protocol.

All tests can be executed using the standard Go testing tool.

### Run All Tests

To run all tests:

```bash
go test ./...
```

To run all tests in verbose mode:

```bash
go test ./... -v
```

To avoid cached results and force the tests to run again:

```bash
go test ./... -v -count=1
```

## Run LSSS and Collaborative Signing Tests

The LSSS and collaborative signing tests are contained in the `test` package.

To run them in verbose mode:

```bash
go test ./test -v -count=1
```

To run the main full signing flow test:

```bash
go test ./test -v -count=1 -run TestLSSSFullSigningFlow
```

To run only the LSSS / threshold signing related tests:

```bash
go test ./test -v -count=1 -run 'Test(LSSSFullSigningFlow|ParticipantRejectsTamperedShare|TamperedPartialSignature|ReplayAttackDifferentSession|DuplicateParticipantIDsRejected|KParticipantsWithoutServerFails|ServerWithKMinus1ParticipantsFails|WrongParticipantIndexShareMismatch)'
```

These tests check:

- correctness of the LSSS construction;
- threshold enforcement;
- mandatory Recovery Server participation;
- rejection of tampered shares;
- rejection of invalid partial signatures;
- rejection of replayed partial signatures;
- rejection of duplicated participant identifiers.

## Run Authenticated Key Exchange Tests

The authenticated key exchange tests are also contained in the `test` package.

To run the complete key exchange flow:

```bash
go test ./test -v -count=1 -run TestCompleteProtocol
```

To run only the key exchange related tests:

```bash
go test ./test -v -count=1 -run 'Test(CompleteProtocol|InitiatorStateInitialization|ResponderStateInitialization|HandleM1WrongRecipient|AliceRejectsCorruptedM2|BobRejectsTamperedPayloadM3|IdentitySpoofingM1|TranscriptMismatchM3)'
```

These tests check:

- correct state initialization;
- correct synchronization between initiator and responder;
- recipient validation;
- identity checks;
- signature verification;
- rejection of corrupted handshake messages;
- ciphertext integrity;
- transcript binding.

## Notes on Verbose Test Output

The tests use verbose logging to show the execution flow of the protocols.

To see the full formatted output, always run tests with the `-v` flag.

For example:

```bash
go test ./test -v -count=1
```

Without `-v`, Go may hyde most of the log output when tests pass.

## Security Model

The system assumes that:

- the Dealer behaves honestly during setup;
- recovery conditions are fixed during setup;
- the Recovery Server correctly enforces the recovery activation policy;
- the Recovery Server is not trusted with the confidentiality of Shareholders' recovery shares;
- cryptographic keys are securely stored by their owners;
- a bounded subset of Shareholders may behave maliciously or collude;
- the underlying cryptographic primitives are secure.

Under these assumptions, the system prevents unauthorized recovery by insufficient subsets of participants and avoids reconstructing the wallet secret in full during protocol execution.

## Known Limitations

This project is a prototype and is not intended to be production-ready.

The main limitations are:

- the Recovery Server is trusted to enforce the recovery policy correctly;
- the system does not implement a strong certificate-based identity infrastructure;
- full device compromise is out of scope;
- the collaborative signing protocol and key exchange protocol are custom designs and were not formally verified;
- protocol-level constant-time behavior was not formally analyzed;
- polling is used instead of WebSockets;
- relay endpoint authorization is limited;
- the implementation focuses on correctness of the cryptographic flow rather than complete fault tolerance.

## Authors

- Elena Bortolameotti
- Beatrice Currarino
- Alessandro Marostica

## License

This project was developed for academic purposes as part of the course **Advanced Programming of Cryptographic Methods**.