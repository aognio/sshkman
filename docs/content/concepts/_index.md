+++
title = "Concepts"
+++

# Concepts

These pages explain why sshkma is shaped the way it is. Read them after the getting started tutorial, or before if you are evaluating the security model.

## Zero knowledge

The server stores account authentication data, device and session records, and encrypted vault content. It never receives raw SSH private keys, plaintext vault passwords, unwrapped vault master keys, or plaintext identity records.

The vault password never leaves the client. The client derives a key encryption key from it, unwraps the vault master key, and decrypts identity records locally.

## Account authentication and vault decryption

Account authentication and vault decryption are separate. A valid API session does not grant access to vault contents. An attacker who steals a session token still needs the vault password.

## Key preservation

Imported private and public key bytes are preserved exactly, including comments, whitespace, and line endings where the input format allows. The client validates key material with an SSH key library, but emits the original bytes.

## OpenSSH integration

sshkma uses a bounded managed include block in `~/.ssh/config`. It does not rewrite user-owned host blocks. Each managed identity has its own configuration file and key files.

## Storage

The server uses filesystem storage only. Metadata is TOML. Encrypted content is stored as separate files. Writes are atomic and protected by advisory locks.
