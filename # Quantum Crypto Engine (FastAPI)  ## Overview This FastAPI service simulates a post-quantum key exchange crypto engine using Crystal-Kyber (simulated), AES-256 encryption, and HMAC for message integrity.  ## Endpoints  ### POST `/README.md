# Quantum Crypto Engine (FastAPI)

## Overview
This FastAPI service simulates a post-quantum key exchange crypto engine using Crystal-Kyber (simulated), AES-256 encryption, and HMAC for message integrity.

## Endpoints

### POST `/encrypt`
Request body:
```json
{ "message": "Your plaintext message" }
