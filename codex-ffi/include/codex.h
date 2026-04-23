/* Codex FFI — auto-generated from codex-ffi/src/lib.rs via cbindgen. */
/* Do not edit by hand. Regenerate via `cargo build -p codex-ffi`. */

#ifndef CODEX_H
#define CODEX_H

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/**
 * Derive a 20-byte `PeerId` from a 32-byte ed25519 public key.
 *
 * # Safety
 * - `pubkey_ptr` must point to at least 32 readable bytes.
 * - `out_peer_id_ptr` must point to a writable 20-byte buffer.
 *
 * Returns 0 on success; `-1` if any pointer is null.
 */
int32_t codex_peer_id_from_pubkey(const uint8_t *pubkey_ptr, uint8_t *out_peer_id_ptr);

/**
 * Verify an Event's signature against a 32-byte ed25519 public key.
 * `event_bytes` must be the postcard-encoded `Event`.
 *
 * # Safety
 * - `event_ptr` must point to `event_len` readable bytes.
 * - `pubkey_ptr` must point to 32 readable bytes.
 */
int32_t codex_event_verify(const uint8_t *event_ptr,
                           uintptr_t event_len,
                           const uint8_t *pubkey_ptr);

/**
 * Verify a raw ed25519 signature over an arbitrary message.
 */
int32_t codex_ed25519_verify(const uint8_t *pubkey_ptr,
                             const uint8_t *msg_ptr,
                             uintptr_t msg_len,
                             const uint8_t *sig_ptr);

/**
 * Verify an `ExistenceProof` (postcard-encoded) against a 32-byte
 * state root.
 */
int32_t codex_state_verify_existence(const uint8_t *proof_ptr,
                                     uintptr_t proof_len,
                                     const uint8_t *state_root_ptr);

/**
 * Verify a `NonExistenceProof` (postcard-encoded) against a 32-byte
 * state root.
 */
int32_t codex_state_verify_non_existence(const uint8_t *proof_ptr,
                                         uintptr_t proof_len,
                                         const uint8_t *state_root_ptr);

/**
 * Verify an `EventInclusionProof` (postcard-encoded) against a 32-byte
 * events root.
 */
int32_t codex_events_verify_inclusion(const uint8_t *proof_ptr,
                                      uintptr_t proof_len,
                                      const uint8_t *events_root_ptr);

#ifdef __cplusplus
}  // extern "C"
#endif  // __cplusplus

#endif  /* CODEX_H */
