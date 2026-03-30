package crypto

import (
	"errors"
)

// ProtocolSignSessionBound runs an end-to-end threshold Schnorr signing protocol
// with commit/reveal, entirely in memory (no networking).
//
// Inputs:
// - ctx, sess: curve context + session (sess binds challenge to this session/group)
// - msg: message to sign
// - P: master public key (for Feldman VSS this is typically comms[0].Point)
// - signers: indices of participants who will sign (must be unique)
// - shares: map[index]Share (each signer must have its share)
// Output:
// - aggregated signature (R,z), plus a final verification check.
//
// This function is useful as a reference implementation and for testing.
// In a real distributed deployment, you would replace the in-memory maps
// with message passing (broadcast + collection) between participants.
func ProtocolSignSessionBound(
	ctx *CurveCtx,
	sess *Session,
	msg []byte,
	P []byte,
	signers []int,
	shares map[int]Share,
) (Signature, error) {
	if ctx == nil || sess == nil {
		return Signature{}, errors.New("nil ctx/session")
	}

	// Normalize signer set (sorted + unique)
	ids, err := NormalizeIndices(signers)
	if err != nil {
		return Signature{}, err
	}

	// -------------------------
	// Round 1: Nonce commit
	// -------------------------
	nonces := make(map[int]*NonceShare, len(ids))
	commits := make(map[int][]byte, len(ids)) // in the real protocol this is broadcasted

	for _, i := range ids {
		// each signer must have a share
		if _, ok := shares[i]; !ok {
			return Signature{}, errors.New("missing share for signer")
		}

		ns, err := NewNonceShare(ctx, sess, i)
		if err != nil {
			return Signature{}, err
		}
		nonces[i] = ns
		commits[i] = ns.Commit()
	}

	// -------------------------
	// Round 2: Reveal Ri
	// -------------------------
	reveals := make(map[int][]byte, len(ids))
	for _, i := range ids {
		reveals[i] = nonces[i].Reveal() // it would be a broadcast of the point
	}

	// Verify all reveals match the commits and are valid points
	for _, i := range ids {
		if !VerifyNonce(ctx, sess, i, commits[i], reveals[i]) {
			return Signature{}, errors.New("nonce verification failed")
		}
	}

	// Compute aggregated R = Σ Ri
	R, err := CombineRStrict(ctx, reveals, ids)
	if err != nil {
		return Signature{}, err
	}

	// Compute challenge e (session-bound)
	e, err := ChallengeSessionBound(ctx, sess, R, P, msg)
	if err != nil {
		return Signature{}, err
	}

	// Lagrange coefficients for this signer set
	lambdas, err := LagrangeCoefficients(ctx, ids)
	if err != nil {
		return Signature{}, err
	}

	// -------------------------
	// Round 3: Partial signatures z_i
	// -------------------------
	partials := make(map[int][]byte, len(ids))
	for _, i := range ids {
		zi, err := PartialSignStrict(ctx, shares[i], nonces[i], lambdas[i], e)
		if err != nil {
			return Signature{}, err
		}
		partials[i] = zi
	}

	// -------------------------
	// Final aggregation
	// -------------------------
	sig, err := CombineSignatureStrict(ctx, R, partials, ids)
	if err != nil {
		return Signature{}, err
	}

	// Sanity check: verify final signature
	// in rete reale, il combiner vuole essere certo prima di “pubblicare” la firma
	if !VerifySignatureSessionBound(ctx, sess, P, msg, sig) {
		return Signature{}, errors.New("final signature verification failed")
	}

	return sig, nil
}

// -----------------------------------------------------------------------------
// NOTE FOR DISTRIBUTED IMPLEMENTATION (IMPORTANT)
//
// This function implements the *logical* threshold Schnorr signing protocol
// entirely in memory. All maps (commits, reveals, partials) simulate messages
// that, in a real distributed deployment, MUST be exchanged via the network.
//
// To convert this reference implementation into a real distributed protocol,
// the following message flow is required:
//
// ROUND 1 — Nonce commit (broadcast):
//   - Each participant i locally generates a nonce share (r_i, R_i = r_i*G).
//   - Each participant broadcasts ONLY the commitment c_i = H(session || i || R_i).
//   - No R_i values are revealed at this stage.
//
// ROUND 2 — Nonce reveal (broadcast + verification):
//   - After collecting all commitments c_i, each participant broadcasts R_i.
//   - Upon receiving R_i from participant i, every participant MUST:
//       * verify that H(session || i || R_i) == c_i
//       * verify that R_i is a valid point on the curve
//   - If any verification fails, the protocol MUST abort.
//   - After successful verification, all participants compute the same
//     aggregated nonce R = Σ R_i.
//
// ROUND 3 — Challenge computation (local, deterministic):
//   - Each participant computes the challenge
//       e = H(R || P || msg || session.ID || session.IndexHash) mod N
//   - No messages are exchanged in this step.
//   - Determinism is critical: all participants must compute the same e.
//
// ROUND 4 — Partial signature (unicast or broadcast):
//   - Each participant i computes its partial signature
//       z_i = r_i + e * lambda_i * s_i mod N
//   - Each participant sends z_i to the designated combiner
//     (or broadcasts it to all, depending on the architecture).
//
// FINAL STEP — Signature aggregation and verification:
//   - The combiner collects all z_i values and computes
//       z = Σ z_i mod N
//   - The final Schnorr signature is (R, z).
//   - The final signature MUST be verified before being released.
//
// IMPORTANT SECURITY NOTES:
//   - Commit–reveal is mandatory: revealing R_i without a prior commitment
//     allows adaptive attacks on the nonce.
//   - Nonces r_i MUST NEVER be reused across signing sessions.
//   - All participants must agree on the exact signer set (IndexHash).
//   - Any failure in verification (nonce, partial signature, final signature)
//     MUST cause the protocol to abort.
//
// This in-memory implementation exists as a reference and test oracle.
// Any distributed version must preserve the exact round structure above.
// -----------------------------------------------------------------------------

// Altro commento: tutto quello che viene mandato nel canale (ci, ecc...) dovrà
// essere protetto. Non so se con cifratura, mac o firme digitali,
// ci devo pensare, ma nella pratica non può essere mandato in chiaro.
// Non perchè vengano rivelati segreti, il protocollo è matematicamente sicuro,
// ma piuttosto per i soliti attacchi (MITM,...) :) poi a questo ci pensiamo
