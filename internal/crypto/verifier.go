package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"math/big"
)

type DefaultVerifier struct {
	Curve elliptic.Curve
}

func NewVerifier() *DefaultVerifier {
	return &DefaultVerifier{Curve: elliptic.P256()}
}

// VerifySignature checks standard ECDSA signatures (used for Liveness)
// Expects signature to be r || s
func (v *DefaultVerifier) VerifySignature(pubKeyBytes, message, signature []byte) bool {
    // 1. Unmarshal the Public Key
    curve := elliptic.P256()
    x, y := elliptic.Unmarshal(curve, pubKeyBytes)
    if x == nil {
        return false // Invalid public key format
    }
    pubKey := &ecdsa.PublicKey{Curve: curve, X: x, Y: y}

    // 2. Split the concatenated R || S signature
    // For P-256, R and S are 32 bytes each
    if len(signature) != 64 {
        return false // Signature length mismatch
    }

    r := new(big.Int).SetBytes(signature[:32])
    s := new(big.Int).SetBytes(signature[32:])

    // 3. Perform actual verification
    return ecdsa.Verify(pubKey, message, r, s)
}

// VerifyShare implements Feldman's VSS Verification
// Checks if: g^share == Product( (C_j)^(i^j) )
// commitment: Expects concatenated list of serialized points [C_0, C_1... C_k-1]
func (v *DefaultVerifier) VerifyShare(shareBytes []byte, commitmentBlob []byte, index int) bool {
	// 1. Parse Share
	shareVal := new(big.Int).SetBytes(shareBytes)
	
	// 2. Compute LHS = g^share
	lhsX, lhsY := v.Curve.ScalarBaseMult(shareVal.Bytes())

	// 3. Parse Commitments (Assuming 65 bytes uncompressed per point)
	pointSize := 65 
	if len(commitmentBlob)%pointSize != 0 {
		return false // Invalid blob
	}
	
	numCommits := len(commitmentBlob) / pointSize
	
	// 4. Compute RHS
	// RHS = C_0 + C_1*i + C_2*i^2 ... (Elliptic Curve Addition)
	
	// Initialize RHS with identity (infinity) or handle C_0 explicitly
	// We'll start with C_0
	c0X, c0Y := elliptic.Unmarshal(v.Curve, commitmentBlob[:pointSize])
	if c0X == nil { return false }
	
	accX, accY := c0X, c0Y
	
	idxBig := big.NewInt(int64(index))
	
	for j := 1; j < numCommits; j++ {
		// Extract C_j
		chunk := commitmentBlob[j*pointSize : (j+1)*pointSize]
		cjX, cjY := elliptic.Unmarshal(v.Curve, chunk)
		if cjX == nil { return false }

		// Calculate scalar = i^j
		pow := new(big.Int).Exp(idxBig, big.NewInt(int64(j)), v.Curve.Params().N)
		
		// Calculate term = C_j * (i^j)
		termX, termY := v.Curve.ScalarMult(cjX, cjY, pow.Bytes())
		
		// Add to accumulator
		accX, accY = v.Curve.Add(accX, accY, termX, termY)
	}

	// Compare LHS == RHS
	return lhsX.Cmp(accX) == 0 && lhsY.Cmp(accY) == 0
}

// SignPartial computes the Lagrange-weighted share used for reconstruction
// share: The server's share (scalar)
// message: In this simplified model, message contains context like [TargetIndex, TotalIndexes...]
// But to stick to the interface, we'll implement the "Server Contribution" 
// which is typically: share * LagrangeCoefficient(0)
func (v *DefaultVerifier) SignPartial(share []byte, message []byte) ([]byte, error) {
	// For recovery, we need to return: Share * (Product(x_j / (x_j - x_i)))
	// Since the server doesn't know who the other participants are in a stateless request,
	// strict interpolation is hard stateless.
	
	// ADAPTATION: We return the raw share (decrypted) implies the "Server has agreed".
	// The Client (Combiner) does the Lagrange interpolation locally.
	// This fits the "Access Control" requirement: Server only releases this value
	// if the dead-man switch is active.
	
	return share, nil
}

// Helper for ECDSA verify manually since we have raw coordinates
func ecdsaVerify(curve elliptic.Curve, x, y *big.Int, hash []byte, r, s *big.Int) bool {
    // Standard ECDSA verification logic
    if r.Sign() <= 0 || s.Sign() <= 0 { return false }
    if r.Cmp(curve.Params().N) >= 0 || s.Cmp(curve.Params().N) >= 0 { return false }
    
    e := new(big.Int).SetBytes(hash)
    w := new(big.Int).ModInverse(s, curve.Params().N)
    
    u1 := new(big.Int).Mul(e, w)
    u1.Mod(u1, curve.Params().N)
    
    u2 := new(big.Int).Mul(r, w)
    u2.Mod(u2, curve.Params().N)
    
    x1, y1 := curve.ScalarBaseMult(u1.Bytes())
    x2, y2 := curve.ScalarMult(x, y, u2.Bytes())
    
    x3, _ := curve.Add(x1, y1, x2, y2)
    
    return x3.Cmp(r) == 0
}
