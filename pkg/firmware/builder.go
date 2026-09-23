package firmware

import (
	"errors"
	"time"
)

// SignFunc signs the canonical metadata encoding. It is supplied by the
// caller (typically a trust.TestKey) to keep this package free of key
// dependencies.
type SignFunc func(canonicalMeta []byte) ([]byte, error)

// Builder constructs firmware packages.
type Builder struct{}

// NewBuilder returns a package builder.
func NewBuilder() *Builder { return &Builder{} }

// Build computes the payload hash, assembles metadata and signs it.
func (b *Builder) Build(model, target string, version uint64, payload []byte, keyID string, issuedAt time.Time, sign SignFunc) (*Package, error) {
	if model == "" {
		return nil, errors.New("firmware: empty model")
	}
	if target == "" {
		return nil, errors.New("firmware: empty target slot")
	}
	if keyID == "" {
		return nil, errors.New("firmware: empty key id")
	}
	if sign == nil {
		return nil, errors.New("firmware: nil sign function")
	}
	meta := Metadata{
		Model:       model,
		TargetSlot:  target,
		Version:     version,
		PayloadHash: HashPayload(payload),
		PayloadSize: int64(len(payload)),
		KeyID:       keyID,
		IssuedAt:    issuedAt.UTC(),
	}
	canonical, err := CanonicalEncode(meta)
	if err != nil {
		return nil, err
	}
	sig, err := sign(canonical)
	if err != nil {
		return nil, err
	}
	return &Package{Meta: meta, Payload: payload, Signature: sig}, nil
}
