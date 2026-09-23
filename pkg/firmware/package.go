package firmware

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// ContainerMagic prefixes every on-disk firmware container.
const ContainerMagic = "SFW1"

// metaFormatV1 is the domain-separated, fixed-shape signed metadata format.
const metaFormatV1 = "sfw-meta-v1"

type signedMeta struct {
	Format        string    `json:"format"`
	Model         string    `json:"model"`
	TargetSlot    string    `json:"target_slot"`
	Version       uint64    `json:"version"`
	PayloadSHA256 []byte    `json:"payload_sha256"`
	PayloadSize   int64     `json:"payload_size"`
	KeyID         string    `json:"key_id"`
	IssuedAt      time.Time `json:"issued_at"`
}

// CanonicalEncode deterministically encodes the metadata covered by the
// signature. The encoding is a fixed-field-order JSON object (no maps) with
// timestamps normalized to UTC RFC3339Nano, so it is stable across machines.
func CanonicalEncode(m Metadata) ([]byte, error) {
	if len(m.PayloadHash) != sha256.Size {
		return nil, errors.New("firmware: payload hash must be SHA-256")
	}
	sm := signedMeta{
		Format:        metaFormatV1,
		Model:         m.Model,
		TargetSlot:    m.TargetSlot,
		Version:       m.Version,
		PayloadSHA256: append([]byte(nil), m.PayloadHash...),
		PayloadSize:   m.PayloadSize,
		KeyID:         m.KeyID,
		IssuedAt:      m.IssuedAt.UTC(),
	}
	b, err := json.Marshal(&sm)
	if err != nil {
		return nil, fmt.Errorf("firmware: encode metadata: %w", err)
	}
	return b, nil
}

// Encode serializes a package: magic | len(meta) | metaJSON | len(sig) | sig | payload.
func (p *Package) Encode() ([]byte, error) {
	meta, err := CanonicalEncode(p.Meta)
	if err != nil {
		return nil, err
	}
	if uint64(len(p.Payload)) > uint64(maxInt32) || uint64(len(p.Signature)) > uint64(maxInt32) {
		return nil, errors.New("firmware: field too large")
	}
	var buf bytes.Buffer
	buf.WriteString(ContainerMagic)
	writeLen := func(b []byte) {
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(b)))
		buf.Write(l[:])
		buf.Write(b)
	}
	writeLen(meta)
	writeLen(p.Signature)
	buf.Write(p.Payload)
	return buf.Bytes(), nil
}

const maxInt32 = 1<<31 - 1

// Decode parses a container produced by Encode and performs structural
// validation. Cryptographic verification happens elsewhere.
func Decode(b []byte) (*Package, error) {
	if len(b) < len(ContainerMagic) || string(b[:len(ContainerMagic)]) != ContainerMagic {
		return nil, errors.New("firmware: bad container magic")
	}
	r := bytes.NewReader(b[len(ContainerMagic):])
	readBlob := func() ([]byte, error) {
		var l [4]byte
		if _, err := r.Read(l[:]); err != nil {
			return nil, errors.New("firmware: truncated container")
		}
		n := binary.BigEndian.Uint32(l[:])
		buf := make([]byte, n)
		if _, err := r.Read(buf); err != nil {
			return nil, errors.New("firmware: truncated container")
		}
		return buf, nil
	}
	metaBytes, err := readBlob()
	if err != nil {
		return nil, err
	}
	sig, err := readBlob()
	if err != nil {
		return nil, err
	}
	payload := make([]byte, r.Len())
	if _, err := r.Read(payload); err != nil {
		return nil, fmt.Errorf("firmware: reading payload: %w", err)
	}
	var sm signedMeta
	if err := json.Unmarshal(metaBytes, &sm); err != nil {
		return nil, fmt.Errorf("firmware: malformed metadata: %w", err)
	}
	if sm.Format != metaFormatV1 {
		return nil, fmt.Errorf("firmware: unsupported metadata format %q", sm.Format)
	}
	if sm.PayloadSize < 0 || sm.PayloadSize != int64(len(payload)) {
		return nil, errors.New("firmware: declared payload size does not match container")
	}
	if len(sm.PayloadSHA256) != sha256.Size {
		return nil, errors.New("firmware: payload hash must be SHA-256")
	}
	return &Package{
		Meta: Metadata{
			Model:       sm.Model,
			TargetSlot:  sm.TargetSlot,
			Version:     sm.Version,
			PayloadHash: sm.PayloadSHA256,
			PayloadSize: sm.PayloadSize,
			KeyID:       sm.KeyID,
			IssuedAt:    sm.IssuedAt,
		},
		Payload:   payload,
		Signature: sig,
	}, nil
}

// HashPayload returns the SHA-256 digest of the payload.
func HashPayload(payload []byte) []byte {
	sum := sha256.Sum256(payload)
	return sum[:]
}
