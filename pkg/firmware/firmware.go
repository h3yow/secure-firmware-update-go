// Package firmware defines the firmware package envelope: a canonical JSON
// manifest describing the payload, and a detached Ed25519 signature over that
// manifest. The on-disk format is a small self-delimiting binary container so
// that truncation is detectable at parse time:
//
//	magic "FWPKG01\n"
//	u32be manifest_len ; manifest JSON (canonical)
//	u32be sig_len      ; raw Ed25519 signature
//	u8    key_id_len ; key_id bytes
//	u64be payload_len ; payload bytes
package firmware

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Magic is the package file magic.
const Magic = "FWPKG01\n"

// Version is a semantic version "MAJOR.MINOR.PATCH" without pre-release tags.
type Version struct {
	Major int
	Minor int
	Patch int
}

// ParseVersion parses a strictly formatted MAJOR.MINOR.PATCH string.
func ParseVersion(s string) (Version, error) {
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return Version{}, fmt.Errorf("invalid version %q: want MAJOR.MINOR.PATCH", s)
	}
	nums := [3]int{}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || strings.TrimLeft(p, "0") != strings.TrimPrefix(p, "") && p != "0" {
			return Version{}, fmt.Errorf("invalid version %q: component %q is not a non-negative integer", s, p)
		}
		nums[i] = n
	}
	return Version{Major: nums[0], Minor: nums[1], Patch: nums[2]}, nil
}

// String renders the canonical version text.
func (v Version) String() string {
	return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
}

// Compare returns -1, 0, 1 when v is below, equal to, or above other.
func (v Version) Compare(other Version) int {
	switch {
	case v.Major != other.Major:
		return cmpInt(v.Major, other.Major)
	case v.Minor != other.Minor:
		return cmpInt(v.Minor, other.Minor)
	case v.Patch != other.Patch:
		return cmpInt(v.Patch, other.Patch)
	default:
		return 0
	}
}

func cmpInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

// Manifest is the signed metadata of a firmware package. Field order is the
// canonical signing order; JSON is rendered deterministically by CanonicalManifest.
type Manifest struct {
	Schema        uint   `json:"schema"`
	PackageID     string `json:"package_id"`
	Model         string `json:"model"`
	TargetSlot    string `json:"target_slot"`
	FromVersion   string `json:"from_version,omitempty"`
	Version       string `json:"version"`
	PayloadSize   int64  `json:"payload_size"`
	PayloadSHA256 string `json:"payload_sha256"`
	PayloadKey    string `json:"payload_key"`
	IssuedAt      int64  `json:"issued_at"`
}

// CurrentSchema is the only accepted manifest schema version.
const CurrentSchema uint = 1

// Package is a parsed firmware package.
type Package struct {
	Manifest      Manifest
	ManifestBytes []byte
	Signature     []byte
	KeyID         string
	Payload       []byte
	SourcePath    string
}

// CanonicalManifest renders the manifest deterministically for signing:
// keys are sorted (encoding/json sorts map keys; we use a fixed struct with
// no map), compact JSON, terminated by a single newline.
func CanonicalManifest(m *Manifest) ([]byte, error) {
	b, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("canonical manifest: %w", err)
	}
	return append(b, '\n'), nil
}

// PayloadSHA256Hex returns the lowercase hex SHA-256 of data.
func PayloadSHA256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// ErrMalformed is returned when a package file cannot be parsed.
var ErrMalformed = errors.New("malformed firmware package")

// Parse parses package bytes.
func Parse(data []byte) (*Package, error) {
	if len(data) < len(Magic) || string(data[:len(Magic)]) != Magic {
		return nil, fmt.Errorf("%w: bad magic", ErrMalformed)
	}
	r := &reader{buf: data[len(Magic):]}

	manifestBytes, err := r.blob32()
	if err != nil {
		return nil, err
	}
	sig, err := r.blob32()
	if err != nil {
		return nil, err
	}
	keyID, err := r.blob8len()
	if err != nil {
		return nil, err
	}
	payload, err := r.blob64()
	if err != nil {
		return nil, err
	}
	if len(r.buf) != 0 {
		return nil, fmt.Errorf("%w: %d trailing bytes", ErrMalformed, len(r.buf))
	}

	var m Manifest
	if err := json.Unmarshal(manifestBytes, &m); err != nil {
		return nil, fmt.Errorf("%w: manifest json: %v", ErrMalformed, err)
	}
	// Re-serialize and compare: a package whose manifest is not in canonical
	// form is rejected so that signature bytes always sign one exact byte string.
	canon, err := CanonicalManifest(&m)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if string(canon) != string(manifestBytes) {
		return nil, fmt.Errorf("%w: manifest is not canonical", ErrMalformed)
	}
	if _, err := ParseVersion(m.Version); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}

	return &Package{
		Manifest:      m,
		ManifestBytes: manifestBytes,
		Signature:     sig,
		KeyID:         string(keyID),
		Payload:       payload,
	}, nil
}

// ParseFile reads and parses a firmware package file.
func ParseFile(path string) (*Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read package %s: %w", path, err)
	}
	p, err := Parse(data)
	if err != nil {
		return nil, err
	}
	p.SourcePath = path
	return p, nil
}

// Encode serializes a signed package.
func Encode(manifestBytes, sig []byte, keyID string, payload []byte) ([]byte, error) {
	w := &writer{}
	w.bytes([]byte(Magic))
	w.blob32(manifestBytes)
	w.blob32(sig)
	w.blob8len([]byte(keyID))
	w.blob64(payload)
	return w.buf, w.err
}

type reader struct {
	buf []byte
}

func (r *reader) need(n int) error {
	if len(r.buf) < n {
		return fmt.Errorf("%w: truncated container (need %d bytes, have %d)", ErrMalformed, n, len(r.buf))
	}
	return nil
}

func (r *reader) u32() (uint32, error) {
	if err := r.need(4); err != nil {
		return 0, err
	}
	v := binary.BigEndian.Uint32(r.buf[:4])
	r.buf = r.buf[4:]
	return v, nil
}

func (r *reader) u64() (uint64, error) {
	if err := r.need(8); err != nil {
		return 0, err
	}
	v := binary.BigEndian.Uint64(r.buf[:8])
	r.buf = r.buf[8:]
	return v, nil
}

func (r *reader) u8() (uint8, error) {
	if err := r.need(1); err != nil {
		return 0, err
	}
	v := r.buf[0]
	r.buf = r.buf[1:]
	return v, nil
}

func (r *reader) blob32() ([]byte, error) {
	n, err := r.u32()
	if err != nil {
		return nil, err
	}
	if err := r.need(int(n)); err != nil {
		return nil, err
	}
	b := r.buf[:n]
	r.buf = r.buf[n:]
	return b, nil
}

func (r *reader) blob64() ([]byte, error) {
	n, err := r.u64()
	if err != nil {
		return nil, err
	}
	if err := r.need(int(n)); err != nil {
		return nil, err
	}
	b := r.buf[:n]
	r.buf = r.buf[n:]
	return b, nil
}

func (r *reader) blob8len() ([]byte, error) {
	n, err := r.u8()
	if err != nil {
		return nil, err
	}
	if err := r.need(int(n)); err != nil {
		return nil, err
	}
	b := r.buf[:n]
	r.buf = r.buf[n:]
	return b, nil
}

type writer struct {
	buf []byte
	err error
}

func (w *writer) bytes(b []byte) { w.buf = append(w.buf, b...) }

func (w *writer) u32(v uint32) {
	var tmp [4]byte
	binary.BigEndian.PutUint32(tmp[:], v)
	w.bytes(tmp[:])
}

func (w *writer) u64(v uint64) {
	var tmp [8]byte
	binary.BigEndian.PutUint64(tmp[:], v)
	w.bytes(tmp[:])
}

func (w *writer) u8(v uint8) { w.buf = append(w.buf, v) }

func (w *writer) blob32(b []byte) {
	if uint64(len(b)) > uint64(^uint32(0)) {
		w.err = fmt.Errorf("blob too large")
		return
	}
	w.u32(uint32(len(b)))
	w.bytes(b)
}

func (w *writer) blob64(b []byte) {
	w.u64(uint64(len(b)))
	w.bytes(b)
}

func (w *writer) blob8len(b []byte) {
	if len(b) > 255 {
		w.err = fmt.Errorf("key id too long")
		return
	}
	w.u8(uint8(len(b)))
	w.bytes(b)
}
