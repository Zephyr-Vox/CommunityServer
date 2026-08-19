package realtime

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
)

var (
	// ErrInvalidEntityETag is returned when a caller cannot form one of the
	// protocol's strong single-resource ETags.
	ErrInvalidEntityETag = errors.New("realtime: invalid entity etag")
	// ErrInvalidConfigETag is returned when effective-config ETag input lacks a
	// valid target/source scope, version, or JSON configuration.
	ErrInvalidConfigETag = errors.New("realtime: invalid config etag")
)

// roleKeyPattern matches the immutable role-key grammar used by strong ETags.
var roleKeyPattern = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,63}$`)

// EntityETag returns the protocol's quoted strong ETag for a group, channel,
// role, or mute. identity must already be the resource's canonical decimal ID
// or immutable role key.
func EntityETag(kind, identity string, version int64) (string, error) {
	if version < 1 {
		return "", ErrInvalidEntityETag
	}
	switch kind {
	case "group", "channel", "mute":
		if !isCanonicalPositiveID(identity) {
			return "", ErrInvalidEntityETag
		}
	case "role":
		if !roleKeyPattern.MatchString(identity) {
			return "", ErrInvalidEntityETag
		}
	default:
		return "", ErrInvalidEntityETag
	}
	return fmt.Sprintf(`"%s:%s:%d"`, kind, identity, version), nil
}

// NumericEntityETag returns an EntityETag for one positive numeric resource ID.
func NumericEntityETag(kind string, id, version int64) (string, error) {
	if id <= 0 {
		return "", ErrInvalidEntityETag
	}
	return EntityETag(kind, strconv.FormatInt(id, 10), version)
}

// EffectiveConfigETagInput identifies the complete fact represented by one
// effective permission configuration, including inheritance provenance.
type EffectiveConfigETagInput struct {
	Target        Scope
	Local         bool
	Source        Scope
	SourceVersion int64
	Config        string
}

// EffectiveConfigETag returns the quoted base64url SHA-256 ETag required for
// a local or inherited permission configuration. Config is normalized before
// hashing so insignificant object formatting cannot produce distinct ETags.
func EffectiveConfigETag(input EffectiveConfigETagInput) (string, error) {
	if !input.Target.Valid() || !input.Source.Valid() || input.SourceVersion < 1 {
		return "", ErrInvalidConfigETag
	}
	config, err := canonicalJSON(input.Config)
	if err != nil {
		return "", ErrInvalidConfigETag
	}
	encoded := fmt.Sprintf(
		"target=%s\nlocal=%t\nsource=%s\nsource_version=%d\nconfig=%s",
		input.Target.Key(), input.Local, input.Source.Key(), input.SourceVersion, config,
	)
	digest := sha256.Sum256([]byte(encoded))
	return `"` + base64.RawURLEncoding.EncodeToString(digest[:]) + `"`, nil
}

// canonicalJSON validates one JSON value and emits encoding/json's stable
// representation. Permission arrays are already sorted by ConfigStore.
func canonicalJSON(raw string) (string, error) {
	var value map[string][]string
	if err := json.Unmarshal([]byte(raw), &value); err != nil {
		return "", err
	}
	if value == nil {
		return "", errors.New("permission config must be an object")
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}

// isCanonicalPositiveID validates a decimal ID without leading zeroes.
func isCanonicalPositiveID(value string) bool {
	id, err := strconv.ParseInt(value, 10, 64)
	return err == nil && id > 0 && strconv.FormatInt(id, 10) == value
}
