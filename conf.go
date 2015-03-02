package dkim

import (
	"crypto"
	_ "crypto/sha256"
	"fmt"
	"strconv"
	"strings"
	"time"
)

var (
	minRequired = []string{
		VersionKey,
		AlgorithmKey,
		DomainKey,
		SelectorKey,
		CanonicalizationKey,
		QueryMethodKey,
		TimestampKey,
	}
	keyOrder = []string{
		VersionKey,
		AlgorithmKey,
		CanonicalizationKey,
		DomainKey,
		QueryMethodKey,
		SelectorKey,
		TimestampKey,
		BodyHashKey,
		FieldsKey,
		CopiedFieldsKey,
		AUIDKey,
		BodyLengthKey,
		SignatureDataKey,
	}
)

type Conf map[string]string

const (
	VersionKey          = "v"
	AlgorithmKey        = "a"
	DomainKey           = "d"
	SelectorKey         = "s"
	CanonicalizationKey = "c"
	QueryMethodKey      = "q"
	BodyLengthKey       = "l"
	TimestampKey        = "t"
	ExpireKey           = "x"
	FieldsKey           = "h"
	BodyHashKey         = "bh"
	SignatureDataKey    = "b"
	AUIDKey             = "i"
	CopiedFieldsKey     = "z"
)

const (
	AlgorithmSHA256         = "rsa-sha256"
	DefaultVersion          = "1"
	DefaultCanonicalization = "relaxed/simple"
	DefaultQueryMethod      = "dns/txt"
)

func NewConf(domain string, selector string) (Conf, error) {
	if domain == "" {
		return nil, fmt.Errorf("domain invalid")
	}
	if selector == "" {
		return nil, fmt.Errorf("selector invalid")
	}
	return Conf{
		VersionKey:          DefaultVersion,
		AlgorithmKey:        AlgorithmSHA256,
		DomainKey:           domain,
		SelectorKey:         selector,
		CanonicalizationKey: DefaultCanonicalization,
		QueryMethodKey:      DefaultQueryMethod,
		TimestampKey:        strconv.FormatInt(time.Now().Unix(), 10),
		FieldsKey:           Empty,
		BodyHashKey:         Empty,
		SignatureDataKey:    Empty,
	}, nil
}

func (this Conf) Validate() error {
	for _, key := range minRequired {
		if _, ok := this[key]; !ok {
			return fmt.Errorf("key '%s' missing", key)
		}
	}
	return nil
}

func (this Conf) Algorithm() string {
	if algorithm := this[AlgorithmKey]; algorithm != Empty {
		return algorithm
	}
	return AlgorithmSHA256
}

func (this Conf) Hash() crypto.Hash {
	if this.Algorithm() == AlgorithmSHA256 {
		return crypto.SHA256
	}
	panic("algorithm not implemented")
}

func (this Conf) RelaxedHeader() bool {
	if strings.HasPrefix(strings.ToLower(this[CanonicalizationKey]), "relaxed") {
		return true
	}
	return false
}

func (this Conf) RelaxedBody() bool {
	if strings.HasSuffix(strings.ToLower(this[CanonicalizationKey]), "/relaxed") {
		return true
	}
	return false
}

func (this Conf) String() string {
	pairs := make([]string, 0, len(keyOrder))
	for _, key := range keyOrder {
		if value, ok := this[key]; ok {
			pairs = append(pairs, fmt.Sprintf("%s=%s", key, value))
		}
	}
	return strings.Join(pairs, "; ")
}
