package boring

import (
	"crypto/cipher"

	utlserrors "github.com/refraction-networking/utls/errors"
)

const Enabled bool = false

func NewGCMTLS(_ cipher.Block) (cipher.AEAD, error) {
	return nil, utlserrors.New("tls: boring not implemented").AtError()
}

func NewGCMTLS13(_ cipher.Block) (cipher.AEAD, error) {
	return nil, utlserrors.New("tls: boring not implemented").AtError()
}

func Unreachable() {
	// do nothing
}
