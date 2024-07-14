package ssh

import (
	"bytes"
	"strings"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol/http"
)

type version byte

const (
	SSH1 version = iota
	SSH2
)

type SniffHeader struct {
	version version
	host    string
}

func (s SniffHeader) Protocol() string {
	switch s.version {
	case SSH1:
		return "ssh1"
	case SSH2:
		return "ssh2"
	default:
		return "unknown"
	}
}

func (s SniffHeader) Domain() string {
	return s.host
}

var (
	keyExchangePrefixSSH1 = []byte{'S', 'S', 'H', '-', '1', '.', '5', '-'}
	keyExchangePrefixSSH2 = []byte{'S', 'S', 'H', '-', '2', '.', '0', '-'}

	errNotSSH = errors.New("not SSH")
)

func SniffSSH(b []byte) (*SniffHeader, error) {
	if len(b) < 10 {
		return nil, common.ErrNoClue
	}

	if b[len(b)-1] != '\n' {
		return nil, errNotSSH
	}

	sh := &SniffHeader{
		version: SSH1,
	}

	if bytes.HasPrefix(b, keyExchangePrefixSSH1) {
		return sh, nil
	} else if bytes.HasPrefix(b, keyExchangePrefixSSH2) && b[len(b)-2] == '\r' {
		sh.version = SSH2
	} else {
		return nil, errNotSSH
	}

	parts := bytes.SplitN(b[len(keyExchangePrefixSSH2):len(b)-2], []byte{' '}, 2)
	if len(parts) == 2 {
		rawComment := strings.ToLower(string(bytes.TrimSpace(parts[1])))
		dest, err := http.ParseHost(rawComment, net.Port(22))
		if err == nil {
			sh.host = dest.Address.String()
		}
	}

	return sh, nil
}
