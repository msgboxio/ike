// +build linux

package platform

import (
	"testing"

	"github.com/msgboxio/context"
)

func TestXfrmReader(t *testing.T) {
	parent := context.Background()
	cxt := Listen(parent)
	<-cxt.Done()
}
