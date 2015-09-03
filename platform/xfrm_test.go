// +build linux

package platform

import (
	"testing"

	"msgbox.io/context"
)

func TestXfrmReader(t *testing.T) {
	parent := context.Background()
	cxt := Listen(parent)
	<-cxt.Done()
}
