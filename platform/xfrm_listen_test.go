// +build linux

package platform

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/davecgh/go-spew/spew"
)

func TestListenClose(t *testing.T) {
	l := ListenForEvents(context.Background(), nil)
	time.Sleep(100 * time.Millisecond)
	if err := l.Err(); err != nil {
		t.Fatal(err)
	}
	l.Close()
	<-l.Done()
	if err := l.Err(); err != context.Canceled {
		t.Fatal(err)
	}
}

func command(t *testing.T, str string) error {
	splits := strings.Split(str, " ")
	cmd := exec.Command(splits[0], splits[1:]...)
	out, err := cmd.CombinedOutput()
	t.Logf("cmd: %s ; out: %s", str, string(out))
	return err
}

func TestListen(t *testing.T) {
	wg := &sync.WaitGroup{}
	wg.Add(1)
	cb := func(msg interface{}) {
		t.Log(spew.Sdump(msg))
		wg.Done()
	}
	l := ListenForEvents(context.Background(), cb)
	if err := l.Err(); err != nil {
		t.Fatal(err)
	}
	cmd := fmt.Sprintf(
		"ip xfrm policy add src %s dst %s dir in tmpl src %s dst %s proto esp reqid 1 mode tunnel",
		"127.0.0.1", "127.0.0.2", "127.0.0.1/32", "127.0.0.2/32",
	)
	if err := command(t, cmd); err != nil {
		t.Fatal(err)
	}
	wg.Wait()

	wg.Add(1)
	l.Close()
	<-l.Done()
	if err := l.Err(); err != context.Canceled {
		t.Fatal(err)
	}

	if err := command(t, "ip xfrm policy flush"); err != nil {
		t.Fatal(err)
	}
}
