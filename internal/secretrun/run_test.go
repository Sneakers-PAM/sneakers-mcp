// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package secretrun

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Sneakers-PAM/sneakers-mcp/internal/gwclient"
)

type fakeGateway struct {
	states       []string
	boundArgv    []string
	value        string
	prepared     []string
	polls        int
	redeemed     bool
	prepareLabel string
	prepareRun   gwclient.Run
}

func (f *fakeGateway) use(state string) gwclient.SecretUse {
	return gwclient.SecretUse{ID: "use-1", State: state, Argv: f.boundArgv, ApprovalURL: "https://sneakers.example.org/approvals"}
}

func (f *fakeGateway) PrepareSecretUse(_ context.Context, token, secretID, fieldKey string, argv []string, label string, run ...gwclient.Run) (gwclient.SecretUse, error) {
	f.prepared = append([]string{token, secretID, fieldKey}, argv...)
	f.prepareLabel = label
	if len(run) > 0 {
		f.prepareRun = run[0]
	}
	if f.boundArgv == nil {
		f.boundArgv = argv
	}
	return f.use(f.states[0]), nil
}

func (f *fakeGateway) SecretUse(context.Context, string, string) (gwclient.SecretUse, error) {
	f.polls++
	i := f.polls
	if i >= len(f.states) {
		i = len(f.states) - 1
	}
	return f.use(f.states[i]), nil
}

func (f *fakeGateway) RedeemSecretUse(context.Context, string, string) (string, gwclient.SecretUse, error) {
	f.redeemed = true
	return f.value, f.use("REDEEMED"), nil
}

func opts(argv ...string) (Options, *bytes.Buffer, *bytes.Buffer) {
	var out, errb bytes.Buffer
	return Options{
		Token: "snk_u_x", SecretID: "s1", FieldKey: "password", Argv: argv, Label: "laptop",
		Inject: InjectStdin, PollInterval: time.Millisecond, Stdout: &out, Stderr: &errb,
	}, &out, &errb
}

func TestRunWaitsForApprovalThenFeedsTheValueOnStdinAndMasksOutput(t *testing.T) {
	gw := &fakeGateway{states: []string{"PENDING", "PENDING", "APPROVED"}, value: "hunter2"}
	o, out, errb := opts("sh", "-c", `read v; echo "got $v"`)
	code, err := Run(context.Background(), gw, o)
	if err != nil || code != 0 {
		t.Fatalf("code=%d err=%v stderr=%q", code, err, errb.String())
	}
	if strings.Join(gw.prepared[:3], " ") != "snk_u_x s1 password" || gw.prepareLabel != "laptop" || !gw.redeemed {
		t.Fatalf("prepared=%v label=%q redeemed=%v", gw.prepared, gw.prepareLabel, gw.redeemed)
	}
	if !strings.Contains(errb.String(), "https://sneakers.example.org/approvals") {
		t.Fatalf("approval link not shown: %q", errb.String())
	}
	if out.String() != "got "+maskText+"\n" {
		t.Fatalf("stdout = %q", out.String())
	}
}

func TestRunStopsWhenTheUseIsDenied(t *testing.T) {
	gw := &fakeGateway{states: []string{"PENDING", "DENIED"}, value: "hunter2"}
	o, _, _ := opts("true")
	if _, err := Run(context.Background(), gw, o); err == nil || gw.redeemed {
		t.Fatalf("a denied use must not redeem: err=%v", err)
	}
}

func TestRunRefusesACommandOtherThanTheOneApproved(t *testing.T) {
	gw := &fakeGateway{states: []string{"APPROVED"}, value: "hunter2", boundArgv: []string{"sh", "-c", "echo other"}}
	o, out, _ := opts("sh", "-c", "echo mine")
	if _, err := Run(context.Background(), gw, o); !errors.Is(err, ErrArgvMismatch) || out.Len() != 0 {
		t.Fatalf("err=%v out=%q", err, out.String())
	}
}

func TestRunFileInjectionUsesAPrivateTempFileAndRemovesIt(t *testing.T) {
	gw := &fakeGateway{states: []string{"APPROVED"}, value: "hunter2"}
	o, out, errb := opts("sh", "-c", `stat -c %a "$1"; cat "$1"; echo; echo "$1" >&2`, "sh", FilePlaceholder)
	o.Inject = InjectFile
	code, err := Run(context.Background(), gw, o)
	if err != nil || code != 0 {
		t.Fatalf("code=%d err=%v stderr=%q", code, err, errb.String())
	}
	if out.String() != "600\n"+maskText+"\n" {
		t.Fatalf("stdout = %q", out.String())
	}
	path := strings.TrimSpace(errb.String()[strings.LastIndex(strings.TrimSpace(errb.String()), "\n")+1:])
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Fatalf("temp file %q still exists", path)
	}
}

func TestRunKeepsTheTokenOutOfTheChildEnvironment(t *testing.T) {
	t.Setenv(TokenEnv, "snk_u_x")
	gw := &fakeGateway{states: []string{"APPROVED"}, value: "hunter2"}
	o, out, _ := opts("sh", "-c", `echo "[$`+TokenEnv+`]"`)
	if _, err := Run(context.Background(), gw, o); err != nil || out.String() != "[]\n" {
		t.Fatalf("err=%v stdout=%q", err, out.String())
	}
}

func TestRunReturnsTheChildExitCode(t *testing.T) {
	gw := &fakeGateway{states: []string{"APPROVED"}, value: "hunter2"}
	o, _, _ := opts("sh", "-c", "exit 3")
	if code, err := Run(context.Background(), gw, o); err != nil || code != 3 {
		t.Fatalf("code=%d err=%v", code, err)
	}
}

func recordOpens(o *Options) *[]string {
	var opened []string
	o.Open = func(u string) { opened = append(opened, u) }
	return &opened
}

func TestRunOpensTheApprovalPageOnceForAPendingUse(t *testing.T) {
	gw := &fakeGateway{states: []string{"PENDING", "PENDING", "PENDING", "APPROVED"}, value: "hunter2"}
	o, _, errb := opts("true")
	opened := recordOpens(&o)
	if _, err := Run(context.Background(), gw, o); err != nil {
		t.Fatal(err)
	}
	if len(*opened) != 1 || (*opened)[0] != "https://sneakers.example.org/approvals" {
		t.Fatalf("opened = %q, want the approval URL once", *opened)
	}
	if !strings.Contains(errb.String(), "https://sneakers.example.org/approvals") {
		t.Fatalf("the link must still be printed: %q", errb.String())
	}
}

func TestRunNeverOpensForAnAutoApprovedUse(t *testing.T) {
	gw := &fakeGateway{states: []string{"APPROVED"}, value: "hunter2"}
	o, _, _ := opts("true")
	opened := recordOpens(&o)
	if _, err := Run(context.Background(), gw, o); err != nil || len(*opened) != 0 {
		t.Fatalf("err=%v opened=%q", err, *opened)
	}
}

func TestRunWithoutAnOpenerStillPrintsTheLink(t *testing.T) {
	gw := &fakeGateway{states: []string{"PENDING", "APPROVED"}, value: "hunter2"}
	o, _, errb := opts("true")
	if _, err := Run(context.Background(), gw, o); err != nil || !strings.Contains(errb.String(), "https://sneakers.example.org/approvals") {
		t.Fatalf("err=%v stderr=%q", err, errb.String())
	}
}
