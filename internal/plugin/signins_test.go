package plugin

// A plugin's sign-in travels in a backup or a sync (internal/backup's
// SignIns, davsync's providers part), unlike a subscription's. These cover
// which sign-ins go, and how they are put back.

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/yetone/magpie/internal/settings"
)

// listen writes plugins.json and plugin-providers.json as a host would
// leave them, and plugin-auth.json with the sign-ins given; the folder it
// needs is the one plugin-auth.json shares with the listing.
func signInsSandbox(t *testing.T, plugins string, listed []Provider, auth map[string]any) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "config"))
	t.Setenv("XDG_CACHE_HOME", filepath.Join(dir, "cache"))
	if err := os.MkdirAll(settings.Dir(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ListPath(), []byte(plugins), 0o600); err != nil {
		t.Fatal(err)
	}
	if listed != nil {
		b, _ := json.Marshal(listed)
		if err := os.WriteFile(filepath.Join(settings.Dir(), "plugin-providers.json"), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if auth != nil {
		b, _ := json.MarshalIndent(auth, "", "  ")
		if err := os.WriteFile(AuthPath(), append(b, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	UseCached(nil)
}

func readAuthTest(t *testing.T) map[string]any {
	t.Helper()
	b, err := os.ReadFile(AuthPath())
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("plugin-auth.json doesn't read: %v", err)
	}
	return m
}

// SignInsFor takes a sign-in of each plugin the bundle carries, and none of
// a plugin it doesn't: one taken off this computer, and one added from a
// folder, which is this computer's alone.
func TestSignInsForServesTheCarriedPlugins(t *testing.T) {
	entry := func(spec string) Entry { return Entry{Spec: spec} }
	signInsSandbox(t, `{"plugins":[{"spec":"@scope/wb"},{"spec":"/home/me/mine"}]}`,
		[]Provider{
			{ID: "wb", Spec: "@scope/wb"},
			{ID: "gone", Spec: "@scope/removed"},
			{ID: "mine", Spec: "/home/me/mine"},
		},
		map[string]any{
			"wb":           map[string]any{"type": "oauth", "accountId": "me", "refresh": "r1"},
			"wb#work":      map[string]any{"type": "oauth", "accountId": "work", "refresh": "r2"},
			"gone":         map[string]any{"type": "oauth", "accountId": "me", "refresh": "r3"},
			"mine":         map[string]any{"type": "api", "key": "sk-mine"},
			"never-listed": map[string]any{"type": "api", "key": "sk-x"},
		})
	es := []Entry{entry("@scope/wb"), entry("/home/me/mine")}
	got := SignInsFor(es)
	if want := []string{"wb", "wb#work"}; !slices.Equal(sortedKeys(got), want) {
		t.Fatalf("took %v, want %v", sortedKeys(got), want)
	}
	// without the plugins' listing every sign-in goes: a key can't then be
	// told for a path plugin's, and leaving the rest out would carry none
	signInsSandbox(t, `{"plugins":[{"spec":"@scope/wb"}]}`, nil,
		map[string]any{"wb": map[string]any{"type": "api", "key": "k"}})
	if got := SignInsFor(es); len(got) != 1 {
		t.Fatalf("without a listing took %v, want the one sign-in", sortedKeys(got))
	}
}

// KeepSignIns adds an account, replaces one it has, and leaves this
// computer's own accounts alone. An account's sign-in is written as the
// bundle has it, and the file stays one plugin-auth.json.
func TestKeepSignInsAddsReplacesAndLeavesAlone(t *testing.T) {
	signInsSandbox(t, `{"plugins":[{"spec":"@scope/wb"}]}`, nil,
		map[string]any{
			"wb":      map[string]any{"type": "oauth", "accountId": "me", "refresh": "old"},
			"wb#mine": map[string]any{"type": "api", "key": "mine"},
		})
	signs := map[string]json.RawMessage{
		"wb":      json.RawMessage(`{"type":"oauth","accountId":"me","refresh":"new"}`),
		"wb#work": json.RawMessage(`{"type":"oauth","accountId":"work","refresh":"r2"}`),
	}
	if err := KeepSignIns(context.Background(), signs); err != nil {
		t.Fatal(err)
	}
	got := readAuthTest(t)
	if a := got["wb"].(map[string]any); a["refresh"] != "new" {
		t.Errorf("the account came as %v, want the bundle's", a)
	}
	if a := got["wb#work"].(map[string]any); a["refresh"] != "r2" {
		t.Errorf("the bundle's second account came as %v", got["wb#work"])
	}
	if a := got["wb#mine"].(map[string]any); a["key"] != "mine" {
		t.Errorf("an account this computer had and the bundle didn't is gone: %v", got)
	}
}

// KeepSignIns leaves a file it can't read as it is: sign-ins read as unknown
// are never written over with the bundle's, as SignOut never clears one.
func TestKeepSignInsLeavesAnUnreadableFileAlone(t *testing.T) {
	signInsSandbox(t, `{"plugins":[{"spec":"@scope/wb"}]}`, nil, nil)
	if err := os.WriteFile(AuthPath(), []byte(`{"wb": `), 0o600); err != nil {
		t.Fatal(err)
	}
	err := KeepSignIns(context.Background(), map[string]json.RawMessage{
		"wb#work": json.RawMessage(`{"type":"oauth","accountId":"work","refresh":"r2"}`),
	})
	if err == nil {
		t.Fatal("an unreadable plugin-auth.json was written over")
	}
	if b, _ := os.ReadFile(AuthPath()); string(b) != `{"wb": ` {
		t.Fatalf("the file is now %q", b)
	}
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}
