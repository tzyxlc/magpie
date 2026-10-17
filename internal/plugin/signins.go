package plugin

// A plugin's sign-in is a key the user typed or a token the plugin saved for
// it, kept in plugin-auth.json. Unlike a subscription's, which is the
// sign-in of an agent on one machine, it belongs to the plugin the user
// installed in magpie, so a backup or a sync that carries the plugin carries
// its sign-ins too — unless it was asked for without keys, as a provider's
// key isn't then.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/yetone/magpie/internal/lastgood"
	"github.com/yetone/magpie/internal/settings"
)

// SignInsFor is the sign-ins the plugins es serve, by account key, as
// plugin-auth.json keeps them. An entry that is a path is this computer's
// alone (Carried leaves it out), so its sign-ins stay here too. When the
// plugins' provider listing isn't known, every sign-in is taken: a key
// can't then be told for a path plugin's, and leaving the others out would
// carry no sign-in at all.
func SignInsFor(es []Entry) map[string]json.RawMessage {
	carried := map[string]bool{}
	for _, e := range es {
		if IsPath(e.Spec) {
			continue
		}
		carried[PackageName(e.Spec)] = true
	}
	listed, known := Listed()
	served := map[string]bool{}
	if known {
		for _, pp := range listed {
			if carried[PackageName(pp.Spec)] {
				served[pp.ID] = true
			}
		}
	}
	var out map[string]json.RawMessage
	for k, v := range authRaw() {
		if known && !served[ProviderOf(k)] {
			continue
		}
		if out == nil {
			out = map[string]json.RawMessage{}
		}
		out[k] = bytes.Clone(v)
	}
	return out
}

// SignInsServed is have, the sign-ins on the server, without those the
// plugins es don't serve: a keyless upload replaced the plugins' list, so
// an account of a plugin it left out is gone from there too, and one of a
// plugin it still names stays. When the listing isn't known, every sign-in
// is kept: a key can't then be told for a plugin that went.
func SignInsServed(have map[string]json.RawMessage, es []Entry) map[string]json.RawMessage {
	if have == nil {
		return nil
	}
	listed, known := Listed()
	if !known {
		return have
	}
	carried := map[string]bool{}
	for _, e := range es {
		if !IsPath(e.Spec) {
			carried[PackageName(e.Spec)] = true
		}
	}
	served := map[string]bool{}
	for _, pp := range listed {
		if carried[PackageName(pp.Spec)] {
			served[pp.ID] = true
		}
	}
	out := map[string]json.RawMessage{}
	for k, v := range have {
		if served[ProviderOf(k)] {
			out[k] = v
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// KeepSignIns puts sign-ins, by account key, into plugin-auth.json: one
// under a key already there replaces it (a token renewed elsewhere), a key
// not there is added (an account signed in elsewhere). None is taken away:
// a sign-out is the computer that made it. Through the running host when
// there is one, so the account's options are read afresh and the gateway is
// told; else in the file under its lock, for a magpie that isn't serving.
func KeepSignIns(ctx context.Context, signs map[string]json.RawMessage) error {
	if len(signs) == 0 {
		return nil
	}
	have := authRaw()
	var changedKeys []string
	for k, v := range signs {
		if sameAuth(have[k], v) {
			continue
		}
		changedKeys = append(changedKeys, k)
	}
	if len(changedKeys) == 0 {
		return nil
	}
	if Running() {
		var errs []error
		for _, k := range changedKeys {
			// decoded first: a json.RawMessage handed over as []byte would
			// reach the host base64-encoded
			var auth map[string]any
			if err := json.Unmarshal(signs[k], &auth); err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", k, err))
				continue
			}
			if err := Restore(ctx, ProviderOf(k), k, auth); err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", k, err))
			}
		}
		return errors.Join(errs...)
	}
	unlock := lockAuth()
	defer unlock()
	// read again under the lock: a host that was running a moment ago, or
	// another magpie, may have written since
	m := map[string]json.RawMessage{}
	b, err := readAuthFile()
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return err // sign-ins that don't read are not written over
	default:
		if err := json.Unmarshal(b, &m); err != nil {
			return err
		}
	}
	wrote := false
	for k, v := range signs {
		if sameAuth(m[k], v) {
			continue
		}
		m[k] = v
		wrote = true
	}
	if !wrote {
		return nil
	}
	out, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(settings.Dir(), 0o700); err != nil {
		return err
	}
	if err := lastgood.Keep(AuthPath(), validAuth, 0o600); err != nil {
		return err
	}
	if err := writeWhole(AuthPath(), append(out, '\n')); err != nil {
		return err
	}
	changed()
	return nil
}

// sameAuth is whether a and b are the same sign-in, whatever the way each
// is written (an indent, the order of its keys): absent is neither.
func sameAuth(a, b json.RawMessage) bool {
	if len(a) == 0 || len(b) == 0 {
		return len(a) == 0 && len(b) == 0
	}
	var x, y any
	if json.Unmarshal(a, &x) != nil || json.Unmarshal(b, &y) != nil {
		return bytes.Equal(a, b)
	}
	ax, errx := json.Marshal(x)
	by, erry := json.Marshal(y)
	return errx == nil && erry == nil && bytes.Equal(ax, by)
}
