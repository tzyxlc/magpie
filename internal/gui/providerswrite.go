package gui

import (
	"bufio"
	"bytes"
	"encoding/json"
	"net/http"
)

// providersNull is how a providersJSON with no providers begins:
// Providers is its first field.
const providersNull = `{"providers":null`

// writeProvidersJSON writes s to rw as writeJSON does, each provider's row
// encoded alone. Encoding the answer whole grew a buffer to its size each
// poll: 27 MB of what forty polls of the Providers page allocated with
// real accounts.
func writeProvidersJSON(rw http.ResponseWriter, s providersJSON) {
	rows := s.Providers
	s.Providers = nil
	tail, err := json.Marshal(s)
	if rows == nil || err != nil || !bytes.HasPrefix(tail, []byte(providersNull)) {
		s.Providers = rows
		writeJSON(rw, s)
		return
	}
	rw.Header().Set("Content-Type", "application/json")
	out := bufio.NewWriterSize(rw, 32<<10)
	defer out.Flush()
	_, _ = out.WriteString(`{"providers":[`)
	enc := json.NewEncoder(lineless{out})
	for i := range rows {
		if i > 0 {
			_ = out.WriteByte(',')
		}
		// a pointer, so a method on *T is used as it is in the slice
		if enc.Encode(&rows[i]) != nil {
			return
		}
	}
	_ = out.WriteByte(']')
	_, _ = out.Write(tail[len(providersNull):])
	_ = out.WriteByte('\n')
}
