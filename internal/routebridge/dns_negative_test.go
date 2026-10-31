package routebridge

import (
	"context"
	"encoding/binary"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func TestNegativeDNSWithDottedSOAMailbox(t *testing.T) {
	for _, tc := range []struct {
		name string
		code dnsmessage.RCode
		want string
	}{
		{"no-a", dnsmessage.RCodeSuccess, "no_address"},
		{"nxdomain", dnsmessage.RCodeNameError, "nxdomain"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				b, _ := io.ReadAll(r.Body)
				var q dnsmessage.Message
				if err := q.Unpack(b); err != nil {
					t.Error(err)
					return
				}
				q.Response = true
				q.RCode = tc.code
				out, err := q.Pack()
				if err != nil {
					t.Error(err)
					return
				}
				// SOA RNAME can contain a dot inside the mailbox's first wire label.
				// dnsmessage.Name cannot represent it; this ancillary field is not an A answer.
				soa := []byte{2, 'n', 's', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
					8, 'o', 'p', 's', '.', 't', 'e', 'a', 'm', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}
				for range 5 {
					soa = binary.BigEndian.AppendUint32(soa, 60)
				}
				binary.BigEndian.PutUint16(out[8:10], 1)
				out = append(out, 0xc0, 0x0c)
				out = binary.BigEndian.AppendUint16(out, uint16(dnsmessage.TypeSOA))
				out = binary.BigEndian.AppendUint16(out, uint16(dnsmessage.ClassINET))
				out = binary.BigEndian.AppendUint32(out, 60)
				out = binary.BigEndian.AppendUint16(out, uint16(len(soa)))
				out = append(out, soa...)
				w.Header().Set("Content-Type", "application/dns-message")
				w.Write(out)
			}))
			defer srv.Close()
			ips, status := resolvePublic(context.Background(), srv.Client(), srv.URL, "api.example.com")
			if status != tc.want || len(ips) != 0 {
				t.Fatalf("got %q %v, want %q", status, ips, tc.want)
			}
		})
	}
}

func TestDNSResponseValidationSurvivesSelectiveParsing(t *testing.T) {
	for _, kind := range []string{"wrong-id", "wrong-question", "not-response", "truncated", "missing-question", "extra-question", "broken-answer", "broken-authority", "broken-additional"} {
		t.Run(kind, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				b, _ := io.ReadAll(r.Body)
				var q dnsmessage.Message
				if err := q.Unpack(b); err != nil {
					t.Error(err)
					return
				}
				q.Response = true
				switch kind {
				case "wrong-id":
					q.ID++
				case "wrong-question":
					q.Questions[0].Type = dnsmessage.TypeAAAA
				case "not-response":
					q.Response = false
				case "truncated":
					q.Truncated = true
				case "missing-question":
					q.Questions = nil
				case "extra-question":
					q.Questions = append(q.Questions, q.Questions[0])
				}
				out, err := q.Pack()
				if err != nil {
					t.Error(err)
					return
				}
				switch kind {
				case "broken-answer":
					binary.BigEndian.PutUint16(out[6:8], 1)
				case "broken-authority":
					binary.BigEndian.PutUint16(out[8:10], 1)
				case "broken-additional":
					binary.BigEndian.PutUint16(out[10:12], 1)
				}
				w.Header().Set("Content-Type", "application/dns-message")
				w.Write(out)
			}))
			defer srv.Close()
			ips, status := resolvePublic(context.Background(), srv.Client(), srv.URL, "api.example.com")
			if status != "dns_response" || len(ips) != 0 {
				t.Fatalf("invalid response accepted: %s %v", status, ips)
			}
		})
	}
}
