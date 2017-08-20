// Unit tests for iocrypt.

package iocrypt

import (
	"bytes"
	"github.com/kylelemons/godebug/pretty"
	"testing"
)

func TestIOCrypt(t *testing.T) {

	casetests := []struct {
		plain     []byte
		crypt     []byte
		wantError bool
	}{
		// Message under default chunk size.
		{
			plain:     []byte("The quick brown fox jumps over the lazy dog 1234567890 times"),
			wantError: false,
		},
		// Invalid encrypted input.
		{
			crypt:     []byte("Totally invalid encrypted input"),
			wantError: true,
		},
	}

	key, err := RandomBytes(16)
	if err != nil {
		t.Fatalf("Got error creating key, want no error")
	}

	for _, tt := range casetests {
		cryptbuf := &bytes.Buffer{}
		decryptbuf := &bytes.Buffer{}

		if tt.plain != nil {
			_, err := Encrypt(bytes.NewBuffer(tt.plain), cryptbuf, key)
			if tt.wantError {
				if err == nil {
					t.Fatalf("Got no error, want error")
				}
				continue
			}
			if err != nil {
				t.Fatalf("Got error %q want no error", err)
			}
		}

		// Crypttext override.
		if tt.crypt != nil {
			cryptbuf = bytes.NewBuffer(tt.crypt)
		}

		_, err := Decrypt(cryptbuf, decryptbuf, key)
		if tt.wantError {
			if err == nil {
				t.Fatalf("Got no error, want error")
			}
			continue
		}
		if err != nil {
			t.Fatalf("Got error %q want no error", err)
		}

		if diff := pretty.Compare(decryptbuf.Bytes(), tt.plain); diff != "" {
			t.Errorf("diff: (-got +want)\n%s", diff)
		}
	}
}
