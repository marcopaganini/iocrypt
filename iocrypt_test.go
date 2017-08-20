// Unit tests for iocrypt.

package iocrypt

import (
	"bytes"
	"fmt"
	"github.com/kylelemons/godebug/pretty"
	"log"
	"testing"
)

func TestIOCrypt(t *testing.T) {
	casetests := []struct {
		plain     []byte
		crypt     []byte
		useAES256 bool
		wantError bool
	}{
		// Message under default chunk size (AES128)
		{
			plain:     []byte("The quick brown fox jumps over the lazy dog 1234567890 times"),
			wantError: false,
		},
		// Message under default chunk size (AES256)
		{
			plain:     []byte("The quick brown fox jumps over the lazy dog 1234567890 times"),
			useAES256: true,
			wantError: false,
		},
		// Invalid encrypted input.
		{
			crypt:     []byte("Totally invalid encrypted input"),
			wantError: true,
		},
	}

	for _, tt := range casetests {
		key, err := RandomAES128Key()
		if tt.useAES256 {
			key, err = RandomAES256Key()
		}
		if err != nil {
			t.Fatalf("Got error creating key, want no error")
		}

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

		_, err = Decrypt(cryptbuf, decryptbuf, key)
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

func ExampleEncrypt() {
	r := bytes.NewBufferString("Vanilla Plaintext")
	w := &bytes.Buffer{}

	key, err := RandomAES128Key()
	if err != nil {
		log.Fatal(err)
	}

	n, err := Encrypt(r, w, key)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Wrote %d encrypted bytes\n", n)
	// Output: Wrote 57 encrypted bytes
}
