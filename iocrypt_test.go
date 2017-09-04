// Unit tests for iocrypt.

package iocrypt

import (
	"bytes"
	"fmt"
	"log"
	"testing"
)

func TestIOCrypt(t *testing.T) {
	casetests := []struct {
		plainLen               int  // Generate random plaintext of this length if != 0.
		cryptLen               int  // Generate random crypttext of this length if != 0.
		forceDecryptMaxLen     bool // force decryptMaxLen bytes on decrypt (0=all).
		decryptMaxLen          int
		forceDecryptBufPadding bool // If true, add some padding to decrypted text.
		useAES256              bool
		wantError              bool
	}{
		// Message under default chunk size.
		{
			plainLen:  100,
			wantError: false,
		},
		// Message under default chunk size (AES256).
		{
			plainLen:  100,
			useAES256: true,
			wantError: false,
		},
		// Message over default chunk size.
		{
			plainLen:  readChunkSize*2 + 100,
			wantError: false,
		},
		// Max number of encrypted bytes == 0 (read entire input stream).
		{
			plainLen:           100,
			forceDecryptMaxLen: true,
			decryptMaxLen:      0,
			wantError:          false,
		},
		// Max number of encrypted bytes < header length (24), fail.
		{
			plainLen:           100,
			forceDecryptMaxLen: true,
			decryptMaxLen:      20,
			wantError:          true,
		},
		// Max number of encrypted bytes < header+payload length, fail.
		{
			plainLen:           100,
			forceDecryptMaxLen: true,
			decryptMaxLen:      30,
			wantError:          true,
		},
		// Force a decrypt buffer with trailing contents (should be ignored since we use size).
		{
			plainLen:               100,
			forceDecryptBufPadding: true,
			wantError:              false,
		},
		// Invalid encrypted input.
		{
			cryptLen:  100,
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

		// Generate plaintext of specified size
		var plaintext []byte
		if tt.plainLen > 0 {
			plaintext = make([]byte, tt.plainLen)
			for i := 0; i < len(plaintext); i++ {
				plaintext[i] = byte(0x41 + (i % 26))
			}
		}

		cryptSize := 0
		if tt.plainLen > 0 {
			cryptSize, err = Encrypt(bytes.NewBuffer(plaintext), cryptbuf, key)
			if err != nil {
				t.Fatalf("Got error %q want no error", err)
			}
		}

		// Crypttext override.
		if tt.cryptLen > 0 {
			crypttext := make([]byte, tt.cryptLen)
			for i := 0; i < len(crypttext); i++ {
				crypttext[i] = byte(0x41 + (i % 26))
			}
			cryptbuf = bytes.NewBuffer(crypttext)
		}
		// cryptSize override.
		if tt.forceDecryptMaxLen {
			cryptSize = tt.decryptMaxLen
		}

		// Make a copy of buffer and add 100 bytes of padding if requested.
		// This is useful to make sure we're not reading past the number of
		// requested bytes.
		if tt.forceDecryptBufPadding {
			b := make([]byte, cryptbuf.Len()+100)
			copy(b, cryptbuf.Bytes())
			cryptbuf = bytes.NewBuffer(b)
		}

		_, err = DecryptN(cryptbuf, decryptbuf, key, cryptSize)
		if tt.wantError {
			if err == nil {
				t.Fatalf("Got no error, want error")
			}
			continue
		}
		if err != nil {
			t.Fatalf("Got error %q want no error", err)
		}

		if !bytes.Equal(decryptbuf.Bytes(), plaintext) {
			// Suppress large outputs
			if len(plaintext) > 256 {
				plaintext = []byte("(suppressed)")
			}
			t.Errorf("diff: plaintext %q does not match encrypted version\n", plaintext)
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
