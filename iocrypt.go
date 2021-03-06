// iocrypt - Encrypt/Decrypt io streams using AES/GCM
//
// This library encrypts and decrypts I/O streams using the standard lib
// AES/GCM golang libraries (in contrast to the standard libraries which
// operate on slices of bytes and are unsuitable for direct use with large data
// sets.)
//
// IMPORTANT DISCLAIMER:
//
// I'm NOT a cryptographer and I've put together this in an afternoon. It uses
// the standard libraries to encrypt/decrypt a file in "chunks", so it should be
// safe. Use at your own risk.
//
// (C) 2017 by Marco Paganini <paganini@paganini.net>

package iocrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
)

const (
	// readChunkSize defines the size of the read buffer (in bytes).
	readChunkSize = 64 * (1 << 20)

	// sizeLen holds the length of the field in the header (in bytes).
	sizeLen = 8
)

// Encrypt encrypts data from an io.Reader into an io.Writer using the
// specified key, and returns the number of bytes written to the io.Writer.
func Encrypt(r io.Reader, w io.Writer, key []byte) (int, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return 0, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return 0, err
	}

	// Create a random nonce.
	nonce, err := randomBytes(gcm.NonceSize())
	if err != nil {
		return 0, err
	}

	payload := make([]byte, readChunkSize)

	tbytes := 0

	for {
		// Reset payload slice to original size.
		payload = payload[:readChunkSize]

		nbytes, err := io.ReadFull(r, payload)
		if err == io.EOF {
			break
		}
		if err != nil && err != io.ErrUnexpectedEOF {
			return 0, err
		}
		payload = payload[:nbytes]
		payload = gcm.Seal(payload[:0], nonce, payload, nil)

		// write header.
		header := packNonceAndSize(nonce, len(payload))
		written, err := w.Write(header)
		if err != nil {
			return 0, err
		}
		tbytes += written

		// write payload.
		written, err = w.Write(payload)
		if err != nil {
			return 0, err
		}
		tbytes += written

		// Increment nonce to avoid nonce duplications on next chunk
		incNonce(nonce)
	}

	return tbytes, nil
}

// Decrypt decrypts an encrypted data stream from an io.Reader into an
// io.Writer using the specified key, and returns the number of bytes written
// to the io.Writer.
func Decrypt(r io.Reader, w io.Writer, key []byte) (int, error) {
	return DecryptN(r, w, key, 0)
}

// DecryptN decrypts an encrypted data stream from an io.Reader into an
// io.Writer using the specified key, and returns the number of bytes written
// to the io.Writer. The maximum length limits the number of bytes to read from
// the input stream (including the encryption block headers.) If the maximum
// length is set to zero, the function consumes all bytes in the input stream.
// Nonces are read from the input stream.
func DecryptN(r io.Reader, w io.Writer, key []byte, maxlen int) (int, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return 0, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return 0, err
	}

	header := make([]byte, gcm.NonceSize()+sizeLen+crc32.Size)

	rbytes := 0
	wbytes := 0

	for {
		// Break if we don't have enough bytes left to read the next header.
		if maxlen > 0 && rbytes+len(header) > maxlen {
			break
		}

		// Read header. When decrypting we need to read the header first to
		// allocate the buffer for the encrypted payload following the header.
		// It's not acceptable to have a short read in the header, so any error
		// (other than EOF) causes the function to return.
		nbytes, err := io.ReadFull(r, header)
		if err == io.EOF {
			break
		}
		if err != nil {
			return 0, err
		}
		rbytes += nbytes

		nonce, payloadLen, err := unpackNonceAndSize(header, gcm.NonceSize())
		if err != nil {
			return 0, err
		}

		// Break if we don't have enough bytes left to read the next payload block.
		if maxlen > 0 && rbytes+payloadLen > maxlen {
			break
		}

		// Allocate buffer and decrypt payload.
		payload := make([]byte, payloadLen)
		nbytes, err = io.ReadFull(r, payload)
		if err != nil {
			return 0, err
		}
		payload, err = gcm.Open(payload[:0], nonce, payload, nil)
		if err != nil {
			return 0, err
		}
		rbytes += nbytes

		// Write payload.
		written, err := w.Write(payload)
		if err != nil {
			return 0, err
		}
		wbytes += written
	}
	// If we have a specified maxlen, the number of read bytes must match exactly.
	if maxlen > 0 && rbytes != maxlen {
		return 0, fmt.Errorf("decoded %d bytes. Expected %d", rbytes, maxlen)
	}

	return wbytes, nil
}

// RandomAES128Key returns a randomly generated AES128 key.
func RandomAES128Key() ([]byte, error) {
	return randomBytes(16)
}

// RandomAES256Key returns a randomly generated AES256 key.
func RandomAES256Key() ([]byte, error) {
	return randomBytes(32)
}

// packNonceAndSize packs the nonce, size and their CRC32 into a byte slice.
func packNonceAndSize(nonce []byte, size int) []byte {
	nlen := len(nonce)
	sizeoffset := nlen
	crcoffset := sizeoffset + sizeLen

	ret := make([]byte, nlen+sizeLen+crc32.Size)
	copy(ret, nonce)

	binary.LittleEndian.PutUint64(ret[sizeoffset:], uint64(size))
	crc := crc32.ChecksumIEEE(ret[0:crcoffset])
	binary.LittleEndian.PutUint32(ret[crcoffset:], crc)

	return ret
}

// unpackNonceAndSize retrieves the nonce and size from a byte slice.
// Returns an error if the checksum of nonce+size does not match.
func unpackNonceAndSize(b []byte, nonceSize int) ([]byte, int, error) {
	nonce := b[0:nonceSize]
	crcoffset := nonceSize + sizeLen

	size := binary.LittleEndian.Uint64(b[nonceSize:crcoffset])
	crc := crc32.ChecksumIEEE(b[0:crcoffset])
	hcrc := binary.LittleEndian.Uint32(b[crcoffset:])

	if crc != hcrc {
		return nil, 0, fmt.Errorf("corrupt header or not an encrypted file. Got CRC %x, expected %x", hcrc, crc)
	}
	return nonce, int(size), nil
}

// incNonce increments the nonce (not the counter) by one.
func incNonce(nonce []byte) {
	n := binary.LittleEndian.Uint64(nonce) + 1
	binary.LittleEndian.PutUint64(nonce, n)
}

// randomBytes returns a byte slice of random bytes.
func randomBytes(n int) ([]byte, error) {
	ret := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, ret); err != nil {
		return []byte{}, err
	}
	return ret, nil
}
