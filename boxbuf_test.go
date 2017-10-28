package boxbuf

import (
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"io"
	"testing"

	"golang.org/x/crypto/nacl/box"
)

// TestSecureBuffers verifies that data can be encrypted and decrypted at
// various sizes using EncWriters and DecReaders.
func TestSecureBuffers(t *testing.T) {
	tests := []struct {
		sourceData []byte
	}{
		{[]byte("this is a test")},
		{make([]byte, maxBlockSize-1)},
		{make([]byte, maxBlockSize+1)},
		{make([]byte, maxBlockSize)},
		{func() []byte {
			res := make([]byte, 300e6)
			_, err := io.ReadFull(rand.Reader, res)
			if err != nil {
				t.Fatal(err)
			}
			return res
		}()},
	}
	for _, test := range tests {
		t.Log("testing with", len(test.sourceData), "B of data")
		result := new(bytes.Buffer)
		pk, sk, err := box.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		encWriter, err := NewWriter(*pk, result)
		if err != nil {
			t.Fatal(err)
		}
		if len(encWriter.buf) > maxBlockSize*3 { // there should never be more than 3 chunks buffered in memory
			t.Fatal("encWriter is leaking chunks")
		}
		n, err := encWriter.Write(test.sourceData)
		if err != nil {
			t.Fatal(err)
		}
		if n != len(test.sourceData) {
			t.Fatal("output was not the correct length got", n, "wanted", len(test.sourceData))
		}
		if !sufficientEntropy(result.Bytes()) {
			t.Fatal("resulting output was not uniformly random")
		}
		decReader, err := NewReader(*sk, result)
		if err != nil {
			t.Fatal(err)
		}
		decryptedData := make([]byte, len(test.sourceData))
		_, err = decReader.Read(decryptedData)
		if err != nil {
			t.Fatal(err)
		}
		if len(decReader.buf) > maxBlockSize*3 { // there should never be more than 3 chunks buffered in memory
			t.Fatal("decReader is leaking chunks")
		}
		if !bytes.Equal(decryptedData, test.sourceData) {
			t.Fatal("data decrypt mismatch got", decryptedData, "wanted", test.sourceData)
		}
	}
}

func sufficientEntropy(data []byte) bool {
	b := new(bytes.Buffer)
	zip, _ := gzip.NewWriterLevel(b, gzip.BestCompression)
	if _, err := zip.Write(data); err != nil {
		panic(err)
	}
	if err := zip.Close(); err != nil {
		panic(err)
	}
	if b.Len() < len(data) {
		return false
	}
	return true
}
