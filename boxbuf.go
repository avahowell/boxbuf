package boxbuf

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"

	"golang.org/x/crypto/nacl/box"
)

// maxBlockSize determines the amount of data written to an EncWriter before a
// new block is written
const maxBlockSize = 16384 // 16 kb

// EncWriter is an io.Writer that can be used to encrypt data with a peer's
// public key. EncWriter uses golang.org/x/crypto/nacl/box to perform
// asymmetric encryption.
type EncWriter struct {
	out io.Writer
	buf []byte

	publicKey      [32]byte
	secretKey      [32]byte
	peersPublicKey [32]byte
}

// DecReader is an io.Reader that can be used to decrypt data using a secret
// key. DecWriter uses golang.org/x/crypto/nacl/box to perform asymmetric
// decryption.
type DecReader struct {
	in    io.Reader
	buf   []byte
	index int

	secretKey      [32]byte
	peersPublicKey [32]byte
}

// NewWriter intializes a new EncWriter using peersPublicKey to encrypt all
// data, writing the result to `out`.
func NewWriter(peersPublicKey [32]byte, out io.Writer) (*EncWriter, error) {
	// TODO: naming here (pk vs peersPublicKey, need consistent naming)
	// TODO: is this the optimal API? it seems very opinionated. one might want
	// to pass the sender keypair, for example.
	pk, sk, err := box.GenerateKey(rand.Reader)
	if err != nil {
		panic("could not generate keys for encryption")
	}
	_, err = out.Write(pk[:])
	if err != nil {
		return nil, err
	}
	return &EncWriter{
		peersPublicKey: peersPublicKey,
		publicKey:      *pk,
		secretKey:      *sk,
		out:            out,
	}, nil
}

// NewReader creates a new DecReader using secretKey to decrypt the data as
// needed from in.
func NewReader(secretKey [32]byte, in io.Reader) (*DecReader, error) {
	var peersPublicKey [32]byte
	_, err := io.ReadFull(in, peersPublicKey[:])
	if err != nil {
		return nil, err
	}
	return &DecReader{
		secretKey:      secretKey,
		peersPublicKey: peersPublicKey,
		in:             in,
	}, nil
}

// Write writes the entirety of p to the underlying io.Writer, encrypting the
// data with the public key and chunking as needed.
func (w *EncWriter) Write(p []byte) (int, error) {
	for i, b := range p {
		if len(w.buf) == maxBlockSize {
			err := w.writeBlock()
			if err != nil {
				return i, err
			}
		}
		w.buf = append(w.buf, b)
	}
	err := w.writeBlock()
	return len(p), err
}

// writeBlock writes a block using EncWriter's buf and resets the buffer.
func (w *EncWriter) writeBlock() error {
	var nonce [24]byte
	_, err := io.ReadFull(rand.Reader, nonce[:])
	if err != nil {
		panic("could not read entropy for encryption")
	}

	encryptedData := box.Seal(nil, w.buf, &nonce, &w.peersPublicKey, &w.secretKey)
	w.buf = nil

	_, err = w.out.Write(nonce[:])
	if err != nil {
		return err
	}
	blockSize := uint64(len(encryptedData))
	err = binary.Write(w.out, binary.LittleEndian, blockSize)
	if err != nil {
		return err
	}
	_, err = w.out.Write(encryptedData)
	return err
}

// Read reads from the underlying io.Reader, decrypting bytes as needed, until
// len(p) byte have been read or the underlying stream is exhausted.
func (b *DecReader) Read(p []byte) (int, error) {
	for i := range p {
		if b.index == 0 {
			err := b.nextBlock()
			if err != nil {
				return len(p) - i, err
			}
		}
		p[i] = b.buf[b.index]
		b.index++
		if b.index >= len(b.buf) {
			b.index = 0
		}
	}
	return len(p), nil
}

// nextBlock reads the next block into DecReader's buf.
func (b *DecReader) nextBlock() error {
	var nonce [24]byte
	_, err := io.ReadFull(b.in, nonce[:])
	if err != nil {
		return err
	}
	var blockSize uint64
	err = binary.Read(b.in, binary.LittleEndian, &blockSize)
	if err != nil {
		return err
	}
	blockData := make([]byte, blockSize)
	_, err = io.ReadFull(b.in, blockData)
	if err != nil {
		return err
	}
	decryptedBytes, success := box.Open(nil, blockData, &nonce, &b.peersPublicKey, &b.secretKey)
	if !success {
		return errors.New("could not decrypt block")
	}
	b.buf = decryptedBytes
	return nil
}
