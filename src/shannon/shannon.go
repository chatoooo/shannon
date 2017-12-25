package shannon

import (
	"errors"
	"bytes"
)

const (
	n         uint   = 16
	fold      uint   = n
	initKonst uint32 = 0x6996c53a
	keyp      uint   = 13
)

func sbox1(w uint32) uint32 {
	w = w ^ (w<<5 | w>>32 - 5 | (w<<7 | w>>32 - 7))
	w = w ^ (w<<19 | w>>32 - 19 | (w<<22 | w>>32 - 22))
	return w
}

func sbox2(w uint32) uint32 {
	w = w ^ (w<<7 | w>>32 - 7 | (w<<22 | w>>32 - 22))
	w = w ^ (w<<5 | w>>32 - 5 | (w<<19 | w>>32 - 19))
	return w
}

func rotl(w uint32, x uint) uint32 {
	return (w << x) | (w >> (32 - x))
}

type Shannon struct {
	r     []uint32
	crc   []uint32
	initR []uint32
	konst uint32
	sbuf  uint32
	mbuf  uint32
	nbuf  uint
}

type FullWordCallback func(*Shannon, *uint32)
type ByteCallback func(*Shannon, *byte)


func ShannonNew(key []byte) *Shannon {
	result := new(Shannon)
	result.r = make([]uint32, n)
	result.crc = make([]uint32, n)
	result.initR = make([]uint32, n)
	result.konst = initKonst
	result.sbuf = 0
	result.mbuf = 0
	result.nbuf = 0

	result.r[0] = 1
	result.r[1] = 1
	for i := uint(2); i < n; i++ {
		result.r[i] = result.r[i-1] + result.r[i-2]
	}

	result.loadKey(key)
	result.genKonst()
	result.saveState()

	return result
}

func (this *Shannon) saveState() {
	copy(this.initR, this.r)
}

func (this *Shannon) genKonst() {
	this.konst = this.r[0]
}

func (this *Shannon) reloadState() {
	copy(this.r, this.initR)
}

func (this *Shannon) loadKey(key []byte) {
	// start folding in key
	for _, word := range chunkBytes(key, 4) {
		if len(word) == 4 {
			this.r[keyp] ^= readLittleEndian(word)
		} else {
			// if there were any extra key bytes, zero pad to a word
			xtra := make([]byte, 4)
			for i := 0; i < len(word); i++ {
				xtra[i] = word[i]
			}
			this.r[keyp] ^= readLittleEndian(xtra)
		}
		this.cycle()
	}

	// also fold in the length of the key
	this.r[keyp] ^= uint32(len(key))
	this.cycle()

	// save a copy of the register
	copy(this.crc,this.r)

	// now diffuse
	this.diffuse()

	// now xor the copy back -- makes key loading irreversible
	for i := 0; i < 16; i++ {
		this.r[i] ^= this.crc[i]
	}
}

func (this *Shannon) diffuse() {
	for i := uint(0); i < fold; i++ {
		this.cycle()
	}
}

func (this *Shannon) cycle() {
	// nonlinear feedback function
	t := this.r[12] ^ this.r[13] ^ this.konst
	t = sbox1(t) ^ rotl(this.r[0], 1)

	// shift register
	for i := uint(1); i < n; i++ {
		this.r[i-1] = this.r[i]
	}
	this.r[n-1] = t
	t = sbox2(this.r[2] ^ this.r[15])
	this.r[0] ^= t
	this.sbuf = t ^ this.r[8] ^ this.r[12]
}

func (this *Shannon) Nonce(nonce []byte) {
	this.reloadState()
	this.konst = initKonst
	this.loadKey(nonce)
	this.genKonst()
	this.nbuf = 0
}

// Accumulate a CRC of input words, later to be fed into MAC.
// This is actually 32 parallel CRC-16s, using the IBM CRC-16
// polynomial x^16 + x^15 + x^2 + 1.
func (this *Shannon) crcFunc(i uint32) {
	t := this.crc[0] ^ this.crc[2] ^ this.crc[15] ^ i
	for j := uint(1); j < n; j++ {
		this.crc[j-1] = this.crc[j]
	}
	this.crc[n-1] = t
}

func (this *Shannon) macFunc(i uint32) {
	this.crcFunc(i)
	this.r[keyp] ^= i
}

func (this *Shannon) process(buf []byte, fullWord FullWordCallback, partial ByteCallback) {
	// handle any previously buffered bytes
	if this.nbuf != 0 {
		for i:=0;this.nbuf > 0;i++ {
			if i<len(buf) {
				partial(this, &buf[i])
				this.nbuf -= 8
			} else {
				// not a whole word yet
				return
			}
			// LFSR already cycled
			m := this.mbuf
			this.macFunc(m)
		}
	}

	// handle whole words
	length := len(buf) &^ 0x3
	wbuf, extra := buf[:length], buf[length:]
	for _, word :=range chunkBytes(wbuf, 4) {
		this.cycle()
		t := readLittleEndian(word)
		fullWord(this, &t)
		writeLittleEndian(word, t)
	}

	// handle any trailing bytes
	if len(extra) > 0 {
		this.cycle()
		this.mbuf = 0
		this.nbuf = 32
		for i := range extra {
			partial(this, &extra[i])
			this.nbuf -= 8
		}
	}
}

// Combined MAC and encryption.
// Note that plaintext is accumulated for MAC.
func (this *Shannon) Encrypt(buf []byte) {
	this.process(buf,
		func(ctx *Shannon, word *uint32) {
			ctx.macFunc(*word)
			*word ^= ctx.sbuf
		},
		func(ctx *Shannon, b *byte) {
			ctx.mbuf ^= uint32(*b) << (32 - ctx.nbuf)
			*b ^= byte((ctx.sbuf >> (32 - ctx.nbuf)) & 0xFF)
		})
}

// Combined MAC and decryption.
// Note that plaintext is accumulated for MAC.
func (this *Shannon) Decrypt(buf []byte) {
	this.process(buf,
		func(ctx *Shannon, word *uint32) {
			*word ^= ctx.sbuf
			ctx.macFunc(*word)
		},
		func(ctx *Shannon, b *byte) {
			*b ^= byte((ctx.sbuf >> (32 - ctx.nbuf)) & 0xFF)
			ctx.mbuf ^= uint32(*b) << (32 - ctx.nbuf)
		})
}

func (this *Shannon) Finish(buf []byte) {
	// handle any previously buffered bytes
	if this.nbuf != 0 {
		m := this.mbuf
		this.macFunc(m)
	}

	// perturb the MAC to mark end of input.
	// Note that only the stream register is updated, not the CRC. This is an
	// action that can't be duplicated by passing in plaintext, hence
	// defeating any kind of extension attack.
	//
	this.cycle()
	this.r[keyp] ^= initKonst ^ (uint32(this.nbuf) << 3)
	this.nbuf = 0

	// now add the CRC to the stream register and diffuse it
	for i := uint(0); i < n; i++ {
		this.r[i] ^= this.crc[i]
	}
	this.diffuse()

	// produce output from the stream buffer
	for _, word := range chunkBytes(buf, 4) {
		this.cycle()
		if len(word) == 4 {
			writeLittleEndian(word, this.sbuf)
		} else {
			for i := range word {
				word[i] = byte((this.sbuf >> (8 * uint(i))) & 0xFF)
			}
		}
	}
}

func (this *Shannon) NonceU32(n uint32) {
	nonce := make([]byte, 4)
	writeBigEndian(nonce, n)
	this.Nonce(nonce)
}


func (this *Shannon) CheckMac(expected []byte) error {
	actual := make([]byte, len(expected))
	this.Finish(actual)

	if bytes.Compare(actual, expected) != 0 {
		return errors.New("MAC mismatch")
	} else {
		return nil
	}
}
