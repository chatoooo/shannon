package go_shannon

import (
	"bytes"
	"errors"
)

const (
	n         uint   = 16
	fold      uint   = n
	initKonst uint32 = 0x6996c53a
	keyp      uint   = 13
)

func sbox1(w uint32) uint32 {
	w = w ^ (w<<5 | w>>(32 - 5) | (w<<7 | w>>(32 - 7)))
	w = w ^ (w<<19 | w>>(32 - 19) | (w<<22 | w>>(32 - 22)))
	return w
}

func sbox2(w uint32) uint32 {
	w = w ^ (w<<7 | w>>(32 - 7) | (w<<22 | w>>(32 - 22)))
	w = w ^ (w<<5 | w>>(32 - 5) | (w<<19 | w>>(32 - 19)))
	return w
}

func rotl(w uint32, x uint) uint32 {
	return (w << x) | (w >> (32 - x))
}

// Struct for shannon cipher state
type Shannon struct {
	r     []uint32
	crc   []uint32
	initR []uint32
	konst uint32
	sbuf  uint32
	mbuf  uint32
	nbuf  uint
}

type fullWordCallback func(*Shannon, *uint32)
type byteCallback func(*Shannon, *byte)

/**
Creates a new instance of Shannon cipher
 */
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

func (sInst *Shannon) saveState() {
	copy(sInst.initR, sInst.r)
}

func (sInst *Shannon) genKonst() {
	sInst.konst = sInst.r[0]
}

func (sInst *Shannon) reloadState() {
	copy(sInst.r, sInst.initR)
}

func (sInst *Shannon) loadKey(key []byte) {
	// start folding in key
	for _, word := range chunkBytes(key, 4) {
		if len(word) == 4 {
			sInst.r[keyp] ^= readLittleEndian(word)
		} else {
			// if there were any extra key bytes, zero pad to a word
			xtra := make([]byte, 4)
			for i := 0; i < len(word); i++ {
				xtra[i] = word[i]
			}
			sInst.r[keyp] ^= readLittleEndian(xtra)
		}
		sInst.cycle()
	}

	// also fold in the length of the key
	sInst.r[keyp] ^= uint32(len(key))
	sInst.cycle()

	// save a copy of the register
	copy(sInst.crc, sInst.r)

	// now diffuse
	sInst.diffuse()

	// now xor the copy back -- makes key loading irreversible
	for i := 0; i < 16; i++ {
		sInst.r[i] ^= sInst.crc[i]
	}
}

func (sInst *Shannon) diffuse() {
	for i := uint(0); i < fold; i++ {
		sInst.cycle()
	}
}

func (sInst *Shannon) cycle() {
	// nonlinear feedback function
	t := sInst.r[12] ^ sInst.r[13] ^ sInst.konst
	t = sbox1(t) ^ rotl(sInst.r[0], 1)

	// shift register
	for i := uint(1); i < n; i++ {
		sInst.r[i-1] = sInst.r[i]
	}
	sInst.r[n-1] = t
	t = sbox2(sInst.r[2] ^ sInst.r[15])
	sInst.r[0] ^= t
	sInst.sbuf = t ^ sInst.r[8] ^ sInst.r[12]
}

/**
Updates nonce
 */
func (sInst *Shannon) Nonce(nonce []byte) {
	sInst.reloadState()
	sInst.konst = initKonst
	sInst.loadKey(nonce)
	sInst.genKonst()
	sInst.nbuf = 0
}

// Accumulate a CRC of input words, later to be fed into MAC.
// sInst is actually 32 parallel CRC-16s, using the IBM CRC-16
// polynomial x^16 + x^15 + x^2 + 1.
func (sInst *Shannon) crcFunc(i uint32) {
	t := sInst.crc[0] ^ sInst.crc[2] ^ sInst.crc[15] ^ i
	for j := uint(1); j < n; j++ {
		sInst.crc[j-1] = sInst.crc[j]
	}
	sInst.crc[n-1] = t
}

func (sInst *Shannon) macFunc(i uint32) {
	sInst.crcFunc(i)
	sInst.r[keyp] ^= i
}

func (sInst *Shannon) process(buf []byte, fullWord fullWordCallback, partial byteCallback) {
	// handle any previously buffered bytes
	if sInst.nbuf != 0 {
		for i := 0; sInst.nbuf > 0; i++ {
			if i < len(buf) {
				partial(sInst, &buf[i])
				sInst.nbuf -= 8
			} else {
				// not a whole word yet
				return
			}
			// LFSR already cycled
			m := sInst.mbuf
			sInst.macFunc(m)
		}
	}

	// handle whole words
	length := len(buf) &^ 0x3
	wbuf, extra := buf[:length], buf[length:]
	for _, word := range chunkBytes(wbuf, 4) {
		sInst.cycle()
		t := readLittleEndian(word)
		fullWord(sInst, &t)
		writeLittleEndian(word, t)
	}

	// handle any trailing bytes
	if len(extra) > 0 {
		sInst.cycle()
		sInst.mbuf = 0
		sInst.nbuf = 32
		for i := range extra {
			partial(sInst, &extra[i])
			sInst.nbuf -= 8
		}
	}
}

// Combined MAC and encryption.
// Note that plaintext is accumulated for MAC.
func (sInst *Shannon) Encrypt(buf []byte) {
	sInst.process(buf,
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
func (sInst *Shannon) Decrypt(buf []byte) {
	sInst.process(buf,
		func(ctx *Shannon, word *uint32) {
			*word ^= ctx.sbuf
			ctx.macFunc(*word)
		},
		func(ctx *Shannon, b *byte) {
			*b ^= byte((ctx.sbuf >> (32 - ctx.nbuf)) & 0xFF)
			ctx.mbuf ^= uint32(*b) << (32 - ctx.nbuf)
		})
}

/**
Outputs MAC into the buffer
 */
func (sInst *Shannon) Finish(buf []byte) {
	// handle any previously buffered bytes
	if sInst.nbuf != 0 {
		m := sInst.mbuf
		sInst.macFunc(m)
	}

	// perturb the MAC to mark end of input.
	// Note that only the stream register is updated, not the CRC. sInst is an
	// action that can't be duplicated by passing in plaintext, hence
	// defeating any kind of extension attack.
	//
	sInst.cycle()
	sInst.r[keyp] ^= initKonst ^ (uint32(sInst.nbuf) << 3)
	sInst.nbuf = 0

	// now add the CRC to the stream register and diffuse it
	for i := uint(0); i < n; i++ {
		sInst.r[i] ^= sInst.crc[i]
	}
	sInst.diffuse()

	// produce output from the stream buffer
	for _, word := range chunkBytes(buf, 4) {
		sInst.cycle()
		if len(word) == 4 {
			writeLittleEndian(word, sInst.sbuf)
		} else {
			for i := range word {
				word[i] = byte((sInst.sbuf >> (8 * uint(i))) & 0xFF)
			}
		}
	}
}

/**
Updates nonce as BigEndian uint32
 */
func (sInst *Shannon) NonceU32(n uint32) {
	nonce := make([]byte, 4)
	writeBigEndian(nonce, n)
	sInst.Nonce(nonce)
}

/**
Checks MAC integrity
 */
func (sInst *Shannon) CheckMac(expected []byte) error {
	actual := make([]byte, len(expected))
	sInst.Finish(actual)

	if bytes.Compare(actual, expected) != 0 {
		return errors.New("MAC mismatch")
	}
	return nil
}
