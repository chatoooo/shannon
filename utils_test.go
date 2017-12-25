package go_shannon

import (
	"testing"
	"github.com/stretchr/testify/assert"
)

func TestReadLittleEndian(t *testing.T) {
	assert := assert.New(t)
	assert.Equal(uint32(0x01020304), readLittleEndian([]byte{0x4, 0x3, 0x2, 0x1}))
}

func TestWriteLittleEndian(t *testing.T) {
	assert := assert.New(t)
	buf := make([]byte, 4)
	writeLittleEndian(buf, uint32(0x01020304))
	assert.Equal([]byte{0x4, 0x3, 0x2, 0x1}, buf)
}

func TestWriteBigEndian(t *testing.T) {
	assert := assert.New(t)
	buf := make([]byte, 4)
	writeBigEndian(buf, uint32(0x01020304))
	assert.Equal([]byte{0x1, 0x2, 0x3, 0x4}, buf)
}

func TestChunkBytes(t *testing.T) {
	assert := assert.New(t)
	buf := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9}
	chunks := chunkBytes(buf, 4)
	assert.Equal([][]byte{{1, 2, 3, 4}, {5, 6, 7, 8}, {9}}, chunks)
	chunks[1][0] = 15
	assert.Equal([]byte{1, 2, 3, 4, 15, 6, 7, 8, 9}, buf)
	for _, word := range chunks {
		if len(word) > 1 {
			word[1] = 20
		}
	}
	assert.Equal([]byte{1, 20, 3, 4, 15, 20, 7, 8, 9}, buf)
}
