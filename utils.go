package go_shannon

func chunkBytes(data []byte, size uint) [][]byte {
	length := uint(len(data))
	res := make([][]byte, 0, length/size+1)
	for s := uint(0); s < length; s += size {
		e := s + size
		if e > length {
			e = length
		}
		res = append(res, data[s:e])
	}
	return res
}

func readLittleEndian(data []byte) (result uint32) {
	result |= uint32(data[3])
	result <<= 8
	result |= uint32(data[2])
	result <<= 8
	result |= uint32(data[1])
	result <<= 8
	result |= uint32(data[0])
	return
}

func writeLittleEndian(result []byte, data uint32) {
	result[0] = byte(data & 0xFF)
	data >>= 8
	result[1] = byte(data & 0xFF)
	data >>= 8
	result[2] = byte(data & 0xFF)
	data >>= 8
	result[3] = byte(data & 0xFF)
}

func writeBigEndian(result []byte, data uint32) {
	result[3] = byte(data & 0xFF)
	data >>= 8
	result[2] = byte(data & 0xFF)
	data >>= 8
	result[1] = byte(data & 0xFF)
	data >>= 8
	result[0] = byte(data & 0xFF)
}
