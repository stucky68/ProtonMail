package utils

import (
	"bytes"
	"crypto/rand"
	"errors"
	"math/big"
)

func GetRandomString(len int) string {
	var container string
	var str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
	b := bytes.NewBufferString(str)
	length := b.Len()
	bigInt := big.NewInt(int64(length))
	for i := 0;i < len ;i++  {
		randomInt,_ := rand.Int(rand.Reader,bigInt)
		container += string(str[randomInt.Int64()])
	}
	return container
}

func blockCopy(src []byte, srcOffset int, dst []byte, dstOffset, count int) (bool, error) {
	srcLen := len(src)
	if srcOffset > srcLen || count > srcLen || srcOffset+count > srcLen {
		return false, errors.New("源缓冲区 索引超出范围")
	}
	dstLen := len(dst)
	if dstOffset > dstLen || count > dstLen || dstOffset+count > dstLen {
		return false, errors.New("目标缓冲区 索引超出范围")
	}
	index := 0
	for i := srcOffset; i < srcOffset+count; i++ {
		dst[dstOffset+index] = src[srcOffset+index]
		index++
	}
	return true, nil
}

func Radix64Encode(in []byte) []byte {
	m := []byte{
		'.', '/', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J',
		'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V',
		'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
		'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't',
		'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5',
		'6', '7', '8', '9'}

	l := len(in)
	length := 4 * (l / 3)
	if l % 3 != 0 {
		length += l % 3 + 1
	}

	out := make([]byte, length)
	index :=0
	end := l - l % 3

	for i := 0; i < end; i += 3 {
		out[index] = m[(in[i]&0xff)>>2]
		index++
		out[index] = m[((in[i]&0x03)<<4)|((in[i+1]&0xff)>>4)]
		index++
		out[index] = m[((in[i+1]&0x0f)<<2)|((in[i+2]&0xff)>>6)]
		index++
		out[index] = m[(in[i+2] & 0x3f)]
		index++
	}

	switch l % 3 {
	case 1:
		out[index] = m[(in[end]&0xff)>>2]
		index++
		out[index] = m[(in[end]&0x03)<<4]
	case 2:
		out[index] = m[(in[end]&0xff)>>2]
		index++
		out[index] = m[((in[end]&0x03)<<4)|((in[end+1]&0xff)>>4)]
		index++
		out[index] = m[((in[end+1] & 0x0f) << 2)]
	}
	return out
}

func Radix64Decode(in []byte) []byte {
	DECODE_TABLE := []int{
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0, 1, 54, 55, 56, 57,
		58, 59, 60, 61, 62, 63, -1, -1, -1, -2, -1, -1, -1, 2, 3, 4, 5, 6, 7,
		8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
		26, 27, -1, -1, -1, -1, -1, -1, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37,
		38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53}
	limit := len(in)
	for ; limit > 0; limit-- {
		c := in[limit-1]
		if c != '=' && c != '\n' && c != '\r' && c != ' ' && c != '\t' {
			break
		}
	}

	out := make([]byte, limit*6/8)
	outCount := 0
	inCount := 0
	word := 0
	for pos := 0; pos < limit; pos++ {
		c := in[pos]
		bits := 0
		if c == '.' || c == '/' || (c >= 'A' && c <= 'z') || (c >= '0' && c <= '9') {
			bits = int(DECODE_TABLE[c])
		} else if c == '\n' || c == '\r' || c == ' ' || c == '\t' {
			continue
		}

		// Append this char's 6 bits to the word.
		word = (word << 6) | bits

		// For every 4 chars of input, we accumulate 24 bits of output. Emit 3 bytes.
		inCount++
		if inCount%4 == 0 {
			out[outCount] = byte(word >> 16)
			outCount++

			out[outCount] = byte(word >> 8)
			outCount++

			out[outCount] = byte(word)
			outCount++
		}
	}

	lastWordChars := inCount % 4
	if lastWordChars == 1 {
		// We read 1 char followed by "===". But 6 bits is a truncated byte! Fail.
		return []byte{}
	} else if lastWordChars == 2 {
		// We read 2 chars followed by "==". Emit 1 byte with 8 of those 12 bits.
		word = word << 12
		out[outCount] = (byte)(word >> 16)
		outCount++
	} else if lastWordChars == 3 {
		// We read 3 chars, followed by "=". Emit 2 bytes for 16 of those 18 bits.
		word = word << 6
		out[outCount] = (byte)(word >> 16)
		outCount++
		out[outCount] = (byte)(word >> 8)
		outCount++
	}

	if outCount == len(out) {
		return out
	}

	prefix := make([]byte, outCount)
	copy(prefix, out)

	blockCopy(out, 0, prefix, 0, outCount)
	return prefix
}
