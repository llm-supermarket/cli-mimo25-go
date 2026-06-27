package crypt

import (
	"crypto/cipher"
	"crypto/subtle"
)

type directionConst bool

const (
	directionEncrypt = directionConst(true)
	directionDecrypt = directionConst(false)
)

func multByTwo(out []byte, in []byte) {
	if len(in) != 16 {
		panic("len must be 16")
	}
	tmp := make([]byte, 16)
	tmp[0] = 2 * in[0]
	tmp[0] = tmp[0] ^ (135 & byte(-(in[15] >> 7)))
	for j := 1; j < 16; j++ {
		tmp[j] = 2 * in[j]
		tmp[j] += in[j-1] >> 7
	}
	copy(out, tmp)
}

func emeXorBlocks(out, in1, in2 []byte) {
	if len(in1) != len(in2) {
		panic("len(in1) != len(in2)")
	}
	subtle.XORBytes(out, in1, in2)
}

func aesTransform(dst, src []byte, direction directionConst, bc cipher.Block) {
	if direction == directionEncrypt {
		bc.Encrypt(dst, src)
	} else {
		bc.Decrypt(dst, src)
	}
}

func tabulateL(bc cipher.Block, m int) [][]byte {
	eZero := make([]byte, 16)
	Li := make([]byte, 16)
	bc.Encrypt(Li, eZero)

	LTable := make([][]byte, m)
	pool := make([]byte, m*16)
	for i := 0; i < m; i++ {
		multByTwo(Li, Li)
		LTable[i] = pool[i*16 : (i+1)*16]
		copy(LTable[i], Li)
	}
	return LTable
}

func emeTransform(bc cipher.Block, tweak []byte, inputData []byte, direction directionConst) []byte {
	T := tweak
	P := inputData
	m := len(P) / 16

	C := make([]byte, len(P))
	LTable := tabulateL(bc, m)

	PPj := make([]byte, 16)
	for j := 0; j < m; j++ {
		Pj := P[j*16 : (j+1)*16]
		emeXorBlocks(PPj, Pj, LTable[j])
		aesTransform(C[j*16:(j+1)*16], PPj, direction, bc)
	}

	MP := make([]byte, 16)
	emeXorBlocks(MP, C[0:16], T)
	for j := 1; j < m; j++ {
		emeXorBlocks(MP, MP, C[j*16:(j+1)*16])
	}

	MC := make([]byte, 16)
	aesTransform(MC, MP, direction, bc)

	M := make([]byte, 16)
	emeXorBlocks(M, MP, MC)
	CCCj := make([]byte, 16)
	for j := 1; j < m; j++ {
		multByTwo(M, M)
		emeXorBlocks(CCCj, C[j*16:(j+1)*16], M)
		copy(C[j*16:(j+1)*16], CCCj)
	}

	CCC1 := make([]byte, 16)
	emeXorBlocks(CCC1, MC, T)
	for j := 1; j < m; j++ {
		emeXorBlocks(CCC1, CCC1, C[j*16:(j+1)*16])
	}
	copy(C[0:16], CCC1)

	for j := 0; j < m; j++ {
		aesTransform(C[j*16:(j+1)*16], C[j*16:(j+1)*16], direction, bc)
		emeXorBlocks(C[j*16:(j+1)*16], C[j*16:(j+1)*16], LTable[j])
	}

	return C
}

func emeEncrypt(block cipher.Block, tweak []byte, data []byte) []byte {
	return emeTransform(block, tweak, data, directionEncrypt)
}

func emeDecryptBlock(block cipher.Block, tweak []byte, data []byte) []byte {
	return emeTransform(block, tweak, data, directionDecrypt)
}
