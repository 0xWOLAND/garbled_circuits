package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
)

type GateType int

const (
	AND GateType = iota
	OR
	XOR
)

const LabelLength = 16 // Length in bytes for labels

type Wire struct {
	l0 []byte
	l1 []byte
}

type Gate struct {
	table [4][]byte
	typ   GateType
}

func genLabel() []byte {
	label := make([]byte, LabelLength)
	if _, err := rand.Read(label); err != nil {
		panic(err)
	}
	return label
}

func newWire() Wire {
	return Wire{
		l0: genLabel(),
		l1: genLabel(),
	}
}

func enc(key, plaintext []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		panic(err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}

	return append(nonce, aesgcm.Seal(nil, nonce, plaintext, nil)...)
}

func dec(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}

	nonce := ciphertext[:12]
	ct := ciphertext[12:]

	return aesgcm.Open(nil, nonce, ct, nil)
}

func garbleGate(gate Gate, in1, in2, out Wire) Gate {
	for i := range gate.table {
		_in1 := in1.l0
		_in2 := in2.l0
		if i == 1 || i == 3 {
			_in1 = in1.l1
		}
		if i == 2 || i == 3 {
			_in2 = in2.l1
		}

		var _out []byte
		switch gate.typ {
		case AND:
			if i == 3 {
				_out = out.l1
			} else {
				_out = out.l0
			}
		case OR:
			if i == 0 {
				_out = out.l0
			} else {
				_out = out.l1
			}
		case XOR:
			if i == 1 || i == 2 {
				_out = out.l1
			} else {
				_out = out.l0
			}
		}

		key := make([]byte, len(_in1))
		for j := range key {
			key[j] = _in1[j] ^ _in2[j]
		}

		gate.table[i] = enc(key, _out)
	}

	return gate
}

func evaluateGate(gate Gate, l1, l2 []byte) ([]byte, error) {
	key := make([]byte, LabelLength)
	for i := range key {
		key[i] = l1[i] ^ l2[i]
	}

	for _, entry := range gate.table {
		if result, err := dec(key, entry); err == nil {
			return result, nil
		}
	}

	return nil, fmt.Errorf("failed to evaluate gate")
}

func main() {
	// Test all gate types
	gateTypes := []GateType{AND, OR, XOR}
	gateNames := map[GateType]string{AND: "AND", OR: "OR", XOR: "XOR"}

	for _, gateType := range gateTypes {
		fmt.Printf("\nTesting %s gate:\n", gateNames[gateType])
		fmt.Println("in1 in2 out")
		fmt.Println("--- --- ---")

		in1 := newWire()
		in2 := newWire()
		out := newWire()

		garbledGate := garbleGate(Gate{typ: gateType}, in1, in2, out)

		// Test all input combinations
		inputs := [][2][]byte{
			{in1.l0, in2.l0}, // 0,0
			{in1.l0, in2.l1}, // 0,1
			{in1.l1, in2.l0}, // 1,0
			{in1.l1, in2.l1}, // 1,1
		}

		for i, input := range inputs {
			result, err := evaluateGate(garbledGate, input[0], input[1])
			if err != nil {
				panic(err)
			}

			// Determine expected output based on gate type and inputs
			var expectedOutput []byte
			switch gateType {
			case AND:
				if i == 3 {
					expectedOutput = out.l1
				} else {
					expectedOutput = out.l0
				}
			case OR:
				if i == 0 {
					expectedOutput = out.l0
				} else {
					expectedOutput = out.l1
				}
			case XOR:
				if i == 1 || i == 2 {
					expectedOutput = out.l1
				} else {
					expectedOutput = out.l0
				}
			}

			if string(result) != string(expectedOutput) {
				panic(fmt.Sprintf("failed to evaluate %s gate for input combination %d", gateNames[gateType], i))
			}

			// Print truth table row
			in1Val := i >> 1 // 0 for first two rows, 1 for last two
			in2Val := i & 1  // alternates 0,1,0,1
			outVal := 0
			if string(result) == string(out.l1) {
				outVal = 1
			}
			fmt.Printf(" %d   %d   %d\n", in1Val, in2Val, outVal)
		}
	}
}
