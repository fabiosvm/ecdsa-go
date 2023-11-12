package elliptic

import (
	"encoding/hex"
	"math/big"
)

type Point struct {
	X, Y *big.Int
}

func NewPoint(x, y *big.Int) *Point {
	return &Point{
		X: x,
		Y: y,
	}
}

func NewPointAtInfinity() *Point {
	return NewPoint(nil, nil)
}

func NewPointFromBytes(bytes []byte) *Point {
	n := len(bytes) / 2
	xBytes, yBytes := bytes[:n], bytes[n:]
	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)
	return NewPoint(x, y)
}

func NewPointFromString(str string) (*Point, error) {
	bytes, err := hex.DecodeString(str)
	if err != nil {
		return nil, err
	}
	return NewPointFromBytes(bytes), nil
}

func (p *Point) Bytes() []byte {
	xBytes, yBytes := p.X.Bytes(), p.Y.Bytes()
	n := len(p.X.Bytes())
	bytes := make([]byte, n*2)
	copy(bytes[:n], xBytes)
	copy(bytes[n:], yBytes)
	return bytes
}

func (p *Point) String() string {
	return hex.EncodeToString(p.Bytes())
}

func (p *Point) IsAtInfinity() bool {
	return p.X == nil && p.Y == nil
}

func (p *Point) IsEqual(other *Point) bool {
	if p.IsAtInfinity() && other.IsAtInfinity() {
		return true
	}
	if p.IsAtInfinity() || other.IsAtInfinity() {
		return false
	}
	return p.X.Cmp(other.X) == 0 && p.Y.Cmp(other.Y) == 0
}
