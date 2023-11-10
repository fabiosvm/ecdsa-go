package elliptic

import (
	"io"
	"math/big"
)

type Curve interface {
	GenerateValidScalar(rand io.Reader) (*big.Int, error)
	IsValidScalar(scalar *big.Int) bool
	ContainsPoint(p *Point) bool
	AddPoints(p, q *Point) (*Point, error)
	DoublePoint(p *Point) (*Point, error)
	ScalarMultiplyPoint(p *Point, scalar *big.Int) (*Point, error)
	ScalarBaseMultiplyPoint(scalar *big.Int) (*Point, error)
}
