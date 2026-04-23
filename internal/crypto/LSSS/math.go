package lsss

import (
	"filippo.io/edwards25519"
)

id := edwards25519.NewidentityPoint()

id.Add(id, id) // id + id = 2*id = id (modulo l)
