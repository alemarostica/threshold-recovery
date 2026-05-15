package test

import "testing"

func logSection(t *testing.T, title string) {
	t.Helper()
	t.Logf("\n========== %s ==========", title)
}

func logOK(t *testing.T, msg string) {
	t.Helper()
	t.Logf("[OK] %s", msg)
}

