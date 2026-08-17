package managedblock

import (
	"bytes"
	"testing"
)

func TestRenderPreservesOutsideAndIsIdempotent(t *testing.T) {
	input := []byte("user\r\n# BEGIN X\r\nold\r\n# END X\r\ntail\r\n")
	want := []byte("user\n# BEGIN X\nnew\n# END X\ntail\n")
	got, err := Render(input, "# BEGIN X", "# END X", []string{"new"})
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("Render = %q, %v", got, err)
	}
	again, err := Render(got, "# BEGIN X", "# END X", []string{"new"})
	if err != nil || !bytes.Equal(again, want) {
		t.Fatal("render is not idempotent")
	}
}

func TestMalformedMarkersRejected(t *testing.T) {
	for _, data := range []string{"# BEGIN X\n", "# END X\n", "# BEGIN X\n# BEGIN X\n# END X\n", "# END X\n# BEGIN X\n"} {
		if _, err := Render([]byte(data), "# BEGIN X", "# END X", nil); err == nil {
			t.Errorf("malformed markers accepted: %q", data)
		}
	}
}
