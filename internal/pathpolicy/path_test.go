package pathpolicy

import "testing"

func TestParsePortablePath(t *testing.T) {
	valid := []string{".env", "config/private.json", "A-Z_0/file.age"}
	for _, value := range valid {
		if _, err := Parse(value); err != nil {
			t.Errorf("Parse(%q): %v", value, err)
		}
	}
	invalid := []string{
		"", "/absolute", "trailing/", "a//b", "a/../b", "./a", "a\\b",
		"with space", "unicodé", "a:b", ".git/config", ".GITSeal/config.yaml",
		"dir/.gitseal.tmp.secret", "NUL", "con.txt", "COM1.log", "lpt9", "file.",
		"*.env", "[abc]", "line\nfeed",
	}
	for _, value := range invalid {
		if _, err := Parse(value); err == nil {
			t.Errorf("Parse(%q) unexpectedly succeeded", value)
		}
	}
}

func TestCheckMappingsCollisions(t *testing.T) {
	if err := CheckMappings([][2]string{{"a", "a.age"}, {"b", "b.age"}}); err != nil {
		t.Fatal(err)
	}
	for _, pairs := range [][][2]string{
		{{"a", "A"}},
		{{"a", "a.age"}, {"A.AGE", "b"}},
		{{"a", "x"}, {"b", "X"}},
	} {
		if err := CheckMappings(pairs); err == nil {
			t.Errorf("CheckMappings(%v) unexpectedly succeeded", pairs)
		}
	}
}

func FuzzParse(f *testing.F) {
	for _, seed := range []string{".env", "../escape", "CON.txt", "dir/.gitseal.tmp.x", "a/b.age", "é"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		parsed, err := Parse(value)
		if err == nil && parsed.String() != value {
			t.Fatalf("successful parse changed input: %q -> %q", value, parsed)
		}
	})
}
