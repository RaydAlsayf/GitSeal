// Package managedblock replaces and validates a single line-oriented managed
// block while preserving all text outside it.
package managedblock

import (
	"bytes"
	"errors"
	"fmt"
	"unicode/utf8"
)

func Render(existing []byte, begin, end string, body []string) ([]byte, error) {
	lines, err := parseLines(existing)
	if err != nil {
		return nil, err
	}
	start, finish, err := locate(lines, begin, end)
	if err != nil {
		return nil, err
	}
	managed := make([]string, 0, len(body)+2)
	managed = append(managed, begin)
	managed = append(managed, body...)
	managed = append(managed, end)
	if start >= 0 {
		lines = append(append(append([]string(nil), lines[:start]...), managed...), lines[finish+1:]...)
	} else {
		if len(lines) > 0 && lines[len(lines)-1] == "" {
			lines = lines[:len(lines)-1]
		}
		if len(lines) > 0 {
			lines = append(lines, "")
		}
		lines = append(lines, managed...)
	}
	return encodeLines(lines), nil
}

func Validate(data []byte, begin, end string, body []string) error {
	lines, err := parseLines(data)
	if err != nil {
		return err
	}
	start, finish, err := locate(lines, begin, end)
	if err != nil {
		return err
	}
	if start < 0 {
		return errors.New("managed block is missing")
	}
	want := append(append([]string{begin}, body...), end)
	got := lines[start : finish+1]
	if len(got) != len(want) {
		return errors.New("managed block has extra or missing entries")
	}
	for idx := range want {
		if got[idx] != want[idx] {
			return fmt.Errorf("managed block line %d is not canonical", idx+1)
		}
	}
	return nil
}

func parseLines(data []byte) ([]string, error) {
	if !utf8.Valid(data) || bytes.IndexByte(data, 0) >= 0 {
		return nil, errors.New("managed text file must be valid UTF-8 without NUL")
	}
	data = bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
	if bytes.IndexByte(data, '\r') >= 0 {
		return nil, errors.New("managed text file contains a bare CR")
	}
	if len(data) == 0 {
		return []string{}, nil
	}
	return split(string(data), '\n'), nil
}

func split(value string, separator byte) []string {
	var out []string
	start := 0
	for i := 0; i < len(value); i++ {
		if value[i] == separator {
			out = append(out, value[start:i])
			start = i + 1
		}
	}
	out = append(out, value[start:])
	return out
}

func locate(lines []string, begin, end string) (int, int, error) {
	start, finish := -1, -1
	for idx, line := range lines {
		switch line {
		case begin:
			if start >= 0 {
				return -1, -1, errors.New("duplicate managed block start")
			}
			start = idx
		case end:
			if finish >= 0 {
				return -1, -1, errors.New("duplicate managed block end")
			}
			finish = idx
		}
	}
	if start < 0 && finish < 0 {
		return -1, -1, nil
	}
	if start < 0 || finish < 0 || finish < start {
		return -1, -1, errors.New("malformed managed block markers")
	}
	return start, finish, nil
}

func encodeLines(lines []string) []byte {
	var out bytes.Buffer
	for idx, line := range lines {
		if idx > 0 {
			out.WriteByte('\n')
		}
		out.WriteString(line)
	}
	if out.Len() > 0 && out.Bytes()[out.Len()-1] != '\n' {
		out.WriteByte('\n')
	}
	return out.Bytes()
}
