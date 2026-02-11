package main

import "testing"

func TestEncodeLength(t *testing.T) {
	tests := []struct {
		n    int
		want []byte
	}{
		{0, []byte{0x00}},
		{1, []byte{0x01}},
		{127, []byte{0x7F}},
		{128, []byte{0x80, 0x80}},
		{255, []byte{0x80, 0xFF}},
		{256, []byte{0x81, 0x00}},
		{16383, []byte{0xBF, 0xFF}},
		{16384, []byte{0xC0, 0x40, 0x00}},
		{2097151, []byte{0xDF, 0xFF, 0xFF}},
		{2097152, []byte{0xE0, 0x20, 0x00, 0x00}},
		{268435456, []byte{0xF0, 0x10, 0x00, 0x00, 0x00}},
	}
	for _, tt := range tests {
		got := encodeLength(tt.n)
		if len(got) != len(tt.want) {
			t.Errorf("encodeLength(%d) = %v, want %v", tt.n, got, tt.want)
			continue
		}
		for i := range got {
			if got[i] != tt.want[i] {
				t.Errorf("encodeLength(%d) = %v, want %v", tt.n, got, tt.want)
				break
			}
		}
	}
}

func TestParseMikrotikAttrs(t *testing.T) {
	tests := []struct {
		name  string
		words []string
		want  map[string]string
	}{
		{"empty", nil, map[string]string{}},
		{"single", []string{"=name=MyRouter"}, map[string]string{"name": "MyRouter"}},
		{"multiple", []string{"=name=MyRouter", "=model=RB450Gx4"}, map[string]string{"name": "MyRouter", "model": "RB450Gx4"}},
		{"equals in value", []string{"=comment=a=b=c"}, map[string]string{"comment": "a=b=c"}},
		{"ignores non-attr", []string{"!re", "=name=test"}, map[string]string{"name": "test"}},
		{"empty value", []string{"=disabled="}, map[string]string{"disabled": ""}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseMikrotikAttrs(tt.words)
			if len(got) != len(tt.want) {
				t.Errorf("got %v, want %v", got, tt.want)
				return
			}
			for k, v := range tt.want {
				if got[k] != v {
					t.Errorf("key %q: got %q, want %q", k, got[k], v)
				}
			}
		})
	}
}
