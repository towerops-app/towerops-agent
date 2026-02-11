package main

import "testing"

func TestParsePingTime(t *testing.T) {
	tests := []struct {
		name    string
		output  string
		want    float64
		wantErr bool
	}{
		{
			name:   "standard linux",
			output: "64 bytes from 8.8.8.8: icmp_seq=1 ttl=118 time=12.3 ms",
			want:   12.3,
		},
		{
			name:   "localhost",
			output: "64 bytes from localhost: icmp_seq=1 ttl=64 time=0.123 ms",
			want:   0.123,
		},
		{
			name:   "multiline",
			output: "PING 8.8.8.8 (8.8.8.8): 56 data bytes\n64 bytes from 8.8.8.8: icmp_seq=0 ttl=118 time=15.7 ms\n--- 8.8.8.8 ping statistics ---",
			want:   15.7,
		},
		{
			name:    "no time field",
			output:  "Request timeout for icmp_seq 0",
			wantErr: true,
		},
		{
			name:    "empty",
			output:  "",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parsePingTime(tt.output)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error, got %v", got)
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}
