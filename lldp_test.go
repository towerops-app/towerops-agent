// Copyright (C) 2026 Graham McIntire
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"slices"
	"testing"
)

func TestSortedLldpKeys(t *testing.T) {
	got := sortedLldpKeys(map[string]string{"3.2.1": "c", "1.2.1": "a", "2.2.1": "b"})
	want := []string{"1.2.1", "2.2.1", "3.2.1"}
	if !slices.Equal(got, want) {
		t.Fatalf("sortedLldpKeys = %v, want %v", got, want)
	}
}
