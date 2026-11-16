// Copyright (C) 2026 Graham McIntire
// SPDX-License-Identifier: GPL-3.0-or-later

//go:build !unix

package loadtest

// RaiseFileLimit is only implemented where getrlimit(2) exists. Other
// platforms rely on the process limit being high enough and report the
// underlying bind failure otherwise.
func RaiseFileLimit(want uint64) (bool, error) {
	return false, nil
}
