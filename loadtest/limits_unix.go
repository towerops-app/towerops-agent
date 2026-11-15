// Copyright (C) 2026 Graham McIntire
// SPDX-License-Identifier: GPL-3.0-or-later

//go:build unix

package loadtest

import "syscall"

// RaiseFileLimit grows RLIMIT_NOFILE to at least want descriptors. Each
// simulated SNMP device owns one UDP socket, so the 3,000-device scenario
// fails on the common 1,024/2,560 soft limits before the first poll.
// The hard limit is never lowered and an unchanged soft limit is not an
// error: the caller still surfaces any real listen failure with its reason.
func RaiseFileLimit(want uint64) (bool, error) {
	var limit syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &limit); err != nil {
		return false, err
	}
	if limit.Cur >= want {
		return false, nil
	}
	changed := false
	if limit.Max >= want {
		limit.Cur = want
		changed = true
	} else if limit.Cur < limit.Max {
		limit.Cur = limit.Max
		changed = true
	}
	if !changed {
		return false, nil
	}
	if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &limit); err != nil {
		return false, err
	}
	return true, nil
}
