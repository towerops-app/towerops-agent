// Copyright (C) 2026 Graham McIntire
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"
	"github.com/towerops-app/towerops-agent/pb"
)

// snmpWalkRootError carries one root's walk outcome back to the job executor.
// noResponse marks a transport timeout, which is the A3 zero-response signal.
type snmpWalkRootError struct {
	root       string
	err        error
	noResponse bool
	elapsed    time.Duration
}

// snmpWalkRootState is one root's cursor inside a shared GETBULK request. The
// value map is written directly by the walk loop: no intermediate PDU slice,
// no second copy into the result frame (B8).
type snmpWalkRootState struct {
	root       string
	last       string
	values     map[string]string
	started    bool
	done       bool
	duration   time.Duration
	err        error
	noResponse bool
}

func newSnmpWalkRootState(rootOid string) *snmpWalkRootState {
	if rootOid == "" || rootOid == "." {
		// gosnmp's convention: an empty root walks the internet subtree.
		rootOid = ".1.3.6.1"
	}
	root := "." + strings.TrimPrefix(rootOid, ".")
	return &snmpWalkRootState{root: root, last: root, values: make(map[string]string)}
}

// snmpWalkRoots walks every root of one WALK query. SNMPv1 keeps the proven
// sequential GETNEXT loop; v2c/v3 pack all still-active roots into one GETBULK
// per round trip and drop a root as soon as it stops returning rows (B1).
// max-repetitions adapts per device: tooBig halves it, a full response raises
// it for large tables.
func snmpWalkRoots(ctx context.Context, conn snmpQuerier, roots []string, v1 bool, state *snmpDeviceState) ([]snmpResultBucket, []snmpWalkRootError) {
	if len(roots) == 0 {
		return nil, nil
	}
	if v1 {
		return snmpWalkRootsV1(ctx, conn, roots, state)
	}

	states := make([]*snmpWalkRootState, len(roots))
	for i, root := range roots {
		states[i] = newSnmpWalkRootState(root)
	}
	repetitions := snmpMaxRepetitions
	if state != nil {
		repetitions = int(state.bulkRepetitions())
	}
	active := states
	queryStarted := time.Now()

	for len(active) > 0 {
		if err := ctx.Err(); err != nil {
			for _, st := range active {
				st.err = err
			}
			break
		}
		request := make([]string, len(active))
		for i, st := range active {
			request[i] = st.last
		}
		started := time.Now()
		packet, err := conn.GetBulk(request, 0, uint32(repetitions))
		elapsed := time.Since(started)
		if err != nil {
			noResponse := isSNMPTimeout(err)
			for _, st := range active {
				st.duration += elapsed
				st.err, st.noResponse = err, noResponse
			}
			break
		}

		switch packet.Error {
		case gosnmp.NoError:
		case gosnmp.TooBig:
			for _, st := range active {
				st.duration += elapsed
			}
			// Retry the identical request with fewer repetitions. A device
			// cannot answer tooBig forever at one repetition.
			if state != nil {
				repetitions = int(state.noteTooBig())
			} else if repetitions > 1 {
				repetitions /= 2
			}
			if repetitions <= 1 {
				for _, st := range active {
					st.duration += elapsed
					st.err = fmt.Errorf("device answered %v at max-repetitions 1", gosnmp.TooBig)
				}
				break
			}
			continue
		default:
			message := fmt.Errorf("device answered %v (error index %d)", packet.Error, packet.ErrorIndex)
			for _, st := range active {
				st.duration += elapsed
				st.err = message
			}
		}
		if packet.Error != gosnmp.NoError {
			break
		}
		if len(packet.Variables) == 0 {
			message := fmt.Errorf("device answered with an empty varbind list")
			for _, st := range active {
				st.duration += elapsed
				st.err = message
			}
			break
		}
		if len(packet.Variables) >= len(active)*repetitions {
			// A full response means the device could have filled more: learn
			// the delivered row count and ask for that many next round, so
			// large tables cost fewer packets without overshooting tooBig.
			rows := len(packet.Variables) / len(active)
			if state != nil {
				state.noteBulkRows(rows)
			} else {
				repetitions = min(64, max(repetitions, rows))
			}
		}

		// One shared request is one elapsed-time observation. Split it by
		// the number of bindings each root received so summed root durations
		// still equal the actual exchange time.
		counts := make([]int, len(active))
		for i, pdu := range packet.Variables {
			rootIndex := i % len(active)
			counts[rootIndex]++
			st := active[rootIndex]
			// A sentinel ends this root's subtree: later bindings in the same
			// multi-root response belong to no live walk and stay ignored.
			if st.done {
				continue
			}
			done, exact, pduErr := st.absorb(pdu)
			if pduErr != nil {
				st.err = pduErr
				st.done = true
				continue
			}
			if exact {
				st.finishExact(conn)
				continue
			}
			if done {
				st.done = true
			}
		}
		if total := len(packet.Variables); total > 0 {
			distributed := time.Duration(0)
			first := -1
			for i, count := range counts {
				if count == 0 {
					continue
				}
				if first < 0 {
					first = i
				}
				piece := elapsed * time.Duration(count) / time.Duration(total)
				active[i].duration += piece
				distributed += piece
			}
			if first >= 0 {
				active[first].duration += elapsed - distributed
			}
		}
		// A short response ends the roots that received no binding: there is
		// nothing left for them to request, and waiting again cannot help.
		for _, st := range active {
			if !st.done && !st.started {
				st.done = true
			}
		}
		active = activeRoots(states)
	}

	// A shared GETBULK is one exchange observed by every active root. Scale
	// each root's observed wait so their sum stays the query's wall time;
	// diagnostic elapsed reports the actual shared exchange duration.
	queryElapsed := time.Since(queryStarted)
	var observed time.Duration
	for _, st := range states {
		observed += st.duration
	}
	if observed > 0 {
		scale := float64(queryElapsed) / float64(observed)
		for _, st := range states {
			st.duration = time.Duration(float64(st.duration) * scale)
		}
	}

	buckets := make([]snmpResultBucket, 0, len(states))
	errs := make([]snmpWalkRootError, 0, len(states))
	for _, st := range states {
		buckets = append(buckets, snmpResultBucket{
			label: canonicalOID(st.root), values: st.values, completed: st.err == nil, duration: st.duration,
		})
		errs = append(errs, snmpWalkRootError{root: canonicalOID(st.root), err: st.err, noResponse: st.noResponse, elapsed: queryElapsed})
	}
	return buckets, errs
}

func activeRoots(states []*snmpWalkRootState) []*snmpWalkRootState {
	active := make([]*snmpWalkRootState, 0, len(states))
	for _, st := range states {
		if !st.done {
			active = append(active, st)
		}
	}
	return active
}

// absorb records one GETBULK binding for this root. It returns done when the
// root's subtree is exhausted and exact when the first answer reveals a leaf
// root that needs one exact GET.
func (st *snmpWalkRootState) absorb(pdu gosnmp.SnmpPDU) (done, exact bool, err error) {
	first := !st.started
	st.started = true
	switch pdu.Type {
	case gosnmp.EndOfMibView, gosnmp.NoSuchObject, gosnmp.NoSuchInstance:
		return true, first, nil
	}
	if !strings.HasPrefix(pdu.Name, st.root+".") {
		if pdu.Name == st.root && pdu.Type != gosnmp.NoSuchInstance {
			snmpStorePDU(st.values, pdu)
		}
		// The first answer escaped the subtree: the root names a leaf.
		return true, first, nil
	}
	if !snmpOIDLess(st.last, pdu.Name) {
		return true, false, fmt.Errorf("device answered a non-increasing OID %s after %s", canonicalOID(pdu.Name), canonicalOID(st.last))
	}
	snmpStorePDU(st.values, pdu)
	st.last = pdu.Name
	return false, false, nil
}

// finishExact performs the single exact GET gosnmp's walk semantics use for a
// leaf root (gosnmp issues #78, #93).
func (st *snmpWalkRootState) finishExact(conn snmpQuerier) {
	started := time.Now()
	packet, err := conn.Get([]string{st.root})
	st.duration += time.Since(started)
	if err != nil {
		st.err, st.noResponse = err, isSNMPTimeout(err)
		st.done = true
		return
	}
	if packet.Error != gosnmp.NoError {
		st.err = fmt.Errorf("device answered %v (error index %d) for %s", packet.Error, packet.ErrorIndex, canonicalOID(st.root))
		st.done = true
		return
	}
	for _, pdu := range packet.Variables {
		if pdu.Name == st.root {
			snmpStorePDU(st.values, pdu)
		}
	}
	st.done = true
}

// snmpWalkRootsV1 keeps GETNEXT roots sequential: v1 cannot pack several
// roots into one PDU.
func snmpWalkRootsV1(ctx context.Context, conn snmpQuerier, roots []string, state *snmpDeviceState) ([]snmpResultBucket, []snmpWalkRootError) {
	buckets := make([]snmpResultBucket, 0, len(roots))
	errs := make([]snmpWalkRootError, 0, len(roots))
	for _, root := range roots {
		st := newSnmpWalkRootState(root)
		started := time.Now()
		results, err := snmpWalkAll(ctx, conn, root, true)
		st.duration = time.Since(started)
		for _, pdu := range results {
			snmpStorePDU(st.values, pdu)
		}
		st.err = err
		st.noResponse = err != nil && isSNMPTimeout(err)
		buckets = append(buckets, snmpResultBucket{
			label: canonicalOID(st.root), values: st.values, completed: st.err == nil, duration: st.duration,
		})
		errs = append(errs, snmpWalkRootError{root: canonicalOID(st.root), err: st.err, noResponse: st.noResponse, elapsed: st.duration})
		if err != nil {
			break
		}
	}
	return buckets, errs
}

// snmpStorePDU writes one usable walk binding straight into the bucket map.
// Unusable bindings (Null, NoSuchObject, NoSuchInstance, EndOfMibView) never
// become map traffic.
func snmpStorePDU(into map[string]string, pdu gosnmp.SnmpPDU) {
	if snmpValueUsable(pdu) {
		into[canonicalOID(pdu.Name)] = snmpValueToString(pdu)
	}
}

// snmpResponseObserver exposes the job-scoped "did anything answer yet" flag.
type snmpResponseObserver interface {
	responded() bool
}

func (q *snmpJobQuerier) responded() bool { return q.observation.responded }

// snmpGetWithRecovery adds B5 around snmpGetInto's error-status recovery:
// after a timeout from a device that answered earlier in the same job, the
// batch is retried in halves. The largest successful half size is remembered
// per device, so later ticks start at the size the link actually delivers.
func snmpGetWithRecovery(ctx context.Context, conn snmpQuerier, dev *pb.SnmpDevice, state *snmpDeviceState, oids []string, into map[string]string) (int, error) {
	absent, err := snmpGetInto(conn, dev, oids, into)
	if err == nil || ctx.Err() != nil || len(oids) <= 1 || !isSNMPTimeout(err) {
		return absent, err
	}
	observer, ok := conn.(snmpResponseObserver)
	if !ok || !observer.responded() {
		// A3: this was the job's first zero-response request.
		return absent, err
	}

	mid := len(oids) / 2
	loAbsent, loErr := snmpGetWithRecovery(ctx, conn, dev, state, oids[:mid], into)
	if loErr != nil {
		// The first zero-response half ends recovery: the remaining half
		// would wait through the same silence (A3).
		return absent + loAbsent, loErr
	}
	hiAbsent, hiErr := snmpGetWithRecovery(ctx, conn, dev, state, oids[mid:], into)
	if loErr == nil && hiErr == nil && state != nil {
		state.rememberGETSize(mid)
	}
	return absent + loAbsent + hiAbsent, hiErr
}
