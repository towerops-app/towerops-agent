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

	// A tooBig at one repetition cannot shrink further, so the active group
	// splits in half and each side retries alone before any root fails.
	pending := [][]*snmpWalkRootState{states}
	var deadErr error
	var deadNoResponse bool
	for len(pending) > 0 {
		active = pending[0]
		pending = pending[1:]
		if deadErr != nil {
			// The transport already stopped answering: every later request
			// would wait through the same silence, so mark this group the
			// same without asking again.
			for _, st := range active {
				st.err, st.noResponse = deadErr, deadNoResponse
			}
			continue
		}
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
				if noResponse {
					deadErr, deadNoResponse = err, true
				}
				break
			}

			switch packet.Error {
			case gosnmp.NoError:
			case gosnmp.TooBig:
				for _, st := range active {
					st.duration += elapsed
				}
				if repetitions > 1 {
					// Retry the identical request with fewer repetitions. A
					// device cannot answer tooBig forever at one repetition.
					if state != nil {
						repetitions = int(state.noteBulkTooBig(uint32(repetitions)))
					} else {
						repetitions = max(1, repetitions/2)
					}
					continue
				}
				// Already at one repetition: only the root count can still
				// shrink, so split the group before failing anything.
				if len(active) > 1 {
					mid := len(active) / 2
					pending = append([][]*snmpWalkRootState{active[:mid], active[mid:]}, pending...)
				} else {
					active[0].err = fmt.Errorf("device answered %v at max-repetitions 1", gosnmp.TooBig)
				}
				active = nil
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
				// A full response means the device could have filled more: with
				// device state, count it toward stepping the remembered size
				// back up; without, raise the local repetitions directly.
				if state != nil {
					repetitions = int(state.noteBulkFull())
				} else {
					rows := len(packet.Variables) / len(active)
					repetitions = min(64, max(repetitions, rows))
				}
			}

			// One shared request is one elapsed-time observation. Split it by
			// the number of bindings each root received so summed root durations
			// still equal the actual exchange time.
			counts := make([]int, len(active))
			var exact []*snmpWalkRootState
			for i, pdu := range packet.Variables {
				rootIndex := i % len(active)
				counts[rootIndex]++
				st := active[rootIndex]
				// A sentinel ends this root's subtree: later bindings in the same
				// multi-root response belong to no live walk and stay ignored.
				if st.done {
					continue
				}
				done, leaf, pduErr := st.absorb(pdu)
				if pduErr != nil {
					st.err = pduErr
					st.done = true
					continue
				}
				if leaf {
					// The leaf check is deferred until the whole reply is
					// distributed so absent roots share one GET per batch.
					exact = append(exact, st)
					st.done = true
					continue
				}
				if done {
					st.done = true
				}
			}
			if len(exact) > 0 {
				resolveExactRoots(conn, state, exact)
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
			active = activeRoots(active)
		}
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
		if pdu.Name == st.root {
			// The device answered the leaf itself: the value is already
			// stored, so a follow-up GET could only repeat it.
			if pdu.Type != gosnmp.NoSuchInstance {
				snmpStorePDU(st.values, pdu)
			}
			return true, false, nil
		}
		// The first answer escaped the subtree: the root names a leaf. An
		// answer below the root is some other root's chain landing in this
		// slot, not proof of a leaf, so it earns no exact GET.
		return true, first && !snmpOIDLess(pdu.Name, st.root), nil
	}
	if !snmpOIDLess(st.last, pdu.Name) {
		return true, false, fmt.Errorf("device answered a non-increasing OID %s after %s", canonicalOID(pdu.Name), canonicalOID(st.last))
	}
	snmpStorePDU(st.values, pdu)
	st.last = pdu.Name
	return false, false, nil
}

// resolveExactRoots resolves every root flagged for the leaf check with one
// GET per batch instead of one GET per root: a typical poll lists several
// tables a device does not implement, and those absent roots would otherwise
// each cost a full paced round trip. The first batch that gets no response
// ends the rest with the same error, since a silent device would make every
// later request wait out the same timeout.
func resolveExactRoots(conn snmpQuerier, state *snmpDeviceState, pending []*snmpWalkRootState) {
	batchSize := snmpMaxOIDsPerGet
	if state != nil {
		batchSize = max(1, state.getSize())
	}
	var silence error
	for start := 0; start < len(pending); start += batchSize {
		batch := pending[start:min(start+batchSize, len(pending))]
		if silence != nil {
			for _, st := range batch {
				st.err, st.noResponse = silence, true
			}
			continue
		}
		if err := exactRootsGet(conn, batch); isSNMPTimeout(err) {
			silence = err
		}
	}
}

// exactRootsGet issues one GET for a batch of leaf-check roots and stores any
// binding that answers a root exactly. Recoverable statuses split the batch
// like snmpGetInto does; a transport error marks every root in the batch and
// is returned so the caller can stop the remaining batches on a timeout.
func exactRootsGet(conn snmpQuerier, batch []*snmpWalkRootState) error {
	oids := make([]string, len(batch))
	for i, st := range batch {
		oids[i] = st.root
	}
	started := time.Now()
	packet, err := conn.Get(oids)
	elapsed := time.Since(started) / time.Duration(len(batch))
	for _, st := range batch {
		st.duration += elapsed
	}
	if err != nil {
		noResponse := isSNMPTimeout(err)
		for _, st := range batch {
			st.err, st.noResponse = err, noResponse
		}
		return err
	}
	switch packet.Error {
	case gosnmp.NoError:
		byName := make(map[string]*snmpWalkRootState, len(batch))
		for _, st := range batch {
			byName[st.root] = st
		}
		for _, pdu := range packet.Variables {
			if st := byName[pdu.Name]; st != nil {
				snmpStorePDU(st.values, pdu)
			}
		}
	case gosnmp.TooBig, gosnmp.NoSuchName:
		if len(batch) == 1 {
			st := batch[0]
			st.err = fmt.Errorf("device answered %v (error index %d) for %s", packet.Error, packet.ErrorIndex, canonicalOID(st.root))
			return nil
		}
		mid := len(batch) / 2
		if err := exactRootsGet(conn, batch[:mid]); err != nil {
			return err
		}
		return exactRootsGet(conn, batch[mid:])
	default:
		message := fmt.Errorf("device answered %v (error index %d)", packet.Error, packet.ErrorIndex)
		for _, st := range batch {
			st.err = message
		}
	}
	return nil
}

// finishExact performs the single exact GET gosnmp's walk semantics use for a
// leaf root (gosnmp issues #78, #93).
func (st *snmpWalkRootState) finishExact(conn snmpQuerier) {
	_ = exactRootsGet(conn, []*snmpWalkRootState{st})
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
	absent, err := snmpGetInto(conn, dev, state, oids, into)
	if err == nil {
		if state != nil {
			state.noteGetBatchOK()
		}
		return absent, nil
	}
	if ctx.Err() != nil || len(oids) <= 1 || !isSNMPTimeout(err) {
		return absent, err
	}
	observer, ok := conn.(snmpResponseObserver)
	if !ok || !observer.responded() {
		// A3: this was the job's first zero-response request.
		return absent, err
	}
	if state != nil {
		state.noteGetFailure(len(oids))
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
