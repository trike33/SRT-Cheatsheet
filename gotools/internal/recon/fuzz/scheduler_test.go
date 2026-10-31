package fuzz

import (
	"testing"
	"time"
)

func TestEffCapStaticWhenNotAdaptive(t *testing.T) {
	hb := &hostBucket{}
	if got := hb.effCap(10, false); got != 10 {
		t.Errorf("got %d, want the static cap unchanged", got)
	}
	if got := hb.effCap(0, false); got != 0 {
		t.Errorf("got %d, want 0 (unlimited)", got)
	}
}

func TestEffCapStartsConservativeThenClimbs(t *testing.T) {
	hb := &hostBucket{}
	if got := hb.effCap(0, true); got != adaptiveStart {
		t.Errorf("got %d, want the conservative start %d before anything is recorded", got, adaptiveStart)
	}
	for i := 0; i < adaptiveStep; i++ {
		hb.adaptRecord(true, 5*time.Millisecond)
	}
	if got := hb.effCap(0, true); got != adaptiveStart+1 {
		t.Errorf("after %d clean fast responses, got %d, want %d", adaptiveStep, got, adaptiveStart+1)
	}
}

func TestEffCapRespectsStaticCeiling(t *testing.T) {
	hb := &hostBucket{concLimit: 50}
	if got := hb.effCap(5, true); got != 5 {
		t.Errorf("got %d, want the tighter static -hc ceiling to win", got)
	}
}

func TestAdaptRecordShrinksOnError(t *testing.T) {
	hb := &hostBucket{concLimit: 10}
	hb.adaptRecord(false, time.Millisecond)
	if hb.concLimit >= 10 {
		t.Errorf("concLimit = %d, want it to shrink on an error/429/503", hb.concLimit)
	}
}

func TestAdaptRecordHoldsOnLatencySpike(t *testing.T) {
	hb := &hostBucket{}
	// Prime a fast baseline.
	for i := 0; i < 5; i++ {
		hb.adaptRecord(true, 10*time.Millisecond)
	}
	before := hb.concLimit
	// A response far slower than the recent average should hold/ease the cap,
	// not let it climb.
	hb.adaptRecord(true, 500*time.Millisecond)
	if hb.concLimit > before {
		t.Errorf("concLimit grew to %d after a latency spike (was %d)", hb.concLimit, before)
	}
	if hb.successRun != 0 {
		t.Error("a latency spike should reset the climb streak")
	}
}

func TestAdaptRecordNeverGoesBelowOne(t *testing.T) {
	hb := &hostBucket{concLimit: 1}
	for i := 0; i < 10; i++ {
		hb.adaptRecord(false, time.Millisecond)
	}
	if hb.concLimit < 1 {
		t.Errorf("concLimit = %d, must never drop below 1", hb.concLimit)
	}
}

func TestAdaptRecordCapsAtMax(t *testing.T) {
	hb := &hostBucket{concLimit: adaptiveMax}
	for i := 0; i < adaptiveStep*2; i++ {
		hb.adaptRecord(true, time.Millisecond)
	}
	if hb.concLimit > adaptiveMax {
		t.Errorf("concLimit = %d, must never exceed adaptiveMax %d", hb.concLimit, adaptiveMax)
	}
}
