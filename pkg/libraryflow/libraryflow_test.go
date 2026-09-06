package libraryflow

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWriterMarkerFailClosed(t *testing.T) {
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	claimed := ClaimWriter("seat-1", "Alice laptop", now, nil)
	raw, err := claimed.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseWriterMarker(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.SeatID != "seat-1" || got.State != "claimed" {
		t.Fatalf("marker = %+v", got)
	}

	for _, raw := range []string{
		`{`,
		`{"version":2,"state":"free","released_at":"2026-08-19T12:00:00Z"}`,
		`{"version":1,"state":"future"}`,
		`{"version":1,"state":"claimed","seat_label":"Alice","claimed_at":"2026-08-19T12:00:00Z"}`,
		`{"version":1,"state":"free"}`,
		`{"version":1,"state":"free","released_at":"2026-08-19T12:00:00Z","extra":true}`,
	} {
		if _, err := ParseWriterMarker([]byte(raw)); err == nil {
			t.Errorf("ParseWriterMarker(%s) succeeded", raw)
		}
	}
}

func TestReleaseWriterPreservesPublishedAt(t *testing.T) {
	claimedAt := time.Date(2026, 8, 19, 10, 0, 0, 0, time.UTC)
	publishedAt := claimedAt.Add(time.Hour)
	marker := ClaimWriter("seat", "Laptop", claimedAt, nil)
	marker.PublishedAt = &publishedAt
	released := ReleaseWriter(claimedAt.Add(2*time.Hour), marker)
	if released.State != "free" || released.PublishedAt == nil || !released.PublishedAt.Equal(publishedAt) {
		t.Fatalf("released = %+v", released)
	}
	if _, err := released.Marshal(); err != nil {
		t.Fatal(err)
	}
}

func TestSourceFingerprintMetadataContentAndPayloadSizes(t *testing.T) {
	root := t.TempDir()
	write := func(rel, body string) {
		t.Helper()
		path := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("metadata.db", "aaaa")
	write("Author/Book (1)/book.epub", "12345")
	write("Private/Book (2)/private.epub", "hidden")
	write("static/library_index.zst", "derived")

	fp1, objects, err := SourceFingerprint(root, []string{"/Private/Book (2)/**"})
	if err != nil {
		t.Fatal(err)
	}
	if len(objects) != 2 {
		t.Fatalf("objects = %+v", objects)
	}
	write("metadata.db", "bbbb") // same size, different Calibre metadata
	fp2, _, err := SourceFingerprint(root, []string{"/Private/Book (2)/**"})
	if err != nil {
		t.Fatal(err)
	}
	if fp1 == fp2 {
		t.Fatal("same-size metadata edit did not change source fingerprint")
	}
	write("static/library_index.zst", "different derived bytes")
	fp3, _, err := SourceFingerprint(root, []string{"/Private/Book (2)/**"})
	if err != nil {
		t.Fatal(err)
	}
	if fp2 != fp3 {
		t.Fatal("derived output changed the source fingerprint")
	}
}

func TestPublishPlanCanonicalAndProtected(t *testing.T) {
	oldTime := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	newTime := oldTime.Add(time.Minute)
	local := []Object{
		{Path: "metadata.db", Size: 10, ModTime: newTime},
		{Path: "Author/New (2)/new.epub", Size: 20},
	}
	remote := []Object{
		{Path: "_WRITER", Size: 100},
		{Path: "_GENERATION", Size: 24},
		{Path: "static/library_index.manifest.json", Size: 50},
		{Path: "static/library_index.jsonl", Size: 60},
		{Path: ".motw-upload-excludes", Size: 70},
		{Path: "metadata.db", Size: 10, ModTime: oldTime},
		{Path: "Author/Old (1)/old.epub", Size: 30},
	}
	plan, err := BuildPublishPlan(local, remote, nil)
	if err != nil {
		t.Fatal(err)
	}
	if plan.NewUploads() != 1 || plan.Changes() != 1 || len(plan.Deletes) != 3 {
		t.Fatalf("plan = %+v", plan)
	}
	wantDeletes := []string{".motw-upload-excludes", "Author/Old (1)/old.epub", "static/library_index.jsonl"}
	for i, want := range wantDeletes {
		if got := plan.Deletes[i].Path; got != want {
			t.Fatalf("delete[%d] = %q, want %q", i, got, want)
		}
	}
	for _, deleted := range plan.Deletes {
		if IsProtectedPath(deleted.Path) {
			t.Fatalf("protected delete planned: %s", deleted.Path)
		}
	}
}

func TestNormalizePathRejectsAbsoluteAndTraversal(t *testing.T) {
	for _, path := range []string{"/absolute/file", "../escape", "a/../../escape"} {
		if _, err := NormalizePath(path); err == nil {
			t.Errorf("NormalizePath(%q) succeeded", path)
		}
	}
	if got, err := NormalizePath("Author/Book/./file.epub"); err != nil || got != "Author/Book/file.epub" {
		t.Fatalf("normalized path = %q, %v", got, err)
	}
}

func TestStableInventoryTokenDetectsSameSizeRemoteChange(t *testing.T) {
	before := []Object{{Path: "Author/Book (1)/book.epub", Size: 10, ModTime: time.Unix(10, 0)}}
	after := []Object{{Path: "Author/Book (1)/book.epub", Size: 10, ModTime: time.Unix(20, 0)}}
	plainBefore, err := InventoryToken(before, nil)
	if err != nil {
		t.Fatal(err)
	}
	plainAfter, err := InventoryToken(after, nil)
	if err != nil {
		t.Fatal(err)
	}
	if plainBefore != plainAfter {
		t.Fatal("cross-backend target token should use path and size only")
	}
	stableBefore, err := StableInventoryToken(before, nil)
	if err != nil {
		t.Fatal(err)
	}
	stableAfter, err := StableInventoryToken(after, nil)
	if err != nil {
		t.Fatal(err)
	}
	if stableBefore == stableAfter {
		t.Fatal("stable remote token missed same-size identity change")
	}
}

func TestShrinkThresholdBoundariesAndZero(t *testing.T) {
	makePlan := func(deletes, denominator int) PublishPlan {
		p := PublishPlan{DeletableRemote: denominator}
		for i := 0; i < deletes; i++ {
			p.Deletes = append(p.Deletes, PlannedDelete{Object: Object{Path: strings.Repeat("x", i+1)}})
		}
		return p
	}
	if err := makePlan(25, 125).CheckShrink(25, 20, false); err != nil {
		t.Fatalf("equality should be allowed: %v", err)
	}
	if err := makePlan(26, 130).CheckShrink(25, 20, false); err == nil {
		t.Fatal("just-over count should be refused")
	}
	if err := makePlan(1, 10).CheckShrink(0, 100, false); err == nil {
		t.Fatal("zero count allowance must refuse every deletion")
	}
	if err := makePlan(1, 10).CheckShrink(100, 0, false); err == nil {
		t.Fatal("zero percentage allowance must refuse every deletion")
	}
	if err := makePlan(100, 100).CheckShrink(0, 0, true); err != nil {
		t.Fatalf("explicit force should acknowledge the printed plan: %v", err)
	}
	if err := makePlan(0, 0).CheckShrink(-1, 20, false); err == nil {
		t.Fatal("negative count must be invalid")
	}
}
