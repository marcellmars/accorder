package libraryflow

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	WriterPath              = "_WRITER"
	GenerationPath          = "_GENERATION"
	UploadExcludesPath      = ".motw-upload-excludes"
	DefaultMaxDeletes       = 25
	DefaultMaxDeletePercent = 20.0
)

// WriterMarker is the advisory, per-library active-writer seat stored at
// <member-prefix>/_WRITER. SeatID is authority; SeatLabel is explanation.
type WriterMarker struct {
	Version     int        `json:"version"`
	State       string     `json:"state"`
	SeatID      string     `json:"seat_id,omitempty"`
	SeatLabel   string     `json:"seat_label,omitempty"`
	ClaimedAt   *time.Time `json:"claimed_at,omitempty"`
	ReleasedAt  *time.Time `json:"released_at,omitempty"`
	PublishedAt *time.Time `json:"published_at,omitempty"`
}

func ParseWriterMarker(data []byte) (WriterMarker, error) {
	var marker WriterMarker
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&marker); err != nil {
		return WriterMarker{}, fmt.Errorf("invalid _WRITER JSON: %w", err)
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		if err == nil {
			return WriterMarker{}, errors.New("invalid _WRITER JSON: multiple values")
		}
		return WriterMarker{}, fmt.Errorf("invalid _WRITER JSON trailer: %w", err)
	}
	if err := marker.Validate(); err != nil {
		return WriterMarker{}, err
	}
	return marker, nil
}

func (m WriterMarker) Validate() error {
	if m.Version != 1 {
		return fmt.Errorf("unsupported _WRITER version %d", m.Version)
	}
	switch m.State {
	case "claimed":
		if strings.TrimSpace(m.SeatID) == "" {
			return errors.New("invalid _WRITER claimed state: missing seat_id")
		}
		if strings.TrimSpace(m.SeatLabel) == "" {
			return errors.New("invalid _WRITER claimed state: missing seat_label")
		}
		if m.ClaimedAt == nil || m.ClaimedAt.IsZero() {
			return errors.New("invalid _WRITER claimed state: missing claimed_at")
		}
		if m.ReleasedAt != nil {
			return errors.New("invalid _WRITER claimed state: released_at is not allowed")
		}
	case "free":
		if m.ReleasedAt == nil || m.ReleasedAt.IsZero() {
			return errors.New("invalid _WRITER free state: missing released_at")
		}
		if m.SeatID != "" || m.SeatLabel != "" || m.ClaimedAt != nil {
			return errors.New("invalid _WRITER free state: claimed-seat fields are not allowed")
		}
	default:
		return fmt.Errorf("unsupported _WRITER state %q", m.State)
	}
	return nil
}

func (m WriterMarker) Marshal() ([]byte, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(m)
}

func ClaimWriter(seatID, seatLabel string, now time.Time, previous *WriterMarker) WriterMarker {
	marker := WriterMarker{
		Version:   1,
		State:     "claimed",
		SeatID:    seatID,
		SeatLabel: seatLabel,
	}
	now = now.UTC()
	marker.ClaimedAt = &now
	if previous != nil {
		marker.PublishedAt = previous.PublishedAt
	}
	return marker
}

func ReleaseWriter(now time.Time, previous WriterMarker) WriterMarker {
	now = now.UTC()
	return WriterMarker{
		Version:     1,
		State:       "free",
		ReleasedAt:  &now,
		PublishedAt: previous.PublishedAt,
	}
}

// Object is the stable portion of a local or remote inventory entry.
type Object struct {
	Path       string    `json:"path"`
	Size       int64     `json:"size"`
	ModTime    time.Time `json:"mod_time,omitempty"`
	ChangeTime int64     `json:"change_time,omitempty"`
	Hash       string    `json:"hash,omitempty"`
}

func (o Object) Identity() string {
	if o.Hash != "" {
		return fmt.Sprintf("%d:%s", o.Size, o.Hash)
	}
	if !o.ModTime.IsZero() {
		return fmt.Sprintf("%d:%d", o.Size, o.ModTime.UTC().UnixNano())
	}
	return fmt.Sprintf("%d", o.Size)
}

// NewLocalObject captures the portable path/size/mtime identity plus a
// best-effort change timestamp available from FileInfo. Call NewLocalObjectAt
// when the local path is available: Windows requires a file handle to read
// NTFS ChangeTime. ChangeTime is machine-private and never participates in the
// cross-backend source fingerprint; it invalidates a cached content digest
// when bytes are rewritten and mtime is restored.
func NewLocalObject(path string, info os.FileInfo) Object {
	return newLocalObject(path, "", info)
}

// NewLocalObjectAt is NewLocalObject with the filesystem path needed to read
// Windows/NTFS ChangeTime through GetFileInformationByHandleEx.
func NewLocalObjectAt(path, localPath string, info os.FileInfo) Object {
	return newLocalObject(path, localPath, info)
}

func newLocalObject(path, localPath string, info os.FileInfo) Object {
	return Object{
		Path: path, Size: info.Size(), ModTime: info.ModTime().UTC(),
		ChangeTime: fileChangeTimeUnixNano(localPath, info.Sys()),
	}
}

func NormalizePath(path string) (string, error) {
	raw := filepath.ToSlash(strings.TrimSpace(path))
	if strings.HasPrefix(raw, "/") || filepath.IsAbs(path) {
		return "", fmt.Errorf("unsafe object path %q", path)
	}
	path = filepath.ToSlash(filepath.Clean(raw))
	path = strings.TrimPrefix(path, "./")
	if path == "" || path == "." {
		return "", errors.New("empty object path")
	}
	if path == ".." || strings.HasPrefix(path, "../") {
		return "", fmt.Errorf("unsafe object path %q", path)
	}
	return path, nil
}

func IsProtectedPath(path string) bool {
	path = strings.TrimPrefix(filepath.ToSlash(path), "/")
	return path == WriterPath || path == GenerationPath ||
		path == ".accorder" || strings.HasPrefix(path, ".accorder/") ||
		strings.HasSuffix(path, ".manifest.json") || path == "_IDENTITY"
}

// IsDerivedPath reports paths that may be rebuilt without changing the
// librarian's source snapshot.
func IsDerivedPath(path string) bool {
	path = strings.TrimPrefix(filepath.ToSlash(path), "/")
	if strings.HasPrefix(path, "static/") {
		return true
	}
	switch path {
	case "index.html", "BROWSE_LIBRARY.html", UploadExcludesPath:
		return true
	}
	return strings.HasSuffix(path, ".jsonl") || strings.HasSuffix(path, ".jsonl.zst")
}

func IsSourcePath(path string) bool {
	return !IsProtectedPath(path) && !IsDerivedPath(path)
}

func IsPublishManagedPath(path string) bool {
	path = strings.TrimPrefix(filepath.ToSlash(path), "/")
	if IsProtectedPath(path) || path == UploadExcludesPath {
		return false
	}
	return !strings.HasSuffix(path, ".delta.jsonl") && !strings.HasSuffix(path, ".jsonl")
}

func matchesExclude(path string, excludes []string) bool {
	path = strings.TrimPrefix(filepath.ToSlash(path), "/")
	for _, raw := range excludes {
		pattern := strings.TrimPrefix(filepath.ToSlash(strings.TrimSpace(raw)), "/")
		if pattern == "" {
			continue
		}
		if base := strings.TrimSuffix(pattern, "/**"); base != pattern {
			if path == base || strings.HasPrefix(path, base+"/") {
				return true
			}
			continue
		}
		if ok, _ := filepath.Match(pattern, path); ok {
			return true
		}
	}
	return false
}

func FilterInventory(objects []Object, excludes []string, includeDerived bool) ([]Object, error) {
	out := make([]Object, 0, len(objects))
	seen := make(map[string]struct{}, len(objects))
	for _, object := range objects {
		path, err := NormalizePath(object.Path)
		if err != nil {
			return nil, err
		}
		if _, ok := seen[path]; ok {
			return nil, fmt.Errorf("duplicate object path %q", path)
		}
		seen[path] = struct{}{}
		if !IsPublishManagedPath(path) || matchesExclude(path, excludes) {
			continue
		}
		if !includeDerived && !IsSourcePath(path) {
			continue
		}
		object.Path = path
		out = append(out, object)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

// FilterDeletableInventory includes every non-coordination remote object,
// including private leftovers, upload metadata, and stale build intermediates.
// Those paths must stay visible to the planner even though they are never
// candidates for additive upload.
func FilterDeletableInventory(objects []Object) ([]Object, error) {
	out := make([]Object, 0, len(objects))
	seen := make(map[string]struct{}, len(objects))
	for _, object := range objects {
		path, err := NormalizePath(object.Path)
		if err != nil {
			return nil, err
		}
		if _, ok := seen[path]; ok {
			return nil, fmt.Errorf("duplicate object path %q", path)
		}
		seen[path] = struct{}{}
		if IsProtectedPath(path) {
			continue
		}
		object.Path = path
		out = append(out, object)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

func InventoryToken(objects []Object, excludes []string) (string, error) {
	return inventoryToken(objects, excludes, false)
}

// StableInventoryToken binds the remote observation used for race detection to
// each object's best available identity as well as its path and size. It is
// intentionally separate from InventoryToken: the expected target inventory
// must compare across local and remote backends whose hash algorithms differ.
func StableInventoryToken(objects []Object, excludes []string) (string, error) {
	return inventoryToken(objects, excludes, true)
}

func inventoryToken(objects []Object, excludes []string, includeIdentity bool) (string, error) {
	filtered, err := FilterDeletableInventory(objects)
	if err != nil {
		return "", err
	}
	if len(excludes) > 0 {
		withoutExcludes := filtered[:0]
		for _, object := range filtered {
			if !matchesExclude(object.Path, excludes) {
				withoutExcludes = append(withoutExcludes, object)
			}
		}
		filtered = withoutExcludes
	}
	h := sha256.New()
	for _, object := range filtered {
		fmt.Fprintf(h, "%s\x00%d", object.Path, object.Size)
		if includeIdentity {
			fmt.Fprintf(h, "\x00%s", object.Identity())
		}
		fmt.Fprintln(h)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// SourceFingerprint hashes metadata.db by content and the remaining
// publishable source payload by canonical path and size.
func SourceFingerprint(root string, excludes []string) (string, []Object, error) {
	var objects []Object
	metadataHash := ""
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == root {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if matchesExclude(rel, excludes) {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.IsDir() || !IsSourcePath(rel) {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		object := NewLocalObjectAt(rel, path, info)
		objects = append(objects, object)
		if rel == "metadata.db" {
			f, err := os.Open(path)
			if err != nil {
				return err
			}
			h := sha256.New()
			_, copyErr := io.Copy(h, bufio.NewReader(f))
			closeErr := f.Close()
			if copyErr != nil {
				return copyErr
			}
			if closeErr != nil {
				return closeErr
			}
			metadataHash = hex.EncodeToString(h.Sum(nil))
		}
		return nil
	})
	if err != nil {
		return "", nil, fmt.Errorf("source fingerprint %s: %w", root, err)
	}
	return SourceFingerprintFromObjects(objects, metadataHash, excludes)
}

func SourceFingerprintFromObjects(objects []Object, metadataHash string, excludes []string) (string, []Object, error) {
	filtered, err := FilterInventory(objects, excludes, false)
	if err != nil {
		return "", nil, err
	}
	if metadataHash == "" {
		return "", nil, errors.New("source fingerprint: metadata.db content hash is required")
	}
	foundMetadata := false
	h := sha256.New()
	for _, object := range filtered {
		if object.Path == "metadata.db" {
			foundMetadata = true
			fmt.Fprintf(h, "%s\x00%d\x00%s\n", object.Path, object.Size, metadataHash)
			continue
		}
		fmt.Fprintf(h, "%s\x00%d\n", object.Path, object.Size)
	}
	if !foundMetadata {
		return "", nil, errors.New("source fingerprint: metadata.db is missing")
	}
	return hex.EncodeToString(h.Sum(nil)), filtered, nil
}

type PlannedUpload struct {
	Object
	Change bool `json:"change"`
}

type PlannedDelete struct {
	Object
}

type PublishPlan struct {
	Uploads           []PlannedUpload `json:"uploads"`
	Deletes           []PlannedDelete `json:"deletes"`
	DeletableRemote   int             `json:"deletable_remote"`
	UploadBytes       int64           `json:"upload_bytes"`
	LocalInventory    string          `json:"local_inventory"`
	RemoteInventory   string          `json:"remote_inventory"`
	ExpectedInventory string          `json:"expected_inventory"`
}

func BuildPublishPlan(local, remote []Object, excludes []string) (PublishPlan, error) {
	localManaged, err := FilterInventory(local, excludes, true)
	if err != nil {
		return PublishPlan{}, fmt.Errorf("local inventory: %w", err)
	}
	// Local exclusions (notably private book directories) are delete intent,
	// not remote blind spots: a previously published object under one of those
	// paths must appear in the immutable deletion set.
	remoteManaged, err := FilterDeletableInventory(remote)
	if err != nil {
		return PublishPlan{}, fmt.Errorf("remote inventory: %w", err)
	}
	localByPath := make(map[string]Object, len(localManaged))
	remoteByPath := make(map[string]Object, len(remoteManaged))
	for _, object := range localManaged {
		localByPath[object.Path] = object
	}
	for _, object := range remoteManaged {
		remoteByPath[object.Path] = object
	}
	plan := PublishPlan{DeletableRemote: len(remoteManaged)}
	for _, object := range localManaged {
		remoteObject, exists := remoteByPath[object.Path]
		if !exists || !sameObjectForPlan(object, remoteObject) {
			plan.Uploads = append(plan.Uploads, PlannedUpload{Object: object, Change: exists})
			plan.UploadBytes += object.Size
		}
	}
	for _, object := range remoteManaged {
		if _, exists := localByPath[object.Path]; !exists {
			plan.Deletes = append(plan.Deletes, PlannedDelete{Object: object})
		}
	}
	plan.LocalInventory, err = InventoryToken(localManaged, nil)
	if err != nil {
		return PublishPlan{}, err
	}
	plan.RemoteInventory, err = StableInventoryToken(remoteManaged, nil)
	if err != nil {
		return PublishPlan{}, err
	}
	plan.ExpectedInventory = plan.LocalInventory
	return plan, nil
}

func sameObjectForPlan(local, remote Object) bool {
	if local.Size != remote.Size {
		return false
	}
	if local.Hash != "" && remote.Hash != "" {
		return local.Hash == remote.Hash
	}
	if !local.ModTime.IsZero() && !remote.ModTime.IsZero() {
		return local.ModTime.Equal(remote.ModTime)
	}
	// Some backends do not expose a stable hash or modification time. Size is
	// the only common identity in that case; metadata.db still has a mandatory
	// content hash in the final source-fingerprint verification.
	return true
}

func (p PublishPlan) NewUploads() int {
	n := 0
	for _, upload := range p.Uploads {
		if !upload.Change {
			n++
		}
	}
	return n
}

func (p PublishPlan) Changes() int {
	n := 0
	for _, upload := range p.Uploads {
		if upload.Change {
			n++
		}
	}
	return n
}

func (p PublishPlan) DeletePercent() float64 {
	if len(p.Deletes) == 0 || p.DeletableRemote == 0 {
		return 0
	}
	return float64(len(p.Deletes)) * 100 / float64(p.DeletableRemote)
}

func (p PublishPlan) CheckShrink(maxDeletes int, maxPercent float64, force bool) error {
	if maxDeletes < 0 || maxPercent < 0 {
		return errors.New("shrink thresholds cannot be negative")
	}
	if force || len(p.Deletes) == 0 {
		return nil
	}
	countExceeded := len(p.Deletes) > maxDeletes
	percentExceeded := p.DeletePercent() > maxPercent
	if !countExceeded && !percentExceeded {
		return nil
	}
	return fmt.Errorf("publish would delete %d of %d objects (%.1f%%), exceeding limit %d or %.1f%%; review with --dry-run, then pass --force-shrink for this plan",
		len(p.Deletes), p.DeletableRemote, p.DeletePercent(), maxDeletes, maxPercent)
}
