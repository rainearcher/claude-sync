package sync

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	gosync "sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tawanorg/claude-sync/internal/config"
	"github.com/tawanorg/claude-sync/internal/crypto"
	"github.com/tawanorg/claude-sync/internal/storage"
)

// TestFullWorkflowWithLocalState tests the sync workflow with real crypto
// but without actual R2 connection
func TestFullWorkflowWithLocalState(t *testing.T) {
	// Set up temporary directories
	tmpDir := t.TempDir()
	claudeDir := filepath.Join(tmpDir, ".claude")
	configDir := filepath.Join(tmpDir, ".claude-sync")

	if err := os.MkdirAll(claudeDir, 0755); err != nil {
		t.Fatalf("Failed to create claude dir: %v", err)
	}
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatalf("Failed to create config dir: %v", err)
	}

	// Generate encryption key using passphrase
	keyPath := filepath.Join(configDir, "age-key.txt")
	passphrase := "test-integration-passphrase-secure"

	err := crypto.GenerateKeyFromPassphrase(keyPath, passphrase)
	if err != nil {
		t.Fatalf("Failed to generate key from passphrase: %v", err)
	}

	// Create encryptor
	encryptor, err := crypto.NewEncryptor(keyPath)
	if err != nil {
		t.Fatalf("Failed to create encryptor: %v", err)
	}

	// Create test files in claude directory
	testFiles := map[string]string{
		"CLAUDE.md":     "# My Claude Settings\n\nThis is a test.",
		"settings.json": `{"theme": "dark", "autoSave": true}`,
	}

	for name, content := range testFiles {
		path := filepath.Join(claudeDir, name)
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			t.Fatalf("Failed to create test file %s: %v", name, err)
		}
	}

	// Create agents subdirectory with files
	agentsDir := filepath.Join(claudeDir, "agents")
	if err := os.MkdirAll(agentsDir, 0755); err != nil {
		t.Fatalf("Failed to create agents dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(agentsDir, "agent1.json"), []byte(`{"name": "Agent 1"}`), 0644); err != nil {
		t.Fatalf("Failed to create agent file: %v", err)
	}

	// Initialize state
	state := NewState()

	// Detect changes (should be all adds)
	changes, err := state.DetectChanges(claudeDir, []string{"CLAUDE.md", "settings.json", "agents"})
	if err != nil {
		t.Fatalf("DetectChanges failed: %v", err)
	}

	if len(changes) != 3 {
		t.Errorf("Expected 3 new files, got %d", len(changes))
	}

	// Simulate push: encrypt each file and update state
	encryptedFiles := make(map[string][]byte)
	for _, change := range changes {
		fullPath := filepath.Join(claudeDir, change.Path)
		data, err := os.ReadFile(fullPath)
		if err != nil {
			t.Fatalf("Failed to read file %s: %v", change.Path, err)
		}

		encrypted, err := encryptor.Encrypt(data)
		if err != nil {
			t.Fatalf("Failed to encrypt file %s: %v", change.Path, err)
		}

		encryptedFiles[change.Path] = encrypted

		// Update state
		info, _ := os.Stat(fullPath)
		state.UpdateFile(change.Path, info, change.LocalHash)
		state.MarkUploaded(change.Path)
	}

	t.Logf("Encrypted %d files", len(encryptedFiles))

	// Verify no more changes after state update
	changes, err = state.DetectChanges(claudeDir, []string{"CLAUDE.md", "settings.json", "agents"})
	if err != nil {
		t.Fatalf("DetectChanges failed: %v", err)
	}

	if len(changes) != 0 {
		t.Errorf("Expected 0 changes after state update, got %d", len(changes))
	}

	// Simulate pull: decrypt files and verify content
	for path, encrypted := range encryptedFiles {
		decrypted, err := encryptor.Decrypt(encrypted)
		if err != nil {
			t.Fatalf("Failed to decrypt file %s: %v", path, err)
		}

		// Read original file and compare
		fullPath := filepath.Join(claudeDir, path)
		original, err := os.ReadFile(fullPath)
		if err != nil {
			t.Fatalf("Failed to read original file %s: %v", path, err)
		}

		if string(decrypted) != string(original) {
			t.Errorf("Decrypted content doesn't match original for %s", path)
		}
	}

	t.Log("Full workflow with encryption completed successfully")
}

// TestCrossDeviceSyncWithPassphrase verifies that the same passphrase
// produces the same key on different "devices" (simulated with separate directories)
func TestCrossDeviceSyncWithPassphrase(t *testing.T) {
	tmpDir := t.TempDir()
	passphrase := "shared-passphrase-for-sync-test"

	// Device 1 setup
	device1Dir := filepath.Join(tmpDir, "device1")
	device1KeyPath := filepath.Join(device1Dir, "age-key.txt")
	if err := os.MkdirAll(device1Dir, 0700); err != nil {
		t.Fatalf("Failed to create device1 dir: %v", err)
	}

	err := crypto.GenerateKeyFromPassphrase(device1KeyPath, passphrase)
	if err != nil {
		t.Fatalf("Device1: Failed to generate key: %v", err)
	}

	enc1, err := crypto.NewEncryptor(device1KeyPath)
	if err != nil {
		t.Fatalf("Device1: Failed to create encryptor: %v", err)
	}

	// Device 2 setup
	device2Dir := filepath.Join(tmpDir, "device2")
	device2KeyPath := filepath.Join(device2Dir, "age-key.txt")
	if err := os.MkdirAll(device2Dir, 0700); err != nil {
		t.Fatalf("Failed to create device2 dir: %v", err)
	}

	err = crypto.GenerateKeyFromPassphrase(device2KeyPath, passphrase)
	if err != nil {
		t.Fatalf("Device2: Failed to generate key: %v", err)
	}

	enc2, err := crypto.NewEncryptor(device2KeyPath)
	if err != nil {
		t.Fatalf("Device2: Failed to create encryptor: %v", err)
	}

	// Verify both devices have the same public key
	if enc1.PublicKey() != enc2.PublicKey() {
		t.Errorf("Different public keys for same passphrase:\nDevice1: %s\nDevice2: %s",
			enc1.PublicKey(), enc2.PublicKey())
	}

	// Test cross-device encryption/decryption
	testData := []byte("Secret data that should be accessible on both devices")

	// Encrypt on device 1
	encrypted, err := enc1.Encrypt(testData)
	if err != nil {
		t.Fatalf("Device1: Failed to encrypt: %v", err)
	}

	// Decrypt on device 2
	decrypted, err := enc2.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Device2: Failed to decrypt data encrypted on device1: %v", err)
	}

	if string(decrypted) != string(testData) {
		t.Errorf("Cross-device decryption failed:\nExpected: %s\nGot: %s", testData, decrypted)
	}

	t.Log("Cross-device sync with passphrase verified successfully")
}

// TestSyncStateDetectsAllChangeTypes tests add, modify, delete detection
func TestSyncStateDetectsAllChangeTypes(t *testing.T) {
	tmpDir := t.TempDir()
	claudeDir := filepath.Join(tmpDir, ".claude")
	if err := os.MkdirAll(claudeDir, 0755); err != nil {
		t.Fatalf("Failed to create claude dir: %v", err)
	}

	state := NewState()
	syncPaths := []string{"file1.txt", "file2.txt", "file3.txt"}

	// Create initial files
	for _, name := range syncPaths {
		path := filepath.Join(claudeDir, name)
		if err := os.WriteFile(path, []byte("initial content for "+name), 0644); err != nil {
			t.Fatalf("Failed to create file %s: %v", name, err)
		}
	}

	// Initial detection - all adds
	changes, _ := state.DetectChanges(claudeDir, syncPaths)
	addCount := 0
	for _, c := range changes {
		if c.Action == "add" {
			addCount++
		}
	}
	if addCount != 3 {
		t.Errorf("Expected 3 add changes, got %d", addCount)
	}

	// Update state to simulate sync
	for _, c := range changes {
		info, _ := os.Stat(filepath.Join(claudeDir, c.Path))
		state.UpdateFile(c.Path, info, c.LocalHash)
	}

	// Modify file1
	if err := os.WriteFile(filepath.Join(claudeDir, "file1.txt"), []byte("modified content"), 0644); err != nil {
		t.Fatalf("Failed to modify file1: %v", err)
	}

	// Delete file2
	if err := os.Remove(filepath.Join(claudeDir, "file2.txt")); err != nil {
		t.Fatalf("Failed to delete file2: %v", err)
	}

	// file3 unchanged

	// Detect changes
	changes, _ = state.DetectChanges(claudeDir, syncPaths)

	var hasModify, hasDelete bool
	for _, c := range changes {
		switch c.Action {
		case "modify":
			if c.Path == "file1.txt" {
				hasModify = true
			}
		case "delete":
			if c.Path == "file2.txt" {
				hasDelete = true
			}
		}
	}

	if !hasModify {
		t.Error("Expected modify change for file1.txt")
	}
	if !hasDelete {
		t.Error("Expected delete change for file2.txt")
	}
	if len(changes) != 2 {
		t.Errorf("Expected 2 changes (modify + delete), got %d", len(changes))
	}
}

// TestConfigPaths verifies config path functions
func TestConfigPaths(t *testing.T) {
	// These should return non-empty paths
	if config.ConfigDirPath() == "" {
		t.Error("ConfigDirPath should not be empty")
	}
	if config.ConfigFilePath() == "" {
		t.Error("ConfigFilePath should not be empty")
	}
	if config.StateFilePath() == "" {
		t.Error("StateFilePath should not be empty")
	}
	if config.AgeKeyFilePath() == "" {
		t.Error("AgeKeyFilePath should not be empty")
	}
	if config.ClaudeDir() == "" {
		t.Error("ClaudeDir should not be empty")
	}
}

// TestSyncPathsConfig verifies sync paths are properly configured
func TestSyncPathsConfig(t *testing.T) {
	// Verify expected paths are in SyncPaths
	expectedPaths := []string{"CLAUDE.md", "settings.json", "agents", "skills", "plugins", "commands", "hooks", "sessions", "homunculus"}

	for _, expected := range expectedPaths {
		found := false
		for _, path := range config.SyncPaths {
			if path == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected '%s' in SyncPaths", expected)
		}
	}
}

// mockStorage implements storage.Storage for testing
type mockStorage struct {
	mu          gosync.Mutex
	data        map[string][]byte
	latency     time.Duration
	failKeys    map[string]error
	uploadCount atomic.Int32
	deleteCount atomic.Int32
}

func newMockStorage(latency time.Duration) *mockStorage {
	return &mockStorage{
		data:     make(map[string][]byte),
		latency:  latency,
		failKeys: make(map[string]error),
	}
}

func (m *mockStorage) Upload(ctx context.Context, key string, data []byte) error {
	if m.latency > 0 {
		time.Sleep(m.latency)
	}
	m.uploadCount.Add(1)
	if err, ok := m.failKeys[key]; ok {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data[key] = append([]byte(nil), data...)
	return nil
}

func (m *mockStorage) Download(ctx context.Context, key string) ([]byte, error) {
	if m.latency > 0 {
		time.Sleep(m.latency)
	}
	if err, ok := m.failKeys[key]; ok {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	d, ok := m.data[key]
	if !ok {
		return nil, fmt.Errorf("key not found: %s", key)
	}
	return append([]byte(nil), d...), nil
}

func (m *mockStorage) Delete(ctx context.Context, key string) error {
	if m.latency > 0 {
		time.Sleep(m.latency)
	}
	m.deleteCount.Add(1)
	if err, ok := m.failKeys[key]; ok {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.data, key)
	return nil
}

func (m *mockStorage) DeleteBatch(ctx context.Context, keys []string) error {
	for _, key := range keys {
		if err := m.Delete(ctx, key); err != nil {
			return err
		}
	}
	return nil
}

func (m *mockStorage) List(ctx context.Context, prefix string) ([]storage.ObjectInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var objects []storage.ObjectInfo
	for key, data := range m.data {
		objects = append(objects, storage.ObjectInfo{
			Key:          key,
			Size:         int64(len(data)),
			LastModified: time.Now(),
		})
	}
	return objects, nil
}

func (m *mockStorage) Head(ctx context.Context, key string) (*storage.ObjectInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, ok := m.data[key]
	if !ok {
		return nil, fmt.Errorf("key not found: %s", key)
	}
	return &storage.ObjectInfo{Key: key, Size: int64(len(d)), LastModified: time.Now()}, nil
}

func (m *mockStorage) BucketExists(ctx context.Context) (bool, error) {
	return true, nil
}

// helper to create a Syncer with mock storage for testing
func newTestSyncer(t *testing.T, store storage.Storage, claudeDir string) *Syncer {
	t.Helper()

	// Generate encryption key
	keyDir := t.TempDir()
	keyPath := filepath.Join(keyDir, "age-key.txt")
	if err := crypto.GenerateKeyFromPassphrase(keyPath, "test-passphrase"); err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	enc, err := crypto.NewEncryptor(keyPath)
	if err != nil {
		t.Fatalf("Failed to create encryptor: %v", err)
	}

	stateDir := t.TempDir()
	state, err := LoadStateFromDir(stateDir)
	if err != nil {
		t.Fatalf("Failed to load state: %v", err)
	}

	return NewSyncerWithStorage(store, enc, state, claudeDir, true)
}

func TestPushParallel(t *testing.T) {
	claudeDir := t.TempDir()

	// Create 20 test files
	fileCount := 20
	for i := 0; i < fileCount; i++ {
		name := fmt.Sprintf("file%d.txt", i)
		path := filepath.Join(claudeDir, name)
		if err := os.WriteFile(path, []byte(fmt.Sprintf("content %d", i)), 0644); err != nil {
			t.Fatalf("Failed to create file: %v", err)
		}
	}

	store := newMockStorage(50 * time.Millisecond)
	syncer := newTestSyncer(t, store, claudeDir)

	// Build sync paths for the test files
	syncPaths := make([]string, fileCount)
	for i := 0; i < fileCount; i++ {
		syncPaths[i] = fmt.Sprintf("file%d.txt", i)
	}

	start := time.Now()
	result, err := syncer.PushPaths(context.Background(), syncPaths)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("Push failed: %v", err)
	}

	if len(result.Uploaded) != fileCount {
		t.Errorf("Expected %d uploaded, got %d", fileCount, len(result.Uploaded))
	}

	// Sequential at 50ms each would be ~1000ms; parallel should be well under 500ms
	if elapsed > 500*time.Millisecond {
		t.Errorf("Push took %v, expected < 500ms (parallel should be ~10x faster)", elapsed)
	}

	t.Logf("Push of %d files took %v", fileCount, elapsed)
}

func TestPushPartialFailure(t *testing.T) {
	claudeDir := t.TempDir()

	fileCount := 20
	syncPaths := make([]string, fileCount)
	for i := 0; i < fileCount; i++ {
		name := fmt.Sprintf("file%d.txt", i)
		syncPaths[i] = name
		path := filepath.Join(claudeDir, name)
		if err := os.WriteFile(path, []byte(fmt.Sprintf("content %d", i)), 0644); err != nil {
			t.Fatalf("Failed to create file: %v", err)
		}
	}

	store := newMockStorage(0)
	// Fail on 3 specific keys (upload adds .age suffix)
	store.failKeys["file3.txt.age"] = fmt.Errorf("upload failed: simulated")
	store.failKeys["file7.txt.age"] = fmt.Errorf("upload failed: simulated")
	store.failKeys["file15.txt.age"] = fmt.Errorf("upload failed: simulated")

	syncer := newTestSyncer(t, store, claudeDir)

	result, err := syncer.PushPaths(context.Background(), syncPaths)
	if err != nil {
		t.Fatalf("Push should not return top-level error: %v", err)
	}

	if len(result.Uploaded) != 17 {
		t.Errorf("Expected 17 uploaded, got %d", len(result.Uploaded))
	}
	if len(result.Errors) != 3 {
		t.Errorf("Expected 3 errors, got %d", len(result.Errors))
	}

	// Verify state was only updated for successful files
	state := syncer.GetState()
	for i := 0; i < fileCount; i++ {
		name := fmt.Sprintf("file%d.txt", i)
		f := state.GetFile(name)
		if i == 3 || i == 7 || i == 15 {
			if f != nil {
				t.Errorf("Failed file %s should NOT be in state", name)
			}
		} else {
			if f == nil {
				t.Errorf("Successful file %s should be in state", name)
			}
		}
	}
}

func TestPullParallel(t *testing.T) {
	claudeDir := t.TempDir()

	// Generate encryption key for the test syncer
	keyDir := t.TempDir()
	keyPath := filepath.Join(keyDir, "age-key.txt")
	if err := crypto.GenerateKeyFromPassphrase(keyPath, "test-passphrase"); err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	enc, err := crypto.NewEncryptor(keyPath)
	if err != nil {
		t.Fatalf("Failed to create encryptor: %v", err)
	}

	// Pre-populate mock storage with 20 encrypted files
	store := newMockStorage(50 * time.Millisecond)
	fileCount := 20
	originalContent := make(map[string]string)
	for i := 0; i < fileCount; i++ {
		name := fmt.Sprintf("file%d.txt", i)
		content := fmt.Sprintf("content %d", i)
		originalContent[name] = content

		encrypted, err := enc.Encrypt([]byte(content))
		if err != nil {
			t.Fatalf("Failed to encrypt: %v", err)
		}
		store.mu.Lock()
		store.data[name+".age"] = encrypted
		store.mu.Unlock()
	}

	stateDir := t.TempDir()
	state, err := LoadStateFromDir(stateDir)
	if err != nil {
		t.Fatalf("Failed to load state: %v", err)
	}

	syncer := NewSyncerWithStorage(store, enc, state, claudeDir, true)

	start := time.Now()
	result, err := syncer.Pull(context.Background())
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("Pull failed: %v", err)
	}

	if len(result.Downloaded) != fileCount {
		t.Errorf("Expected %d downloaded, got %d", fileCount, len(result.Downloaded))
	}

	// Verify files were written to disk with correct content
	for name, expectedContent := range originalContent {
		data, err := os.ReadFile(filepath.Join(claudeDir, name))
		if err != nil {
			t.Errorf("Failed to read downloaded file %s: %v", name, err)
			continue
		}
		if string(data) != expectedContent {
			t.Errorf("File %s: expected %q, got %q", name, expectedContent, string(data))
		}
	}

	// Sequential at 50ms each would be ~1000ms; parallel should be well under 500ms
	if elapsed > 500*time.Millisecond {
		t.Errorf("Pull took %v, expected < 500ms (parallel should be ~10x faster)", elapsed)
	}

	t.Logf("Pull of %d files took %v", fileCount, elapsed)
}

func TestPushProgressEvents(t *testing.T) {
	claudeDir := t.TempDir()

	fileCount := 5
	syncPaths := make([]string, fileCount)
	for i := 0; i < fileCount; i++ {
		name := fmt.Sprintf("file%d.txt", i)
		syncPaths[i] = name
		path := filepath.Join(claudeDir, name)
		if err := os.WriteFile(path, []byte(fmt.Sprintf("content %d", i)), 0644); err != nil {
			t.Fatalf("Failed to create file: %v", err)
		}
	}

	store := newMockStorage(0)
	syncer := newTestSyncer(t, store, claudeDir)

	var mu gosync.Mutex
	var events []ProgressEvent
	syncer.SetProgressFunc(func(event ProgressEvent) {
		mu.Lock()
		events = append(events, event)
		mu.Unlock()
	})

	result, err := syncer.PushPaths(context.Background(), syncPaths)
	if err != nil {
		t.Fatalf("Push failed: %v", err)
	}

	if len(result.Uploaded) != fileCount {
		t.Errorf("Expected %d uploaded, got %d", fileCount, len(result.Uploaded))
	}

	// Verify progress events
	mu.Lock()
	defer mu.Unlock()

	// Every file should get an upload progress event
	uploadEvents := 0
	currentValues := make(map[int]bool)
	for _, e := range events {
		if e.Action == "upload" && !e.Complete && e.Error == nil {
			uploadEvents++
			currentValues[e.Current] = true
		}
	}

	if uploadEvents != fileCount {
		t.Errorf("Expected %d upload events, got %d", fileCount, uploadEvents)
	}

	// Current values should cover 1..fileCount (order may vary)
	for i := 1; i <= fileCount; i++ {
		if !currentValues[i] {
			t.Errorf("Missing progress event with Current=%d", i)
		}
	}

	// Verify completion event
	hasComplete := false
	for _, e := range events {
		if e.Action == "upload" && e.Complete {
			hasComplete = true
			break
		}
	}
	if !hasComplete {
		t.Error("Missing completion event")
	}
}
