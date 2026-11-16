package osv

import (
	"archive/zip"
	"io"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

const entrySize = 256 << 10

// writeArchive writes an uncompressed zip of random entries to disk, so its size on the wire matches size.
func writeArchive(t *testing.T, size int64) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "all.zip")
	out, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	writer := zip.NewWriter(out)
	random := rand.NewChaCha8([32]byte{})
	for i := int64(0); i < size/entrySize; i++ {
		entry, err := writer.CreateHeader(&zip.FileHeader{Name: filepath.Join("e", string(rune('a'+i%26)), "x.json"), Method: zip.Store})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.CopyN(entry, random, entrySize); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

// peakHeap opens an archive of the given size from a server, reads every entry, and returns the highest live heap seen.
func peakHeap(t *testing.T, size int64) uint64 {
	t.Helper()
	path := writeArchive(t, size)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, path)
	}))
	defer server.Close()

	var peak uint64
	sample := func() {
		var stats runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&stats)
		peak = max(peak, stats.HeapAlloc)
	}

	sample()
	archive, closeArchive, err := openArchive(server.URL + "/all.zip")
	if err != nil {
		t.Fatal(err)
	}
	defer closeArchive()
	sample()
	for i, file := range archive.File {
		data, err := readZipFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if len(data) != entrySize {
			t.Fatalf("entry %d has %d bytes, want %d", i, len(data), entrySize)
		}
		if i%16 == 0 {
			sample()
		}
	}
	return peak
}

func TestArchiveMemoryStaysFlatAsZipGrows(t *testing.T) {
	small := peakHeap(t, 8<<20)
	large := peakHeap(t, 96<<20)

	// Reading the 96 MB archive into memory would add about 88 MB over the small one.
	if growth := int64(large) - int64(small); growth > 8<<20 {
		t.Errorf("peak heap grew by %d MB from an 8 MB to a 96 MB archive (small %d MB, large %d MB)",
			growth>>20, small>>20, large>>20)
	}
}

func TestArchiveLeavesNoTemporaryFile(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	path := writeArchive(t, entrySize)
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/truncated.zip" {
			_, _ = w.Write(content[:len(content)/2])
			return
		}
		_, _ = w.Write(content)
	}))
	defer server.Close()

	_, closeArchive, err := openArchive(server.URL + "/all.zip")
	if err != nil {
		t.Fatal(err)
	}
	closeArchive()
	if _, _, err := openArchive(server.URL + "/truncated.zip"); err == nil {
		t.Fatal("a truncated archive should not open")
	}

	if left, _ := filepath.Glob(filepath.Join(tmp, "osv-*")); len(left) != 0 {
		t.Errorf("temporary files left behind: %v", left)
	}
}

func TestRemoveStaleArchives(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	stale := filepath.Join(tmp, "osv-12345.zip")
	other := filepath.Join(tmp, "keep.zip")
	for _, path := range []string{stale, other} {
		if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	removeStaleArchives()

	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Errorf("stale archive %s was not removed", stale)
	}
	if _, err := os.Stat(other); err != nil {
		t.Errorf("unrelated file was removed: %v", err)
	}
}
