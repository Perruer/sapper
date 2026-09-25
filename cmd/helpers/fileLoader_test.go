package helpers

import (
	"archive/zip"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeZip(t *testing.T, files map[string]string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "data.zip")
	f, err := os.Create(p)
	require.NoError(t, err)
	w := zip.NewWriter(f)
	for name, content := range files {
		entry, err := w.Create(name)
		require.NoError(t, err)
		_, err = entry.Write([]byte(content))
		require.NoError(t, err)
	}
	require.NoError(t, w.Close())
	require.NoError(t, f.Close())
	return p
}

func TestLoadDataFromZipReadsJSONInMemory(t *testing.T) {
	p := writeZip(t, map[string]string{
		"GO-2024-0001.json":      `{"id":"GO-2024-0001"}`,
		"nested/GO-2024-02.json": `{"id":"GO-2024-0002"}`,
		"../outside.json":        `{"id":"escape"}`,
		"README.txt":             "not json",
	})
	before, _ := filepath.Glob(filepath.Join(os.TempDir(), "unzipped*"))

	data, err := LoadDataFromPath(p)
	require.NoError(t, err)
	assert.Len(t, data, 3, "every JSON entry is read, whatever its name, and nothing is written to disk")

	after, _ := filepath.Glob(filepath.Join(os.TempDir(), "unzipped*"))
	assert.Equal(t, len(before), len(after), "no temporary folder is left behind")
}

func TestLoadDataFromDirectory(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "a.json"), []byte(`{}`), 0o600))
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "sub"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "sub", "b.JSON"), []byte(`{}`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "notes.md"), []byte(`#`), 0o600))

	data, err := LoadDataFromPath(dir)
	require.NoError(t, err)
	assert.Len(t, data, 2)
}
