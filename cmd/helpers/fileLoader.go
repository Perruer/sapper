package helpers

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// Data is the content of one JSON document and where it came from.
type Data struct {
	Path string
	Data []byte
}

// maxZipEntrySize caps one document read from a ZIP archive, so a crafted archive cannot exhaust
// memory. The largest OSV records are a few megabytes.
const maxZipEntrySize = 64 << 20

// LoadDataFromPath reads JSON documents from a file, a directory (recursively) or a ZIP archive
// such as the osv.dev dumps. Files with other extensions are skipped.
func LoadDataFromPath(p string) ([]Data, error) {
	info, err := os.Stat(p)
	if err != nil {
		return nil, fmt.Errorf("error accessing path %s: %w", p, err)
	}

	if info.IsDir() {
		entries, err := os.ReadDir(p)
		if err != nil {
			return nil, fmt.Errorf("failed to read directory %s: %w", p, err)
		}
		result := []Data{}
		var errs []error
		for _, entry := range entries {
			entryPath := filepath.Join(p, entry.Name())
			sub, err := LoadDataFromPath(entryPath)
			if err != nil {
				errs = append(errs, fmt.Errorf("failed to load data from path %s: %w", entryPath, err))
				continue
			}
			result = append(result, sub...)
		}
		if len(errs) > 0 {
			return nil, fmt.Errorf("errors occurred during data ingestion: %v", errs)
		}
		return result, nil
	}

	switch strings.ToLower(filepath.Ext(p)) {
	case ".zip":
		result, err := readZipFile(p)
		if err != nil {
			return nil, fmt.Errorf("failed to process zip file %s: %w", p, err)
		}
		return result, nil
	case ".json":
		data, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("failed to read JSON file %s: %w", p, err)
		}
		return []Data{{Path: p, Data: data}}, nil
	default:
		return []Data{}, nil
	}
}

// readZipFile reads the JSON documents of a ZIP archive in memory. Nothing is extracted to disk,
// so entry names cannot point outside a folder (Zip Slip) and no temporary files are left behind.
func readZipFile(filePath string) ([]Data, error) {
	r, err := zip.OpenReader(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open zip file %s: %w", filePath, err)
	}
	defer r.Close()

	result := []Data{}
	for _, f := range r.File {
		if f.FileInfo().IsDir() || !strings.EqualFold(path.Ext(f.Name), ".json") {
			continue
		}
		if f.UncompressedSize64 > maxZipEntrySize {
			return nil, fmt.Errorf("%s in %s is larger than %d bytes", f.Name, filePath, maxZipEntrySize)
		}
		data, err := readZipEntry(f)
		if err != nil {
			return nil, err
		}
		result = append(result, Data{Path: filePath + "!" + f.Name, Data: data})
	}
	return result, nil
}

func readZipEntry(f *zip.File) ([]byte, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, fmt.Errorf("failed to open %s in zip: %w", f.Name, err)
	}
	defer rc.Close()
	// The header can lie about the size; never read more than the limit.
	data, err := io.ReadAll(io.LimitReader(rc, maxZipEntrySize+1))
	if err != nil {
		return nil, fmt.Errorf("failed to read %s in zip: %w", f.Name, err)
	}
	if len(data) > maxZipEntrySize {
		return nil, fmt.Errorf("%s is larger than %d bytes", f.Name, maxZipEntrySize)
	}
	return data, nil
}
