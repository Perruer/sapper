package utils

import (
	"os"
	"path/filepath"
	"runtime"
)

// DataDir returns the folder where Sapper keeps its database: $SAPPER_DATA_DIR if set, otherwise
// the platform's per-user data folder ($XDG_DATA_HOME or ~/.local/share on Linux,
// ~/Library/Application Support on macOS, %LOCALAPPDATA% on Windows), with "sapper" appended.
func DataDir() (string, error) {
	if dir := os.Getenv("SAPPER_DATA_DIR"); dir != "" {
		return dir, nil
	}
	if dir := os.Getenv("XDG_DATA_HOME"); dir != "" {
		return filepath.Join(dir, "sapper"), nil
	}
	switch runtime.GOOS {
	case "windows":
		if dir := os.Getenv("LOCALAPPDATA"); dir != "" {
			return filepath.Join(dir, "sapper"), nil
		}
	case "darwin":
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(home, "Library", "Application Support", "sapper"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".local", "share", "sapper"), nil
}

// DefaultDatabasePath returns DataDir()/sapper.db and creates the folder.
func DefaultDatabasePath() (string, error) {
	dir, err := DataDir()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return filepath.Join(dir, "sapper.db"), nil
}
