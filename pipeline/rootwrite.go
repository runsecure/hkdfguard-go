package pipeline

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
)

// openFolderRoot creates folder if it doesn't exist and opens it as an os.Root, so every file
// written through it stays inside it. The folder path itself is the caller's: a link along it is
// followed, as it is for any path the deployment names.
func openFolderRoot(folder string) (*os.Root, error) {
	if err := os.MkdirAll(folder, folderMode); err != nil {
		return nil, err
	}
	return os.OpenRoot(folder)
}

// writeInRoot writes data as the file name in root, atomically: to a new temporary file beside it,
// flushed to disk, then renamed over name.
//
// Going through root, neither file can be reached by a path leading outside root's folder, whatever
// symbolic links, junctions or mount points have been planted in it; and the rename replaces the
// entry at name - a planted link included - rather than writing through it to what it points at. A
// process that stops part-way leaves the previous file whole, plus at most a temporary file, whose
// name starts with '.' so no secret file name can be it.
//
// The file is new, so it keeps none of a replaced file's owner or ACL: it is given the replaced
// regular file's permission bits, or fileMode less the umask, and inherits the folder's ACL where
// the platform has them.
func writeInRoot(root *os.Root, name string, data []byte) (err error) {
	mode := os.FileMode(fileMode)
	if existing, statErr := root.Lstat(name); statErr == nil && existing.Mode().IsRegular() {
		mode = existing.Mode().Perm()
	} else if statErr != nil && !errors.Is(statErr, fs.ErrNotExist) {
		return statErr
	}

	temporary, err := temporaryName(name)
	if err != nil {
		return err
	}
	file, err := root.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = file.Close()
			_ = root.Remove(temporary)
		}
	}()

	if _, err = file.Write(data); err != nil {
		return err
	}
	// A replaced file's permissions are kept exactly, whatever the umask took from them at creation.
	if mode != fileMode {
		if err = file.Chmod(mode); err != nil {
			return err
		}
	}
	if err = file.Sync(); err != nil {
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	return root.Rename(temporary, name)
}

// temporaryName is a name, beside name, that no other writer and no secret's file has: '.', name,
// and 16 random hex digits.
func temporaryName(name string) (string, error) {
	random := make([]byte, 8)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	return "." + name + "." + hex.EncodeToString(random) + ".tmp", nil
}
