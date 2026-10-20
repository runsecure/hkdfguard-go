package nativev1

import (
	"bytes"
	"slices"
	"strings"
)

// The Linux loader's decisions, kept free of system calls (they are passed in) so they can be
// checked against simulated filesystems on any platform. The loader (kms_linux.go) loads the
// library from its package's install location and nowhere else. The library receives every
// plaintext DEK, and the tpm2-tss library it loads receives every ECDH shared secret, so loading an
// impostor of either would hand over every key:
//
//  1. Location. The file the libhkdfguard1 package installs: the Debian multiarch directory if it
//     is there, otherwise /usr/lib64 (the RPM packages). Only "nothing is there" moves on to the
//     next location; a path that can't be examined is refused.
//  2. Path integrity. Every directory walked through, every symbolic link followed, and the file
//     itself must be owned by root, and no directory or file may be writable by its group or by
//     others. Symbolic links are followed component by component, each checked where it lies.
//  3. Environment. The library's dependencies are found by name: through LD_LIBRARY_PATH, and after
//     LD_PRELOAD and LD_AUDIT objects that can interpose on any symbol. So every location those
//     name must pass the same path checks, and none may be relative, empty (the working directory)
//     or use $ORIGIN-style substitutions - in both the environment the process started with
//     (/proc/self/environ, what the dynamic linker read) and the current one.
//  4. What was loaded. After dlopen, dladdr must place the library's export in the verified file,
//     and every object in its dependency closure (each file's DT_NEEDED entries) must be bound to a
//     file that passes the path checks.
//
// The library is not content-pinned: a release's authenticity is verified with Sigstore/cosign when
// the package is installed, so path integrity is what the loader enforces.
//
// Out of reach here: the tpm2-tss TCTI module is loaded later, by name (the environment check
// covers it), and Go-level injection (a replaced binary, a debugger) is the host's to prevent.

const (
	linuxFileName       = "libhkdfguard.so.1"
	linuxLib64Directory = "/usr/lib64"

	// The dynamic-linker variables that decide where, or what, it loads.
	envLibraryPath = "LD_LIBRARY_PATH"
	envPreload     = "LD_PRELOAD"
	envAudit       = "LD_AUDIT"

	// linuxMaxSymbolicLinks is the kernel's own limit on symbolic links followed in one lookup.
	linuxMaxSymbolicLinks = 40
)

// linuxCandidatePaths returns where the package may have installed the library for a process of
// goarch, in the order they are tried.
func linuxCandidatePaths(goarch string) ([]string, error) {
	var triplet string
	switch goarch {
	case "amd64":
		triplet = "x86_64-linux-gnu"
	case "arm64":
		triplet = "aarch64-linux-gnu"
	default:
		return nil, unsupported("The HkdfGuard native KMS library is built for amd64 and arm64 Linux only; this process is %s.", goarch)
	}
	return []string{"/usr/lib/" + triplet + "/" + linuxFileName, linuxLib64Directory + "/" + linuxFileName}, nil
}

// linuxChoosePath returns the first candidate that exists. probe is statx's result for a path: 0
// if it exists, else the errno - so "can't look" is never mistaken for "not there".
func linuxChoosePath(candidates []string, probe func(string) int) (string, error) {
	for _, candidate := range candidates {
		switch errno := probe(candidate); errno {
		case 0:
			return candidate, nil
		case errnoENOENT, errnoENOTDIR:
			continue
		default:
			return "", untrusted("Could not tell whether the HkdfGuard native library '%s' exists (statx failed with errno %d); refusing to guess or to fall back to another location.", candidate, errno)
		}
	}

	quoted := make([]string, len(candidates))
	for i, c := range candidates {
		quoted[i] = "'" + c + "'"
	}
	return "", notInstalled("The HkdfGuard native KMS library is not installed. Install the libhkdfguard1 package (hkdfguard-libs on RPM distributions); it is loaded only from %s.", strings.Join(quoted, " or "))
}

// statusFunc is an lstat-style status of a path: found is false when nothing is there (ENOENT,
// ENOTDIR); err reports any other failure, such as EACCES.
type statusFunc func(path string) (status fileStatus, found bool, err error)

// readLinkFunc is a symbolic link's stored target; ok is false if it can't be read.
type readLinkFunc func(path string) (target string, ok bool)

// linuxResolveTrusted resolves path the way the kernel would, checking everything it passes
// through: every directory and the final object must be owned by root and writable by neither
// group nor others, and every symbolic link must be owned by root (its target is then resolved and
// checked in turn). It returns the resolved path, which contains no symbolic links.
//
// When allowMissing is true, a path that runs into a missing component returns found == false
// instead of an error: everything up to it was checked, so only root could create what is missing.
func linuxResolveTrusted(path string, expected fileType, getStatus statusFunc, readLink readLinkFunc, allowMissing bool) (resolved string, found bool, err error) {
	if !strings.HasPrefix(path, "/") {
		return "", false, untrusted("'%s' is not an absolute path; the HkdfGuard native library and its dependencies are only trusted at absolute paths.", path)
	}

	root, rootFound, err := getStatus("/")
	if err != nil {
		return "", false, err
	}
	if !rootFound {
		return "", false, untrusted("'/' could not be examined.")
	}
	if err := linuxRequireRootControlled("/", root); err != nil {
		return "", false, err
	}

	// pending is a stack of path components still to walk; the next is at the end.
	var pending []string
	pending = pushComponents(pending, path)
	resolved = "/"
	resolvedType := fileDirectory
	linksFollowed := 0

	for len(pending) > 0 {
		name := pending[len(pending)-1]
		pending = pending[:len(pending)-1]

		if name == "" || name == "." {
			continue
		}
		if resolvedType != fileDirectory {
			return "", false, untrusted("'%s' runs through '%s', which is not a directory.", path, resolved)
		}
		if name == ".." {
			// resolved never contains a symbolic link, so its parent is its lexical parent.
			resolved = linuxParentOf(resolved)
			continue
		}

		candidate := "/" + name
		if resolved != "/" {
			candidate = resolved + "/" + name
		}
		status, ok, err := getStatus(candidate)
		if err != nil {
			return "", false, err
		}
		if !ok {
			if allowMissing {
				return "", false, nil
			}
			return "", false, untrusted("'%s' does not exist (resolving '%s').", candidate, path)
		}

		if status.typ == fileSymlink {
			if status.uid != 0 {
				return "", false, untrusted("'%s' is a symbolic link owned by uid %d; only links owned by root are followed (resolving '%s').", candidate, status.uid, path)
			}
			linksFollowed++
			if linksFollowed > linuxMaxSymbolicLinks {
				return "", false, untrusted("'%s' follows more than %d symbolic links.", path, linuxMaxSymbolicLinks)
			}

			target, ok := readLink(candidate)
			if !ok {
				return "", false, untrusted("'%s' could not be read as a symbolic link.", candidate)
			}
			if strings.HasPrefix(target, "/") {
				resolved = "/"
			}
			pending = pushComponents(pending, target)
			continue
		}

		if err := linuxRequireRootControlled(candidate, status); err != nil {
			return "", false, err
		}
		resolved = candidate
		resolvedType = status.typ
	}

	if resolvedType != expected {
		return "", false, untrusted("'%s' resolves to '%s', which is a %s, not a %s.", path, resolved, resolvedType, expected)
	}
	return resolved, true, nil
}

func linuxRequireRootControlled(path string, status fileStatus) error {
	if status.uid != 0 {
		return untrusted("'%s' is owned by uid %d; the HkdfGuard native library and its dependencies are only trusted in locations owned by root.", path, status.uid)
	}
	if status.perm&(permGroupWrite|permOtherWrite) != 0 {
		return untrusted("'%s' is writable by its group or by every user; the HkdfGuard native library and its dependencies are only trusted in locations only root can modify.", path)
	}
	return nil
}

// pushComponents pushes path's components so the first one is popped next.
func pushComponents(pending []string, path string) []string {
	components := strings.Split(path, "/")
	for i := len(components) - 1; i >= 0; i-- {
		pending = append(pending, components[i])
	}
	return pending
}

func linuxParentOf(path string) string {
	slash := strings.LastIndexByte(path, '/')
	if slash <= 0 {
		return "/"
	}
	return path[:slash]
}

// linuxReadEnvironment returns every value each dynamic-linker variable has had: in the
// environment the process started with (initialEnvironment, /proc/self/environ's NUL-separated
// block, or nil if it couldn't be read) and in the current one (lookupEnv, as os.LookupEnv).
func linuxReadEnvironment(lookupEnv func(string) (string, bool), initialEnvironment []byte) map[string][]string {
	names := []string{envLibraryPath, envPreload, envAudit}
	values := make(map[string][]string, len(names))
	for _, name := range names {
		values[name] = []string{}
	}

	for _, entry := range bytes.Split(initialEnvironment, []byte{0}) {
		name, value, ok := strings.Cut(string(entry), "=")
		if !ok || name == "" {
			continue
		}
		if list, tracked := values[name]; tracked {
			values[name] = append(list, value)
		}
	}

	for _, name := range names {
		if value, ok := lookupEnv(name); ok && !slices.Contains(values[name], value) {
			values[name] = append(values[name], value)
		}
	}
	return values
}

// linuxVerifyEnvironment requires every location the dynamic-linker variables could make it load
// from to pass the path checks. resolveTrusted is linuxResolveTrusted with missing paths allowed.
func linuxVerifyEnvironment(environment map[string][]string, resolveTrusted func(path string, expected fileType) error) error {
	// An empty LD_LIBRARY_PATH is ignored by the dynamic linker; an empty entry within one is the
	// working directory.
	for _, value := range environment[envLibraryPath] {
		if value == "" {
			continue
		}
		for _, entry := range splitAny(value, ":;") {
			if entry == "" {
				return linuxUntrustedVariable(envLibraryPath, value, "an empty entry, which means the working directory")
			}
			if err := linuxVerifyVariableLocation(envLibraryPath, value, entry, fileDirectory, resolveTrusted); err != nil {
				return err
			}
		}
	}

	// Objects to preload or audit: separated by spaces or colons (LD_PRELOAD), or colons
	// (LD_AUDIT). A bare name is found by the same search as any dependency, which the
	// LD_LIBRARY_PATH check above already covers.
	for _, variable := range []struct{ name, separators string }{{envPreload, " :"}, {envAudit, ":"}} {
		for _, value := range environment[variable.name] {
			for _, entry := range splitAny(value, variable.separators) {
				if entry == "" {
					continue
				}
				if strings.ContainsAny(entry, "/$") {
					if err := linuxVerifyVariableLocation(variable.name, value, entry, fileRegular, resolveTrusted); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

// splitAny splits s at every character in separators, keeping empty fields.
func splitAny(s, separators string) []string {
	var fields []string
	for {
		i := strings.IndexAny(s, separators)
		if i < 0 {
			return append(fields, s)
		}
		fields = append(fields, s[:i])
		s = s[i+1:]
	}
}

func linuxVerifyVariableLocation(variable, value, entry string, expected fileType, resolveTrusted func(string, fileType) error) error {
	if strings.Contains(entry, "$") {
		return linuxUntrustedVariable(variable, value, "'"+entry+"', which uses a dynamic string token ($ORIGIN, $LIB or $PLATFORM) that can't be checked in advance")
	}
	if !strings.HasPrefix(entry, "/") {
		return linuxUntrustedVariable(variable, value, "'"+entry+"', which is relative to the working directory")
	}
	if err := resolveTrusted(entry, expected); err != nil {
		return untrustedCause(err, "%s ('%s') names '%s', which the dynamic linker could load the HkdfGuard native library's dependencies from. Remove it from %s, or make it a location only root can modify", variable, value, entry, variable)
	}
	return nil
}

func linuxUntrustedVariable(variable, value, what string) error {
	return untrusted("%s ('%s') contains %s; the dynamic linker could load the HkdfGuard native library's dependencies from there. Refusing to load it.", variable, value, what)
}

// linuxVerifyLoadedImage requires that the file the dynamic linker reports having loaded (resolved;
// "" if the library has no probeExport or the linker can't say) is the one that was verified.
func linuxVerifyLoadedImage(expectedPath, loadedPath string) error {
	if loadedPath == "" {
		return untrusted("The library loaded for '%s' has no '%s' export, or the dynamic linker cannot say where it came from; it is not the HkdfGuard native library and has been unloaded.", expectedPath, probeExport)
	}
	if loadedPath != expectedPath {
		return untrusted("The dynamic linker bound '%s' to '%s', a different file; it has been unloaded and the HkdfGuard native library was not loaded.", expectedPath, loadedPath)
	}
	return nil
}

// linuxVerifyDependencies walks the library's dependency closure - each file's DT_NEEDED names,
// then theirs - and requires every one to be bound to a trusted file. loadedPathOf returns the
// path of the already-loaded object a name is bound to (false if none is); resolveTrusted resolves
// a path, failing unless it passes the path checks.
func linuxVerifyDependencies(libraryPath string, readNeeded func(string) ([]string, error), loadedPathOf func(string) (string, bool), resolveTrusted func(string) (string, error)) error {
	visited := map[string]bool{libraryPath: true}
	queue := []string{libraryPath}

	for len(queue) > 0 {
		file := queue[0]
		queue = queue[1:]

		needed, err := readNeeded(file)
		if err != nil {
			return err
		}
		for _, name := range needed {
			loaded, ok := loadedPathOf(name)
			if !ok {
				return untrusted("'%s' depends on '%s', but no loaded object answers to that name; cannot tell where it came from.", file, name)
			}

			resolved, err := resolveTrusted(loaded)
			if err != nil {
				return untrustedCause(err, "The HkdfGuard native library's dependency '%s' (needed by '%s') was loaded from '%s', which is not trusted", name, file, loaded)
			}
			if !visited[resolved] {
				visited[resolved] = true
				queue = append(queue, resolved)
			}
		}
	}
	return nil
}
