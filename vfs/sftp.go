package vfs

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/pkg/sftp"

	"golang.org/x/crypto/ssh"

	"github.com/eikenb/pipeat"
	"github.com/rs/xid"

	"github.com/drakkan/sftpgo/logger"
	"github.com/drakkan/sftpgo/utils"
)

const (
	// osFsName is the name for the local Fs implementation
	sftpFsName = "sftp"
)

// SftpFs is a Fs implementation that uses functions provided by the os package.
type SftpFs struct {
	name           string
	connectionID   string
	rootDir        string
	virtualFolders []VirtualFolder
	client         *sftp.Client
}

// NewOsFs returns an OsFs object that allows to interact with local Os filesystem
func NewSftpFs(connectionID, rootDir string, virtualFolders []VirtualFolder) Fs {
	fmt.Println("Activating sftp!")
	user := ""
	pass := ""
	remote := ""
	port := ":22"
	hostKey := getHostKey(remote)
	config := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.Password(pass),
		},
		// HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		HostKeyCallback: ssh.FixedHostKey(hostKey),
	}
	conn, err := ssh.Dial("tcp", remote+port, config)
	if err != nil {
		log.Fatal(err)
	}
	client, err := sftp.NewClient(conn)
	if err != nil {
		log.Fatal(err)
	}
	return SftpFs{
		name:           sftpFsName,
		connectionID:   connectionID,
		rootDir:        rootDir,
		virtualFolders: virtualFolders,
		client:         client,
	}
}

// Name returns the name for the Fs implementation
func (fs SftpFs) Name() string {
	return fs.name
}

// ConnectionID returns the SSH connection ID associated to this Fs implementation
func (fs SftpFs) ConnectionID() string {
	return fs.connectionID
}

// Stat returns a FileInfo describing the named file
func (fs SftpFs) Stat(name string) (os.FileInfo, error) {
	return fs.client.Stat(name)
}

// Lstat returns a FileInfo describing the named file
func (fs SftpFs) Lstat(name string) (os.FileInfo, error) {
	return fs.client.Lstat(name)
}

// Open opens the named file for reading
func (fs SftpFs) Open(name string) (TargetFile, *pipeat.PipeReaderAt, func(), error) {
	file, err := fs.client.Open(name)
	if err != nil {
		return nil, nil, nil, err
	}
	sftpFile := SftpFile{file}
	return &sftpFile, nil, nil, err
}

// Create creates or opens the named file for writing
func (fs SftpFs) Create(name string, flag int) (TargetFile, *PipeWriter, func(), error) {
	var err error
	var f *sftp.File
	if flag == 0 {
		f, err = fs.client.Create(name)
	} else {
		f, err = fs.client.OpenFile(name, flag)
	}

	return &SftpFile{File: f}, nil, nil, err
}

// Rename renames (moves) source to target
func (fs SftpFs) Rename(source, target string) error {
	return fs.client.Rename(source, target)
}

// Remove removes the named file or (empty) directory.
func (fs SftpFs) Remove(name string, isDir bool) error {
	if isDir {
		return fs.client.RemoveDirectory(name)
	}
	return fs.client.Remove(name)
}

// Mkdir creates a new directory with the specified name and default permissions
func (fs SftpFs) Mkdir(name string) error {
	return fs.client.Mkdir(name)
}

// Symlink creates source as a symbolic link to target.
func (fs SftpFs) Symlink(source, target string) error {
	return fs.client.Symlink(source, target)
}

// Chown changes the numeric uid and gid of the named file.
func (fs SftpFs) Chown(name string, uid int, gid int) error {
	return fs.client.Chown(name, uid, gid)
}

// Chmod changes the mode of the named file to mode
func (fs SftpFs) Chmod(name string, mode os.FileMode) error {
	return fs.client.Chmod(name, mode)
}

// Chtimes changes the access and modification times of the named file
func (fs SftpFs) Chtimes(name string, atime, mtime time.Time) error {
	return fs.Chtimes(name, atime, mtime)
}

// ReadDir reads the directory named by dirname and returns
// a list of directory entries.
func (fs SftpFs) ReadDir(dirname string) ([]os.FileInfo, error) {
	return fs.client.ReadDir(dirname)
}

// IsUploadResumeSupported returns true if upload resume is supported
func (SftpFs) IsUploadResumeSupported() bool {
	return true
}

// IsAtomicUploadSupported returns true if atomic upload is supported
func (SftpFs) IsAtomicUploadSupported() bool {
	return true
}

// IsNotExist returns a boolean indicating whether the error is known to
// report that a file or directory does not exist
func (SftpFs) IsNotExist(err error) bool {
	return os.IsNotExist(err)
}

// IsPermission returns a boolean indicating whether the error is known to
// report that permission is denied.
func (SftpFs) IsPermission(err error) bool {
	return os.IsPermission(err)
}

// CheckRootPath creates the root directory if it does not exists
func (fs SftpFs) CheckRootPath(username string, uid int, gid int) bool {
	var err error
	if _, err = fs.Stat(fs.rootDir); fs.IsNotExist(err) {
		err = os.MkdirAll(fs.rootDir, 0777)
		fsLog(fs, logger.LevelDebug, "root directory %#v for user %#v does not exist, try to create, mkdir error: %v",
			fs.rootDir, username, err)
		if err == nil {
			SetPathPermissions(fs, fs.rootDir, uid, gid)
		}
	}
	// create any missing dirs to the defined virtual dirs
	for _, v := range fs.virtualFolders {
		p := filepath.Clean(filepath.Join(fs.rootDir, v.VirtualPath))
		err = fs.createMissingDirs(p, uid, gid)
		if err != nil {
			return false
		}
	}
	return (err == nil)
}

// ScanRootDirContents returns the number of files contained in a directory and
// their size
func (fs SftpFs) ScanRootDirContents() (int, int64, error) {
	numFiles, size, err := fs.getDirSize(fs.rootDir)
	for _, v := range fs.virtualFolders {
		if v.ExcludeFromQuota {
			continue
		}
		num, s, err := fs.getDirSize(v.MappedPath)
		if err != nil {
			if fs.IsNotExist(err) {
				fsLog(fs, logger.LevelWarn, "unable to scan contents for non-existent mapped path: %#v", v.MappedPath)
				continue
			}
			return numFiles, size, err
		}
		numFiles += num
		size += s
	}
	return numFiles, size, err
}

// GetAtomicUploadPath returns the path to use for an atomic upload
func (SftpFs) GetAtomicUploadPath(name string) string {
	dir := filepath.Dir(name)
	guid := xid.New().String()
	return filepath.Join(dir, ".sftpgo-upload."+guid+"."+filepath.Base(name))
}

// GetRelativePath returns the path for a file relative to the user's home dir.
// This is the path as seen by SFTP users
func (fs SftpFs) GetRelativePath(name string) string {
	basePath := fs.rootDir
	virtualPath := "/"
	for _, v := range fs.virtualFolders {
		if strings.HasPrefix(name, v.MappedPath+string(os.PathSeparator)) ||
			filepath.Clean(name) == v.MappedPath {
			basePath = v.MappedPath
			virtualPath = v.VirtualPath
		}
	}
	rel, err := filepath.Rel(basePath, filepath.Clean(name))
	if err != nil {
		return ""
	}
	if rel == "." || strings.HasPrefix(rel, "..") {
		rel = ""
	}
	return path.Join(virtualPath, filepath.ToSlash(rel))
}

// Join joins any number of path elements into a single path
func (SftpFs) Join(elem ...string) string {
	return filepath.Join(elem...)
}

// ResolvePath returns the matching filesystem path for the specified sftp path
func (fs SftpFs) ResolvePath(sftpPath string) (string, error) {
	if !filepath.IsAbs(fs.rootDir) {
		return "", fmt.Errorf("Invalid root path: %v", fs.rootDir)
	}
	basePath, r := fs.GetFsPaths(sftpPath)
	p, err := filepath.EvalSymlinks(r)
	if err != nil && !os.IsNotExist(err) {
		return "", err
	} else if os.IsNotExist(err) {
		// The requested path doesn't exist, so at this point we need to iterate up the
		// path chain until we hit a directory that _does_ exist and can be validated.
		_, err = fs.findFirstExistingDir(r, basePath)
		if err != nil {
			fsLog(fs, logger.LevelWarn, "error resolving non-existent path: %#v", err)
		}
		return r, err
	}

	err = fs.isSubDir(p, basePath)
	if err != nil {
		fsLog(fs, logger.LevelWarn, "Invalid path resolution, dir: %#v outside user home: %#v err: %v", p, fs.rootDir, err)
	}
	return r, err
}

// GetFsPaths returns the base path and filesystem path for the given sftpPath.
// base path is the root dir or matching the virtual folder dir for the sftpPath.
// file path is the filesystem path matching the sftpPath
func (fs *SftpFs) GetFsPaths(sftpPath string) (string, string) {
	basePath := fs.rootDir
	virtualPath, mappedPath := fs.getMappedFolderForPath(sftpPath)
	if len(mappedPath) > 0 {
		basePath = mappedPath
		sftpPath = strings.TrimPrefix(utils.CleanSFTPPath(sftpPath), virtualPath)
	}
	r := filepath.Clean(filepath.Join(basePath, sftpPath))
	return basePath, r
}

// returns the path for the mapped folders or an empty string
func (fs *SftpFs) getMappedFolderForPath(p string) (virtualPath, mappedPath string) {
	if len(fs.virtualFolders) == 0 {
		return
	}
	dirsForPath := utils.GetDirsForSFTPPath(p)
	// dirsForPath contains all the dirs for a given path in reverse order
	// for example if the path is: /1/2/3/4 it contains:
	// [ "/1/2/3/4", "/1/2/3", "/1/2", "/1", "/" ]
	// so the first match is the one we are interested to
	for _, val := range dirsForPath {
		for _, v := range fs.virtualFolders {
			if val == v.VirtualPath {
				return v.VirtualPath, v.MappedPath
			}
		}
	}
	return
}

func (fs *SftpFs) findNonexistentDirs(path, rootPath string) ([]string, error) {
	results := []string{}
	cleanPath := filepath.Clean(path)
	parent := filepath.Dir(cleanPath)
	_, err := os.Stat(parent)

	for os.IsNotExist(err) {
		results = append(results, parent)
		parent = filepath.Dir(parent)
		_, err = os.Stat(parent)
	}
	if err != nil {
		return results, err
	}
	p, err := filepath.EvalSymlinks(parent)
	if err != nil {
		return results, err
	}
	err = fs.isSubDir(p, rootPath)
	if err != nil {
		fsLog(fs, logger.LevelWarn, "error finding non existing dir: %v", err)
	}
	return results, err
}

func (fs *SftpFs) findFirstExistingDir(path, rootPath string) (string, error) {
	results, err := fs.findNonexistentDirs(path, rootPath)
	if err != nil {
		fsLog(fs, logger.LevelWarn, "unable to find non existent dirs: %v", err)
		return "", err
	}
	var parent string
	if len(results) > 0 {
		lastMissingDir := results[len(results)-1]
		parent = filepath.Dir(lastMissingDir)
	} else {
		parent = rootPath
	}
	p, err := filepath.EvalSymlinks(parent)
	if err != nil {
		return "", err
	}
	fileInfo, err := os.Stat(p)
	if err != nil {
		return "", err
	}
	if !fileInfo.IsDir() {
		return "", fmt.Errorf("resolved path is not a dir: %#v", p)
	}
	err = fs.isSubDir(p, rootPath)
	return p, err
}

func (fs *SftpFs) isSubDir(sub, rootPath string) error {
	// rootPath must exist and it is already a validated absolute path
	parent, err := filepath.EvalSymlinks(rootPath)
	if err != nil {
		fsLog(fs, logger.LevelWarn, "invalid root path %#v: %v", rootPath, err)
		return err
	}
	if !strings.HasPrefix(sub, parent) {
		err = fmt.Errorf("path %#v is not inside: %#v", sub, parent)
		fsLog(fs, logger.LevelWarn, "error: %v ", err)
		return err
	}
	return nil
}

func (fs *SftpFs) createMissingDirs(filePath string, uid, gid int) error {
	dirsToCreate, err := fs.findNonexistentDirs(filePath, fs.rootDir)
	if err != nil {
		return err
	}
	last := len(dirsToCreate) - 1
	for i := range dirsToCreate {
		d := dirsToCreate[last-i]
		if err := os.Mkdir(d, 0777); err != nil {
			fsLog(fs, logger.LevelError, "error creating missing dir: %#v", d)
			return err
		}
		SetPathPermissions(fs, d, uid, gid)
	}
	return nil
}

func (fs *SftpFs) getDirSize(dirname string) (int, int64, error) {
	numFiles := 0
	size := int64(0)
	isDir, err := IsDirectory(fs, dirname)
	if err == nil && isDir {
		err = filepath.Walk(dirname, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info != nil && info.Mode().IsRegular() {
				size += info.Size()
				numFiles++
			}
			return err
		})
	}
	return numFiles, size, err
}

func getHostKey(host string) ssh.PublicKey {
	// parse OpenSSH known_hosts file
	// ssh or use ssh-keyscan to get initial key
	file, err := os.Open(filepath.Join(os.Getenv("HOME"), ".ssh", "known_hosts"))
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var hostKey ssh.PublicKey
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), " ")
		if len(fields) != 3 {
			continue
		}
		if strings.Contains(fields[0], host) {
			var err error
			hostKey, _, _, _, err = ssh.ParseAuthorizedKey(scanner.Bytes())
			if err != nil {
				log.Fatalf("error parsing %q: %v", fields[2], err)
			}
			break
		}
	}

	if hostKey == nil {
		log.Fatalf("no hostkey found for %s", host)
	}

	return hostKey
}

type SftpFile struct {
	*sftp.File
}

func (s *SftpFile) ReadAt(p []byte, offset int64) (int, error) {
	s.Seek(offset, 0)
	return s.Read(p)
}

func (s *SftpFile) WriteAt(p []byte, offset int64) (int, error) {
	s.Seek(offset, 0)
	return s.Write(p)
}
