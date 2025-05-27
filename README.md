# Files.nim

 **The most comprehensive cross-platform file operations library for Nim**

> *Originally developed for the [Ryton programming language](https://github.com/CodeLibraty/RytonLang)*

## 🚀 Why RytonFiles?

- **🔥 100+ file operations** in one library
- **🌍 Cross-platform** (Windows/Linux/BSD/macOS)  
- **⚡  High performance** optimized algorithms
- **🛡️ Type-safe** with comprehensive error handling
- **📁 Advanced features**: monitoring, filtering, batch ops, extended attributes

## Features

- 📁 **File & Directory Operations** - Create, copy, move, delete files and directories
- 🔗 **Symbolic & Hard Links** - Full support for link creation and management
- 🔍 **Advanced Search** - Find files by name, size, date, and custom filters
- 📊 **File System Information** - Get disk usage, mount points, and file statistics
- 🔐 **Permissions & Security** - Manage file permissions and secure deletion
- 🎯 **Cross-Platform** - Works on Windows, Linux, and macOS
- 📈 **File Monitoring** - Watch directories for changes (basic implementation)
- 🗜️ **Archive Support** - Basic archive creation and extraction
- 🌐 **Network File Systems** - Mount/unmount NFS, SMB shares

## Installation

Add Files.nim to your project using Nimble:

```bash
nimble install https://github.com/CodeLibraty/rytonfiles
```

Or add to your `.nimble` file:

```nim
requires "rytonfiles >= 1.0.0"
```

## Core Types
from file src/Files.nim:
```nim
type
  FileType* = enum
    ftFile,
    ftDirectory,
    ftSymlink,
    ftHardlink,    
    ftDevice,      
    ftPipe,        
    ftSocket,      
    ftUnknown      

  FilePermission* = enum
    fpRead,        
    fpWrite,       
    fpExecute      

  FilePermissions* = set[FilePermission]

  FileInfo* = object
    path*: string
    name*: string
    size*: int64
    fileType*: FileType
    permissions*: FilePermissions
    createdAt*: DateTime
    modifiedAt*: DateTime
    accessedAt*: DateTime
    owner*: string
    group*: string
    isHidden*: bool

  MountPoint* = object
    device*: string
    mountPath*: string
    fileSystem*: string
    options*: seq[string]
    totalSpace*: int64
    freeSpace*: int64
    usedSpace*: int64

  FilesError* = object of CatchableError
```


## ⚡ Quick Start

```nim
# example
import rytonfiles

let testDir = "test_files"

# Filter
var filter = newFileFilter()
filter.extensions = @[".nim", ".ry"]
filter.minSize = 1024
let files = findFilesWithFilter("/home/rejzi/Picturies", filter)
echo files

# Statistic
let stats = getDirectoryStats("/home/rejzi/Downloads")
echo "Files: ", stats.totalFiles
echo "Size: ", formatFileSize(stats.totalSize)

if not exists(testDir):
  createDirectory(testDir)
  echo fmt"Created directory: {testDir}"

let testFile = joinPath(testDir, "test.txt")
createFile(testFile, "Hello, RytonFiles library!")
echo fmt"Created file: {testFile}"

printFileInfo(testFile)

echo "\nDirectory tree:"
printDirectoryTree(testDir)

# Clean
removeDirectory(testDir, recursive = true)
echo fmt"Cleaned up: {testDir}"
```

## Examples

### File Operations

```nim
# Create and write to file
createFile("example.txt", "Hello, World!")
appendTextFile("example.txt", "\nSecond line")

# Copy and move files
copyFile("example.txt", "backup.txt")
moveFile("backup.txt", "archive/backup.txt")

# Batch operations
let copied = batchCopy(@["file1.txt", "file2.txt"], "destination/")
```

### Directory Management

```nim
# Create nested directories
createDirectory("path/to/nested/dir", recursive = true)

# Get directory statistics
let stats = getDirectoryStats("my_folder")
echo "Total files: ", stats.totalFiles
echo "Total size: ", formatFileSize(stats.totalSize)

# Clean old files
cleanDirectory("temp/", olderThan = initDuration(days = 7))
```

### Advanced Search

```nim
# Create a custom filter
var filter = newFileFilter()
filter.extensions = @[".nim", ".ry"]
filter.minSize = 1024
filter.dateFrom = now() - initDuration(days = 30)

let recentNimFiles = findFilesWithFilter("src/", filter)
```

### File System Information

```nim
# Get mount points (Unix/Linux)
when not defined(windows):
  let mounts = getMountPoints()
  for mount in mounts:
    echo mount.device, " -> ", mount.mountPath

# File system info
let fsInfo = getFileSystemInfo(".")
echo "Free space: ", formatFileSize(fsInfo.freeSpace)
```

### Symbolic Links

```nim
# Create and read symbolic links
createSymlink("target_file.txt", "link_to_file.txt")
let target = readSymlink("link_to_file.txt")
echo "Link points to: ", target
```

## Platform-Specific Features

### Unix/Linux
- Extended file attributes
- File ownership management
- NFS/SMB mounting
- inotify-based file watching

### Windows
- Alternate Data Streams
- Network drive mapping
- NTFS-specific features

### macOS
- All Unix features
- macOS-specific directory locations

## Error Handling

The library uses `FilesError` for file system related errors:

```nim
try:
  removeFile("nonexistent.txt")
except FilesError as e:
  echo "Error: ", e.msg
```

## Performance Notes

- Use `recursive = false` for better performance when you don't need deep directory traversal
- Batch operations are more efficient than individual file operations
- File streams provide better performance for large file operations

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

## 🏢 About CodeLibraty Foundation

RytonFiles is developed by [CodeLibraty Foundation](https://github.com/CodeLibraty), 
the creators of the **RytonLang** programming language.

**🔗 Explore our ecosystem:**
- [RytonLang Compiler](https://github.com/CodeLibraty/RytonLang) - Modern programming language
- [RytonFiles](https://github.com/CodeLibraty/rytonfiles) - This library
- More tools coming soon...

## 📄 License

MIT License - see [LICENSE](LICENSE) file.

---
*Made with _❤️4Nim_ by Rejzi-dich*
