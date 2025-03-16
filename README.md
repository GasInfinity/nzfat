# ⚡ nzfat (WIP)
A very generic and configurable FAT12/16/32 implementation library with VFAT support written in zig.
Almost all the features are configurable, from long filename support (and the max number of characters it supports) to the maximum supported FAT type (12/16/32).

[![asciicast](https://asciinema.org/a/Zf1LmR1KpfLKj7KxOFWCuUIPE.svg)](https://asciinema.org/a/Zf1LmR1KpfLKj7KxOFWCuUIPE)

  
## ❓ Usage
The library is not mature enough for production usage.
  
Almost everything revolves around the type `nzfat.FatFileSystem` and the function `nzfat.format.make()`.
Please see [a basic example](examples/basic.zig) or [messy testing code that uses all its features](src/testing_main.zig)

## 📝 TODO

### Small TODO's
- [x] Searching for 1 free entry in a directory (a.k.a: Short filename only)
- [x] Searching for a free cluster linearly
- [x] Deletion of files and directories
- [x] Short filename alternatives for functions when using a VFAT `FatFilesystem`
- [x] Searching for N free clusters for file and directory creation
- [x] Allocate new directory entries if no entries found and not in root (FAT12/16 only)
- [x] Allocate clusters for files
- [x] Creation of files and directories with short names
- [x] API to modify dates and times and attributes in entries
- [x] API for reading and writing file contents
- [x] Searching for N free entries in a directory and creation of directory entries with LFN entries if needed.
- [x] Finish cross-section long filename directory creation
- [x] Support Windows NT extra reserved short filename case flags
- [x] Create fat formatted media
- [ ] Finish FAT32 formatting
- [ ] Proper FAT unmounting
- [ ] API for renaming files without copying
- [ ] API for moving files without copying
- [ ] Utility check and 'fix' fat filesystem
- [x] Utility to write files given a buffer (a.k.a: writeAllBytes)
- [ ] Comptime utility function to create directories and files given a comptime known path (Really useful!)
- [ ] Comptime utility function to search for directories and files given a comptime known path (Really useful!)

### Big TODO's
- [x] Reorganize/rename things
- [x] Rewrite codepage name handling
- [x] Rewrite UTF-16 name handling
- [ ] Think about how to handle errors while writing (e.g: currently an error while allocating clusters will leave the FAT table with dangling clusters...)
- [ ] Behaviour tests

- [ ] Implement some sort of I/O cache? Or leave it to the BlockDevice implementation?
- [ ] Some sort of cache strategy for FAT entries if requested.
- [ ] API Freeze
