# ⚡ nzfat (WIP)
A very generic and configurable FAT12/16/32 implementation library with VFAT support written in zig.
Almost all the features are configurable, from long filename support (and the max number of characters it supports) to the maximum supported FAT type (12/16/32).

[![asciicast](https://asciinema.org/a/Zf1LmR1KpfLKj7KxOFWCuUIPE.svg)](https://asciinema.org/a/Zf1LmR1KpfLKj7KxOFWCuUIPE)

  
## ❓ Usage
The library is not mature enough for production usage, but if you still want to use this, here's some little info:
  
The `FatFilesystem` type only needs two arguments, the block device context and its configuration. Some methods change their signature depending on the configuration and all methods require the block context to be passed to it. This library never stores the passed block device anywhere.

For example, mounting a FAT filesystem might be done like this:
```zig
const nzfat = @import("nzfat");
const Fat = nzfat.FatFilesystem(...);
// ...
var fat_ctx = try Fat.mount(&blk);
// See zfat.MountError
```

To traverse the directory entries you have `directoryIterator` and `directoryIteratorContext` at your disposal:
```zig
// TODO: Explain why directoryIteratorContext is sometimes needed for long filenames.
var dir_it = fat_ctx.directoryIterator(fat_ctx.getRoot());
defer dir_it.deinit();

while (try dir_it.next(&blk)) |entry| : (entries += 1) {
    // Do something with entry 
}
```

As searching for a specific entry in a directory is very common, `searchEntry` and `searchEntryContext` abstract away the case-insensitive nature of the filesystem:
```zig
// TODO: Explain that for long filenames a case-insensitive comparison function must be provided as its out of scope for this project
if(try fat_ctx.searchEntry(&blk, handle, name)) |entry| {
    // Do something with the entry we found...
}
```

## 📝 TODO

### Small TODO's
- [x] Searching for 1 free entry in a directory (a.k.a: Short filename only)
- [x] Searching for a free cluster linearly
- [x] Deletion of files and directories
- [x] Short filename alternatives when using a VFAT `FatFilesystem`
- [x] Searching for N free clusters for file and directory creation
- [x] Allocate new directory entries if no entries found and not in root (FAT12/16 only)
- [ ] Creation of directory entries with LFN entries if needed
- [ ] Searching for N free entries in a directory
- [x] API to allocate clusters for files
- [ ] API to modify dates and times and attributes in entries

### Big TODO's
- [ ] Implement some sort of I/O cache? Or leave it to the BlockDevice implementation?
- [ ] Some sort of cache strategy for FAT entries if requested.
- [ ] Reorganize/rename and API Freeze
