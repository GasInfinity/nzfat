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

To traverse the directory entries you have `directoryEntryIterator` at your disposal:
```zig
// TODO: Explain why directoryIteratorContext is sometimes needed for long filenames.
var dir_it = fat_ctx.directoryEntryIterator(null); // NOTE: null is the root directory
defer dir_it.deinit();

std.debug.print("- Listing entries at /\n");
while (try dir_it.next(&blk)) |it_entry| : (entries += 1) {
    // Do something with it_entry
    std.debug.print("- {s}", .{it_entry.sfn});

    // NOTE: Only if enabled in the config, if not it_entry.lfn will be void!
    if(it_entry.lfn) |lfn| {
        std.debug.print(" ({s})", utf16ToUtf8(lfn));
    }

    std.debug.print("\n", .{});
}
```

As searching for a specific entry in a directory is very common, `search`, `searchContext` and `searchShort` abstract away the case-insensitive nature of the filesystem:
```zig
// TODO: Explain that for long filenames a case-insensitive comparison function must be provided as its out of scope for this project
if(try fat_ctx.search(&blk, handle, name)) |entry| {
    std.debug.print("'{s}' found! Is a {}", .{utf8_name, @tagName(entry.type)});
    // Do something with the entry we found...
}
```

## 📝 TODO

### Small TODO's
- [ ] Update to zig 0.14.0

- [x] Searching for 1 free entry in a directory (a.k.a: Short filename only)
- [x] Searching for a free cluster linearly
- [x] Deletion of files and directories
- [x] Short filename alternatives for functions when using a VFAT `FatFilesystem`
- [x] Searching for N free clusters for file and directory creation
- [x] Allocate new directory entries if no entries found and not in root (FAT12/16 only)
- [x] Allocate clusters for files
- [x] Creation of files and directories with short names
- [x] API to modify dates and times and attributes in entries
- [ ] API for reading and writing file contents
- [ ] Searching for N free entries in a directory and creation of directory entries with LFN entries if needed.
- [ ] Create fat formatted media
- [ ] Utility check and 'fix' fat filesystem
- [ ] Utility to write files given a buffer (a.k.a: writeAllBytes)
- [ ] Comptime utility function to create directories and files given a comptime known path (Really useful!)
- [ ] Comptime utility function to search for directories and files given a comptime known path (Really useful!)

### Big TODO's
- [x] Reorganize/rename things
- [ ] Behaviour tests
- [ ] Rewrite codepage name handling
- [ ] Rewrite UCS-2 name handling

- [ ] Implement some sort of I/O cache? Or leave it to the BlockDevice implementation?
- [ ] Some sort of cache strategy for FAT entries if requested.
- [ ] API Freeze
