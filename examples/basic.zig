const std = @import("std");
const nzfat = @import("nzfat");

// This implements a basic 'BlockDevice' backed by sequential 'sectors' of 512 bytes
// A BlockDevice which will only be mounted only needs three important functions:
// - `map`: Maps a sector of the disk into memory. It is recommended to cache maps for now as they are really frequent
// - 'commit': Syncs the written contents into the disk (May be cached by the underlying implementation). The driver will NEVER write into memory without commiting it after.
// - `unmap`: Unmaps a previous sector of the disk, it only signals to the implementation that the driver has finished using it. The unmapped block MAY be mapped shortly in the future.
// - `setLogicalBlockSize`: Currently is only used when mounting a device, to signal to the underlying implementation to switch to the requested block size or error out if unsupported.
//
// These next functions are only needed when formatting a BlockDevice:
// - `getLogicalBlockSize`: Returns the current block size or the most optimal one if it has not been set by the driver.
// - `getSize`: Returns the size (in sectors) of the block device with its current block size (i.e: getSize() * getLogicalBlockSize() would get the real size in bytes of the device)
// -------------------------------------------------------------------------------------------------------------------------
// NOTES:
// It is recommended to use block sizes of 512 or 4096. Other sizes in-between are supported but I cannot guarantee anything
const BasicBlockContext = struct {
    data: [][512]u8,

    pub const BlockSizeError = error{UnalignedSizeError};
    pub const MapError = error{};
    pub const CommitError = error{};

    pub const Sector = usize;
    // XXX: A struct like this cannot currently have a `[512]u8` for example, as the underlying FatFilesystem driver does `const sector = ...;` and the data is const so cannot create a mutable slice.
    pub const MapResult = struct {
        data: []u8,

        pub inline fn asSlice(result: MapResult) []u8 {
            return result.data;
        }
    };

    pub fn map(ctx: *BasicBlockContext, sector: Sector) MapError!MapResult {
        return MapResult{ .data = &ctx.data[sector] };
    }

    pub fn commit(ctx: *BasicBlockContext, sector: Sector, result: MapResult) CommitError!void {
        ctx.data[sector] = result.data;
    }

    pub fn unmap(_: BasicBlockContext, _: Sector, _: MapResult) void {}

    pub fn setLogicalBlockSize(_: BasicBlockContext, new_logical_block_size: usize) BlockSizeError!void {
        if (new_logical_block_size != 512) {
            return BlockSizeError.UnalignedSizeError;
        }
    }

    pub fn getLogicalBlockSize(_: BasicBlockContext) usize {
        return 512;
    }

    pub fn getSize(ctx: BasicBlockContext) usize {
        return ctx.data.len;
    }
};

// Implements a FAT Filesystem as specified in official documentation.
const Fat = nzfat.FatFilesystem(BasicBlockContext, .{
    // Configures the maximum supported FAT type, it's very important that you set this correctly as if you don't need larger cluster sizes you won't pay for them at compile-time
    // Table of compile-time stored cluster type:
    //   - .fat32 -> Stored cluster size u32
    //   - .fat16 -> Stored cluster size u16
    //   - .fat12 -> Stored cluster size u12
    // Not only it changes the stored cluster type, it also brings down code-size due to comptime dead code.
    .maximum_supported_type = .fat32,

    // A value of `null` means no support for long filenames. As above, it's recommended to not use long filenames if not needed as it brings down code-size greatly.
    .long_filenames = .{
        // Self-explanatory, supported lengths of less characters affects the size of some structures (as an entry will span more sectors) but it's not recommended to change this unless it's really needed.
        .maximum_supported_len = 255,

        // This is temporal and will surely change. Currently this `context` implements the conversion between the system codepage (currently only ASCII, a new config option will be added like this one for it) and UTF-16.
        // Unicode is a hard topic...
        // .context =
    },

    // The only supported option right now, maybe in the future a static and dynamic caches will be implemented
    .cache = .none,
});

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{ .safety = true }){};
    defer _ = gpa.deinit();

    const alloc = gpa.allocator();

    // Emulate a standard 1.44MB floppy disk
    const data = alloc.alloc([512]u8, 2880);
    var blk = BasicBlockContext{ .data = data };

    try nzfat.format.make(&blk, .{
        // The only mandatory config
        .volume_id = [_]u8{ 0x00, 0x00, 0x00, 0x00 },
    });

    // See nzfat.zig for all possible MountError values
    var fat_ctx = try Fat.mount(&blk);

    // Now we have a fat context! (if no error has happened hopefully)
    // Almost all operations are supported (only moving files/directories without copying is missing)

    // Any directory entry converted to a file or dir MUST NOT be used after being converted as they won't be updated (Maybe instead store a pointer to the entry instead of copying?)
    // This creates a short directory entry inside '/' (null dir means root), the new entry is a file with an initial size of "Hello World!".len (WARNING: Left uninitialized!)
    var created_file = (try fat_ctx.createShort(&blk, null, "short.txt", .{
        .type = .{ .file = "Hello World!".len },
    })).toFile();

    // Write the data we allocated before
    try created_file.writeAll(&fat_ctx, &blk, "Hello World!");

    // TODO: try Fat.unmount();

    // There you have! You just created a FAT12 filesystem and added a file named SHORT.TXT with the contents 'Hello World!'
    // There are a lot of more API's like `search` to search an entry inside a directory, `directoryEntryIterator` to iterate entries inside a directory or `delete` to delete an entry and free it's allocated data.
}
