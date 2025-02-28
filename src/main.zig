const std = @import("std");
const zfat = @import("zfat");

const SliceBlockContext = struct {
    slice: []u8,
    logical_block_size: usize,

    pub const Sector = usize;
    pub const ReadResult = struct {
        data: []const u8,

        pub inline fn getData(result: ReadResult) []const u8 {
            return result.data;
        }

        pub inline fn deinit(result: ReadResult) void {
            _ = result;
        }
    };

    pub fn read(ctx: *SliceBlockContext, sector: usize) !ReadResult {
        return ReadResult{ .data = ctx.slice[(sector * ctx.logical_block_size)..][0..ctx.logical_block_size] };
    }

    pub fn setLogicalBlockSize(ctx: *SliceBlockContext, new_logical_block_size: usize) !void {
        ctx.logical_block_size = new_logical_block_size;
    }

    pub fn getLogicalBlockSize(ctx: *SliceBlockContext) usize {
        return ctx.logical_block_size;
    }
};

const FileBlockContext = struct {
    const BlockSizeError = error{
        UnalignedSizeError,
    };

    fd: std.fs.File,
    logical_block_size: usize,

    pub const Sector = usize;
    pub const ReadResult = struct {
        data: [4096]u8 = undefined,
        block_size: usize,

        pub inline fn getData(result: ReadResult) []const u8 {
            return result.data[0..result.block_size];
        }

        pub inline fn deinit(result: ReadResult) void {
            _ = result;
        }
    };

    pub fn read(ctx: *FileBlockContext, sector: usize) !ReadResult {
        var read_res = ReadResult{ .block_size = ctx.logical_block_size };
        try ctx.fd.seekTo(sector * ctx.logical_block_size);
        std.debug.assert(try ctx.fd.read(read_res.data[0..ctx.logical_block_size]) == ctx.logical_block_size);
        return read_res;
    }

    pub fn setLogicalBlockSize(ctx: *FileBlockContext, new_logical_block_size: usize) !void {
        if ((try ctx.fd.stat()).size % new_logical_block_size != 0) {
            return BlockSizeError.UnalignedSizeError;
        }

        ctx.logical_block_size = new_logical_block_size;
    }

    pub fn getLogicalBlockSize(ctx: *FileBlockContext) usize {
        return ctx.logical_block_size;
    }
};

const Fat = zfat.FatFilesystem(FileBlockContext, .{ .maximum_supported_type = .fat12 });
const StringBuilder = std.ArrayList(u8);
const DirectoryStack = std.ArrayList(Fat.Cluster);

// FIXME: Behold! truly amazing code. Never do this!
pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    const alloc = gpa.allocator();
    const stdout = std.io.getStdOut().writer();

    const args = try std.process.argsAlloc(alloc);
    defer std.process.argsFree(alloc, args);

    if (args.len < 2) {
        try stdout.print("Please, specify an image to open!", .{});
        return;
    }

    const floppy_file = try std.fs.cwd().openFile(args[1], .{ .mode = .read_write });
    var floppy_blk_ctx = FileBlockContext{ .fd = floppy_file, .logical_block_size = 512 };

    var fat_ctx = Fat.mount(&floppy_blk_ctx) catch |err| switch (err) {
        zfat.MountError.InvalidBackupSector, zfat.MountError.InvalidBootSignature, zfat.MountError.InvalidBytesPerSector, zfat.MountError.InvalidFatSize, zfat.MountError.InvalidJump, zfat.MountError.InvalidMediaType, zfat.MountError.InvalidReservedSectorCount, zfat.MountError.InvalidRootEntries, zfat.MountError.InvalidSectorCount, zfat.MountError.InvalidSectorsPerCluster, zfat.MountError.UnsupportedFat => {
            try stdout.print("The image does not contain a valid FAT filesystem: {s}", .{@errorName(err)});
            return;
        },
        else => |t| return t,
    };

    try stdout.print("{}\n", .{fat_ctx});

    const stdin = std.io.getStdIn().reader();

    var current_path = StringBuilder.init(alloc);
    defer current_path.deinit();
    try current_path.appendSlice("/");

    var current_dir = DirectoryStack.init(alloc);
    defer current_dir.deinit();
    try current_dir.append(Fat.root_directory_handle);

    var buf: [256]u8 = undefined;
    while (true) {
        try stdout.print("{s} => ", .{current_path.items});

        const input = try stdin.readUntilDelimiter(&buf, '\n');

        const isCd = std.mem.startsWith(u8, input, "cd ");
        if (isCd or std.mem.startsWith(u8, input, "cat ")) {
            const next_path = input[(if (isCd) "cd ".len else "cat ".len)..];

            if (next_path.len == 0) {
                try stdout.print("Please, specify a path to change directory to.", .{});
                continue;
            }

            if (next_path.len == 1 and next_path[0] == '.') {
                continue;
            }

            const utf16_next_path = try std.unicode.utf8ToUtf16LeAlloc(alloc, next_path);
            defer alloc.free(utf16_next_path);

            if (try fat_ctx.searchEntry(&floppy_blk_ctx, current_dir.items[current_dir.items.len - 1], utf16_next_path)) |ent| {
                if (isCd) {
                    if (!ent.attributes.directory) {
                        try stdout.print("Cannot change directory into a file!\n", .{});
                        continue;
                    }

                    try stdout.print("cd: {} => {}\n", .{ current_dir.items[current_dir.items.len - 1], ent.handle });

                    if (current_dir.items.len > 1 and ent.handle == current_dir.items[current_dir.items.len - 2]) {
                        _ = current_dir.pop();
                        _ = current_path.pop();

                        while (current_path.pop() != '/') {}
                        try current_path.append('/');
                    } else {
                        try current_path.appendSlice(next_path);
                        try current_path.append('/');
                        try current_dir.append(ent.handle);
                    }
                } else {
                    if (ent.attributes.directory) {
                        try stdout.print("Cannot cat a directory!\n", .{});
                        continue;
                    }

                    try stdout.print("Contents of file: {s} - CLUSTER {}\n", .{ next_path, ent.handle });
                    const sectors_per_cluster = @as(usize, 1) << fat_ctx.misc.sectors_per_cluster;

                    var current_read_index: usize = 0;
                    var current_cluster = ent.handle;
                    reading: while (true) {
                        const cluster_sector = fat_ctx.cluster2Sector(current_cluster);
                        var current_sector: usize = 0;

                        while (current_sector < sectors_per_cluster) : (current_sector += 1) {
                            const read = try floppy_blk_ctx.read(cluster_sector + current_sector);
                            defer read.deinit();

                            current_read_index += floppy_blk_ctx.getLogicalBlockSize();

                            if (current_read_index >= ent.file_size) {
                                const remaining = ent.file_size - (current_read_index - floppy_blk_ctx.getLogicalBlockSize());

                                try stdout.print("{s}", .{read.getData()[0..remaining]});
                                break :reading;
                            } else {
                                try stdout.print("{s}", .{read.getData()});
                            }
                        }

                        current_sector = 0;

                        if (try fat_ctx.nextCluster(&floppy_blk_ctx, current_cluster)) |next| {
                            current_cluster = next;
                        } else {
                            std.debug.assert(current_read_index == ent.file_size);
                            break :reading;
                        }
                    }

                    try stdout.print("\nFile size: {}\n", .{ent.file_size});
                }
            } else {
                try stdout.print("File or directory not found.\n", .{});
            }
        } else if (std.mem.startsWith(u8, input, "ls")) {
            var dir_it = fat_ctx.directoryIterator(current_dir.items[current_dir.items.len - 1]);
            defer dir_it.deinit();

            var entries: usize = 0;
            while (try dir_it.next(&floppy_blk_ctx)) |dir| : (entries += 1) {
                const long_name = try std.unicode.utf16LeToUtf8Alloc(alloc, dir.name);
                defer alloc.free(long_name);
                try stdout.print("  {s}\n", .{long_name});
            }

            try stdout.print("\n{} entries in the directory\n", .{entries});
        } else if (std.mem.startsWith(u8, input, "exit")) {
            break;
        }
    }
}
