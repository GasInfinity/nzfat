const std = @import("std");
const nzfat = @import("nzfat");

const FileBlockContext = struct {
    const BlockSizeError = error{
        UnalignedSizeError,
    };

    allocator: std.mem.Allocator,
    fd: std.fs.File,
    logical_block_size: usize,
    maps: usize = 0,
    commits: usize = 0,

    pub const MapError = std.fs.File.ReadError || std.fs.File.SeekError || std.mem.Allocator.Error;
    pub const CommitError = std.fs.File.WriteError || std.fs.File.SeekError;
    pub const Sector = usize;
    pub const SectorResult = struct {
        data: []u8,

        pub inline fn asSlice(result: SectorResult) []u8 {
            return result.data;
        }
    };

    pub fn map(ctx: *FileBlockContext, sector: Sector) MapError!SectorResult {
        var read_res = SectorResult{ .data = try ctx.allocator.alloc(u8, ctx.logical_block_size) };
        try ctx.fd.seekTo(sector * ctx.logical_block_size);
        std.debug.assert(try ctx.fd.read(read_res.data[0..ctx.logical_block_size]) == ctx.logical_block_size);
        ctx.maps += 1;
        return read_res;
    }

    pub fn commit(ctx: *FileBlockContext, sector: Sector, result: SectorResult) CommitError!void {
        try ctx.fd.seekTo(sector * ctx.logical_block_size);
        _ = try ctx.fd.write(result.data);
        ctx.commits += 1;
    }

    pub fn unmap(ctx: *FileBlockContext, _: Sector, result: SectorResult) void {
        ctx.allocator.free(result.data);
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

    pub fn getSize(ctx: *FileBlockContext) usize {
        return (ctx.fd.getEndPos() catch unreachable) / ctx.logical_block_size;
    }
};

const Fat = nzfat.FatFilesystem(FileBlockContext, .{});
const StringBuilder = std.ArrayList(u8);
const DirectoryStack = std.ArrayList(?Fat.Dir);

const Command = enum {
    cd,
    ls,
    cat,
    exit,
    mkdir,
    rn,
    rm,
    rmdir,
    touch,
    write,
    append,
};

// FIXME: Behold! truly amazing code. Never do this!
pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{ .safety = true }){};
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
    try floppy_file.setEndPos(2880 * 512);

    var floppy_blk_ctx = FileBlockContext{ .allocator = alloc, .fd = floppy_file, .logical_block_size = 512 };
    // _ = try nzfat.format.make(&floppy_blk_ctx, .{ .volume_id = std.mem.zeroes([4]u8) });

    var fat_ctx = Fat.mount(&floppy_blk_ctx) catch |err| switch (err) {
        nzfat.MountError.InvalidBackupSector, nzfat.MountError.InvalidBootSignature, nzfat.MountError.InvalidBytesPerSector, nzfat.MountError.InvalidFatSize, nzfat.MountError.InvalidJump, nzfat.MountError.InvalidMediaType, nzfat.MountError.InvalidReservedSectorCount, nzfat.MountError.InvalidRootEntries, nzfat.MountError.InvalidSectorCount, nzfat.MountError.InvalidSectorsPerCluster, nzfat.MountError.UnsupportedFat => {
            try stdout.print("The image does not contain a valid FAT filesystem: {s}", .{@errorName(err)});
            return;
        },
        else => |t| return t,
    };
    try stdout.print("{}", .{fat_ctx});

    const stdin = std.io.getStdIn().reader();

    var current_path = StringBuilder.init(alloc);
    defer current_path.deinit();
    try current_path.appendSlice("/");

    var current_dir = DirectoryStack.init(alloc);
    defer current_dir.deinit();
    try current_dir.append(null);

    var buf: [512]u8 = undefined;
    while (true) {
        try stdout.print("{} maps, {} commits\n", .{ floppy_blk_ctx.maps, floppy_blk_ctx.commits });
        try stdout.print("{s} => ", .{current_path.items});

        const input = try stdin.readUntilDelimiter(&buf, '\n');
        const possible_first_space = std.mem.indexOf(u8, input, " ");

        if (possible_first_space) |first_space| {
            const command = std.meta.stringToEnum(Command, input[0..first_space]);

            if (command == null) {
                try stdout.print("Command not found\n", .{});
                continue;
            }

            const command_args = input[(first_space + 1)..];

            switch (command.?) {
                .cd => {
                    const next_path = command_args;

                    if (std.mem.eql(u8, next_path, ".")) {
                        continue;
                    }

                    if (std.mem.eql(u8, next_path, "..")) {
                        if (current_dir.items.len == 1) {
                            continue;
                        }

                        _ = current_dir.pop();
                        _ = current_path.pop();

                        while (current_path.pop() != '/') {}
                        try current_path.append('/');
                        continue;
                    }

                    const utf16_next_path = try std.unicode.utf8ToUtf16LeAlloc(alloc, next_path);
                    defer alloc.free(utf16_next_path);

                    if (try fat_ctx.search(&floppy_blk_ctx, current_dir.items[current_dir.items.len - 1], utf16_next_path)) |found| {
                        if (found.type != .directory) {
                            try stdout.print("Cannot change directory into a file!\n", .{});
                            continue;
                        }

                        try stdout.print("cd: {?} => {}\n", .{ current_dir.items[current_dir.items.len - 1], found });
                        try current_path.appendSlice(next_path);
                        try current_path.append('/');
                        try current_dir.append(found.toDir());
                    } else {
                        try stdout.print("Directory not found.\n", .{});
                    }
                },
                .cat => {
                    const next_path = command_args;

                    const utf16_next_path = try std.unicode.utf8ToUtf16LeAlloc(alloc, next_path);
                    defer alloc.free(utf16_next_path);

                    if (try fat_ctx.search(&floppy_blk_ctx, current_dir.items[current_dir.items.len - 1], utf16_next_path)) |found| {
                        if (found.type != .file) {
                            try stdout.print("Cannot cat a directory!\n", .{});
                            continue;
                        }

                        var file = found.toFile();
                        var file_buf: [512]u8 = undefined;
                        try stdout.print("Contents of file: {s} - CLUSTER {}\n", .{ next_path, found.cluster });
                        while (true) {
                            const read = try file.read(&fat_ctx, &floppy_blk_ctx, &file_buf);

                            if (read == 0) {
                                break;
                            }

                            try stdout.print("{s}", .{file_buf[0..read]});
                        }

                        try stdout.print("File size: {} bytes\n", .{found.file_size});
                    } else {
                        try stdout.print("File not found.\n", .{});
                    }
                },
                .mkdir => {
                    const next_path = command_args;

                    const utf16_next_path = try std.unicode.utf8ToUtf16LeAlloc(alloc, next_path);
                    defer alloc.free(utf16_next_path);

                    if (try fat_ctx.search(&floppy_blk_ctx, current_dir.items[current_dir.items.len - 1], utf16_next_path) == null) {
                        _ = try fat_ctx.create(&floppy_blk_ctx, current_dir.items[current_dir.items.len - 1], utf16_next_path, .{ .type = .{ .directory = 2 } });
                    } else {
                        try stdout.print("File or directory already exists!\n", .{});
                    }
                },
                .touch => {
                    const next_path = command_args;

                    const utf16_next_path = try std.unicode.utf8ToUtf16LeAlloc(alloc, next_path);
                    defer alloc.free(utf16_next_path);

                    if (try fat_ctx.search(&floppy_blk_ctx, current_dir.items[current_dir.items.len - 1], utf16_next_path) == null) {
                        _ = try fat_ctx.create(&floppy_blk_ctx, current_dir.items[current_dir.items.len - 1], utf16_next_path, .{ .type = .{ .file = 0 } });
                    } else {
                        try stdout.print("File or directory already exists!\n", .{});
                    }
                },
                .write => {
                    const next_path = command_args;

                    const utf16_next_path = try std.unicode.utf8ToUtf16LeAlloc(alloc, next_path);
                    defer alloc.free(utf16_next_path);

                    if (try fat_ctx.search(&floppy_blk_ctx, current_dir.items[current_dir.items.len - 1], utf16_next_path)) |found| {
                        if (found.type != .file) {
                            try stdout.print("Cannot write to a directory!\n", .{});
                            continue;
                        }

                        var file = found.toFile();
                        try file.writeAll(&fat_ctx, &floppy_blk_ctx, &("Hello FAT World!\n".* ** 100));
                    } else {
                        try stdout.print("The file does not exist!\n", .{});
                    }
                },
                .rn => {
                    const next_path = command_args;

                    const utf16_next_path = try std.unicode.utf8ToUtf16LeAlloc(alloc, next_path);
                    defer alloc.free(utf16_next_path);

                    if (try fat_ctx.search(&floppy_blk_ctx, current_dir.items[current_dir.items.len - 1], utf16_next_path)) |found| {
                        _ = try fat_ctx.move(&floppy_blk_ctx, found, null, std.unicode.utf8ToUtf16LeStringLiteral("rename.tst"));
                    } else {
                        try stdout.print("The file or directory does not exist!\n", .{});
                    }
                },
                .append => {
                    const next_path = command_args;

                    const utf16_next_path = try std.unicode.utf8ToUtf16LeAlloc(alloc, next_path);
                    defer alloc.free(utf16_next_path);

                    if (try fat_ctx.search(&floppy_blk_ctx, current_dir.items[current_dir.items.len - 1], utf16_next_path)) |found| {
                        if (found.type != .file) {
                            try stdout.print("Cannot append to a directory!\n", .{});
                            continue;
                        }

                        var file = found.toFile();
                        try file.seekTo(&fat_ctx, &floppy_blk_ctx, file.entry.file_size);
                        try file.writeAll(&fat_ctx, &floppy_blk_ctx, &("Appended FAT World!\n".* ** 5));
                    } else {
                        try stdout.print("The file does not exist!\n", .{});
                    }
                },
                .rm => {
                    const next_path = command_args;

                    const utf16_next_path = try std.unicode.utf8ToUtf16LeAlloc(alloc, next_path);
                    defer alloc.free(utf16_next_path);
                    if (try fat_ctx.search(&floppy_blk_ctx, current_dir.items[current_dir.items.len - 1], utf16_next_path)) |found| {
                        if (found.type != .file) {
                            try stdout.print("Use rmdir to delete directories\n", .{});
                            continue;
                        }

                        try fat_ctx.delete(&floppy_blk_ctx, found);
                    } else {
                        try stdout.print("File not found\n", .{});
                    }
                },
                .rmdir => {
                    const next_path = command_args;

                    const utf16_next_path = try std.unicode.utf8ToUtf16LeAlloc(alloc, next_path);
                    defer alloc.free(utf16_next_path);

                    if (try fat_ctx.search(&floppy_blk_ctx, current_dir.items[current_dir.items.len - 1], utf16_next_path)) |found| {
                        if (found.type != .directory) {
                            try stdout.print("Use rm to delete files\n", .{});
                            continue;
                        }

                        if (!try fat_ctx.isDirectoryEmpty(&floppy_blk_ctx, found.toDir())) {
                            try stdout.print("You can only delete empty directories\n", .{});
                            continue;
                        }

                        try fat_ctx.delete(&floppy_blk_ctx, found);
                    }
                },
                // XXX: Yes, I know... this is reachable...
                else => unreachable,
            }
        } else {
            const command = std.meta.stringToEnum(Command, input);

            if (command == null) {
                try stdout.print("Command not found\n", .{});
                continue;
            }

            switch (command.?) {
                .ls => {
                    var dir_it = fat_ctx.directoryEntryIterator(current_dir.items[current_dir.items.len - 1]);
                    defer dir_it.deinit(&floppy_blk_ctx);

                    var entries: usize = 0;
                    while (try dir_it.next(&floppy_blk_ctx)) |dir| : (entries += 1) {
                        var filename = nzfat.ShortFilenameDisplay.init(0) catch unreachable;
                        dir.displayShortFilename(&filename);

                        if (dir.lfn) |lfn| {
                            const long_name = try std.unicode.utf16LeToUtf8Alloc(alloc, lfn);
                            defer alloc.free(long_name);

                            try stdout.print("  {s} ({s})", .{ filename.constSlice(), long_name });
                        } else {
                            try stdout.print("  {s}", .{filename.constSlice()});
                        }

                        try stdout.print("   {s}   \n", .{@tagName(dir.entry.type)});
                    }

                    try stdout.print("\n{} entries in the directory\n", .{entries});
                },
                .exit => {
                    try fat_ctx.unmount(&floppy_blk_ctx, true);
                    break;
                },
                else => |t| try stdout.print("Cannot {}, one or more arguments needed\n", .{t}),
            }
        }
    }
}
