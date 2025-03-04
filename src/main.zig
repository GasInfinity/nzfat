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

    pub const Sector = usize;
    pub const SectorResult = struct {
        data: []u8,

        pub inline fn asSlice(result: SectorResult) []u8 {
            return result.data;
        }
    };

    pub fn map(ctx: *FileBlockContext, sector: Sector) !SectorResult {
        var read_res = SectorResult{ .data = try ctx.allocator.alloc(u8, ctx.logical_block_size) };
        try ctx.fd.seekTo(sector * ctx.logical_block_size);
        std.debug.assert(try ctx.fd.read(read_res.data[0..ctx.logical_block_size]) == ctx.logical_block_size);
        ctx.maps += 1;
        return read_res;
    }

    pub fn commit(ctx: *FileBlockContext, sector: Sector, result: SectorResult) !void {
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
};

const Fat = nzfat.FatFilesystem(FileBlockContext, .{});
const StringBuilder = std.ArrayList(u8);
const DirectoryStack = std.ArrayList(Fat.Cluster);

const Command = enum {
    cd,
    ls,
    cat,
    exit,
    mkdir,
    rm,
    rmdir,
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
    var floppy_blk_ctx = FileBlockContext{ .allocator = alloc, .fd = floppy_file, .logical_block_size = 512 };

    var fat_ctx = Fat.mount(&floppy_blk_ctx) catch |err| switch (err) {
        nzfat.MountError.InvalidBackupSector, nzfat.MountError.InvalidBootSignature, nzfat.MountError.InvalidBytesPerSector, nzfat.MountError.InvalidFatSize, nzfat.MountError.InvalidJump, nzfat.MountError.InvalidMediaType, nzfat.MountError.InvalidReservedSectorCount, nzfat.MountError.InvalidRootEntries, nzfat.MountError.InvalidSectorCount, nzfat.MountError.InvalidSectorsPerCluster, nzfat.MountError.UnsupportedFat => {
            try stdout.print("The image does not contain a valid FAT filesystem: {s}", .{@errorName(err)});
            return;
        },
        else => |t| return t,
    };

    const stdin = std.io.getStdIn().reader();

    var current_path = StringBuilder.init(alloc);
    defer current_path.deinit();
    try current_path.appendSlice("/");

    var current_dir = DirectoryStack.init(alloc);
    defer current_dir.deinit();
    try current_dir.append(fat_ctx.getRoot());

    var buf: [256]u8 = undefined;
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

                    if (next_path.len == 1 and next_path[0] == '.') {
                        continue;
                    }

                    const utf16_next_path = try std.unicode.utf8ToUtf16LeAlloc(alloc, next_path);
                    defer alloc.free(utf16_next_path);

                    if (try fat_ctx.searchEntry(&floppy_blk_ctx, current_dir.items[current_dir.items.len - 1], utf16_next_path)) |ent| {
                        if (!ent.attributes.directory) {
                            try stdout.print("Cannot change directory into a file!\n", .{});
                            continue;
                        }

                        const new_target = ent.cluster;
                        try stdout.print("cd: {} => {}\n", .{ current_dir.items[current_dir.items.len - 1], new_target });

                        if (current_dir.items.len > 1 and std.meta.eql(current_dir.items[current_dir.items.len - 2], new_target)) {
                            _ = current_dir.pop();
                            _ = current_path.pop();

                            while (current_path.pop() != '/') {}
                            try current_path.append('/');
                        } else {
                            try current_path.appendSlice(next_path);
                            try current_path.append('/');
                            try current_dir.append(ent.cluster);
                        }
                    } else {
                        try stdout.print("Directory not found.\n", .{});
                    }
                },
                .cat => {
                    const next_path = command_args;

                    const utf16_next_path = try std.unicode.utf8ToUtf16LeAlloc(alloc, next_path);
                    defer alloc.free(utf16_next_path);

                    if (try fat_ctx.searchEntry(&floppy_blk_ctx, current_dir.items[current_dir.items.len - 1], utf16_next_path)) |ent| {
                        if (ent.attributes.directory) {
                            try stdout.print("Cannot cat a directory!\n", .{});
                            continue;
                        }
                        try stdout.print("Contents of file: {s} - CLUSTER {}\n", .{ next_path, ent.cluster });
                        const sectors_per_cluster = @as(usize, 1) << fat_ctx.misc.sectors_per_cluster;

                        var current_read_index: usize = 0;
                        var current_cluster = ent.cluster;
                        reading: while (true) {
                            const cluster_sector = fat_ctx.cluster2Sector(current_cluster);
                            var current_sector: usize = 0;

                            while (current_sector < sectors_per_cluster) : (current_sector += 1) {
                                const sc = cluster_sector + current_sector;
                                const read = try floppy_blk_ctx.map(sc);
                                defer floppy_blk_ctx.unmap(sc, read);

                                current_read_index += floppy_blk_ctx.logical_block_size;

                                if (current_read_index >= ent.file_size) {
                                    const remaining = ent.file_size - (current_read_index - floppy_blk_ctx.logical_block_size);

                                    try stdout.print("{s}", .{read.asSlice()[0..remaining]});
                                    break :reading;
                                } else {
                                    try stdout.print("{s}", .{read.asSlice()});
                                }
                            }

                            current_sector = 0;

                            if (try fat_ctx.nextAllocatedCluster(&floppy_blk_ctx, current_cluster, .read)) |next| {
                                current_cluster = next;
                                try stdout.print("NEXT CLUSTER => {}", .{next});
                            } else {
                                std.debug.assert(current_read_index == ent.file_size);
                                break :reading;
                            }
                        }

                        try stdout.print("File size: {} bytes\n", .{ent.file_size});
                    } else {
                        try stdout.print("File not found.\n", .{});
                    }
                },
                .mkdir => {
                    if (try fat_ctx.searchShortEntry(&floppy_blk_ctx, current_dir.items[current_dir.items.len - 1], "testing.txt") == null) {
                        try fat_ctx.createShortEntry(&floppy_blk_ctx, current_dir.items[current_dir.items.len - 1], "testing.txt", .{ .type = .{ .file = 0 } });
                    } else {
                        try stdout.print("File already exists!\n", .{});
                    }

                    try stdout.print("TODO Handle paths\n", .{});
                    // TODO
                },
                .rm => {
                    const next_path = command_args;

                    const utf16_next_path = try std.unicode.utf8ToUtf16LeAlloc(alloc, next_path);
                    defer alloc.free(utf16_next_path);
                    if (try fat_ctx.searchEntry(&floppy_blk_ctx, current_dir.items[current_dir.items.len - 1], utf16_next_path)) |found| {
                        if (found.attributes.directory) {
                            try stdout.print("Use rmdir to delete directories\n", .{});
                            continue;
                        }

                        try fat_ctx.deleteEntry(&floppy_blk_ctx, found);
                    } else {
                        try stdout.print("File not found\n", .{});
                    }
                },
                .rmdir => {
                    const next_path = command_args;

                    const utf16_next_path = try std.unicode.utf8ToUtf16LeAlloc(alloc, next_path);
                    defer alloc.free(utf16_next_path);

                    if (try fat_ctx.searchEntry(&floppy_blk_ctx, current_dir.items[current_dir.items.len - 1], utf16_next_path)) |found| {
                        if (!found.attributes.directory) {
                            try stdout.print("Use rm to delete files\n", .{});
                            continue;
                        }

                        // TODO: Check if directory can be deleted (i.e: '.' and '..')
                        if (!try fat_ctx.isDirectoryEmpty(&floppy_blk_ctx, found.cluster)) {
                            try stdout.print("You can only delete empty directories\n", .{});
                            continue;
                        }

                        try fat_ctx.deleteEntry(&floppy_blk_ctx, found);
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
                    var dir_it = fat_ctx.directoryIterator(current_dir.items[current_dir.items.len - 1]);
                    defer dir_it.deinit(&floppy_blk_ctx);

                    var entries: usize = 0;
                    while (try dir_it.next(&floppy_blk_ctx)) |dir| : (entries += 1) {
                        if (dir.lfn) |lfn| {
                            const long_name = try std.unicode.utf16LeToUtf8Alloc(alloc, lfn);
                            defer alloc.free(long_name);

                            try stdout.print("  {s} ({s})\n", .{ dir.sfn, long_name });
                        } else {
                            try stdout.print("  {s}\n", .{dir.sfn});
                        }
                    }

                    try stdout.print("\n{} entries in the directory\n", .{entries});
                },
                .exit => {
                    break;
                },
                else => |t| try stdout.print("Cannot {}, one or more arguments needed\n", .{t}),
            }
        }
    }
}
