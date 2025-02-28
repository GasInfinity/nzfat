const std = @import("std");

pub const structs = @import("structs.zig");
pub const sfn = @import("sfn.zig");

const BiosParameterBlock = structs.BiosParameterBlock;
const ExtendedBootRecord = structs.ExtendedBootRecord;
const ExtendedBootRecord32 = structs.ExtendedBootRecord32;
const FSInfo32 = structs.FSInfo32;
const Attributes = structs.Attributes;
const Time = structs.Time;
const Date = structs.Date;
const DirectoryEntry = structs.DirectoryEntry;
const LongFileNameEntry = structs.LongFileNameEntry;

// TODO: Maybe reorganize this

pub const Type = enum(u2) { fat12, fat16, fat32 };

pub const MountError = error{
    InvalidJump,
    InvalidBytesPerSector,
    InvalidSectorsPerCluster,
    InvalidReservedSectorCount,
    InvalidMediaType,
    InvalidFatSize,
    InvalidSectorCount,
    InvalidRootEntries,
    InvalidBootSignature,
    InvalidBackupSector,
    UnsupportedFat,
};

pub const ClusterChainError = error{InvalidClusterValue};

pub const DefaultLongContext = struct {
    pub fn shortFilenameToUtf16Le(_: DefaultLongContext, buf: []u16, shrt: [sfn.len]u8) usize {
        return sfn.shortFilenameToCodepage(u16, buf, shrt);
    }

    pub fn utf16LeToShortFilename(_: DefaultLongContext, _: *[sfn.len]u8, _: []const u16) usize {
        unreachable;
    }

    pub fn eqlIgnoreCase(_: DefaultLongContext, left: []const u16, right: []const u16) bool {
        return std.mem.eql(u16, left, right);
    }
};

pub const Config = struct {
    pub const LongFilenameConfig = struct {
        maximum_supported_len: u8 = 255,
        context: type = DefaultLongContext,
    };

    maximum_supported_type: Type = .fat32,
    long_filenames: ?LongFilenameConfig = LongFilenameConfig{},
};

const MiscData = packed struct(u16) { type: Type, mul: u1, div: u1, bytes_per_sector: u4, sectors_per_cluster: u3, directory_entries_per_sector: u3, _: u2 = 0 };
const allowed_media_values = [_]u8{ 0xF0, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF };

pub fn FatFilesystem(comptime BlockDevice: type, comptime config: Config) type {
    return struct {
        const Self = @This();

        const BlockSector = BlockDevice.Sector;
        const BlockReadResult = BlockDevice.ReadResult;

        pub const Cluster = switch (config.maximum_supported_type) {
            .fat32 => u32,
            .fat16 => u16,
            .fat12 => u12,
        };

        pub const FatSize = switch (config.maximum_supported_type) {
            .fat32 => u32,
            else => u16,
        };

        pub const ReturnEntryName = if (config.long_filenames) |_| [:0]const u16 else [:0]const u8;
        pub const EntryName = if (config.long_filenames) |_| []const u16 else []const u8;

        // +1 for dot
        const EntryNameBuffer = if (config.long_filenames) |long_config| [long_config.maximum_supported_len:0]u16 else [sfn.len + 1:0]u8;
        const LongContext = if (config.long_filenames) |long_config| long_config.context else void;

        pub const RootDirectoryEntryData = union {
            cluster: if (config.maximum_supported_type == .fat32) Cluster else void,
            sector_info: packed struct(u16) { sectors: u16 },
        };

        pub const TableEntryType = enum { free, allocated, defective, reserved, end_of_file };
        pub const TableEntry = union(TableEntryType) { free, allocated: Cluster, defective, reserved, end_of_file };

        pub const root_directory_handle: Cluster = 0;

        misc: MiscData,
        root_entry_data: RootDirectoryEntryData,
        reserved_sector_count: u16,
        fats: u8,
        fat_size: FatSize,
        data_sector_start: u32,
        max_cluster: Cluster,

        pub fn mount(blk: *BlockDevice) !Self {
            const first_sector: BlockReadResult = try blk.read(0);
            defer first_sector.deinit();

            const first_sector_data = first_sector.getData();
            const bpb: *align(1) const BiosParameterBlock = std.mem.bytesAsValue(BiosParameterBlock, first_sector_data);

            if (bpb.jmp[0] != 0xEB and bpb.jmp[0] != 0xE9) {
                return MountError.InvalidJump;
            }

            if (first_sector_data[510] != 0x55 or first_sector_data[511] != 0xAA) {
                return MountError.InvalidBootSignature;
            }

            const bytes_per_sector = std.mem.readInt(u16, std.mem.asBytes(&bpb.bytes_per_sector), .little);

            if (!std.math.isPowerOfTwo(bytes_per_sector) or bytes_per_sector < 512 or bytes_per_sector > 4096) {
                return MountError.InvalidBytesPerSector;
            }

            try blk.setLogicalBlockSize(bytes_per_sector);

            const sectors_per_cluster = bpb.sectors_per_cluster;

            if (!std.math.isPowerOfTwo(sectors_per_cluster) or sectors_per_cluster > 128) {
                return MountError.InvalidSectorsPerCluster;
            }

            const reserved_sector_count = std.mem.readInt(u16, std.mem.asBytes(&bpb.reserved_sectors), .little);

            if (reserved_sector_count == 0) {
                return MountError.InvalidReservedSectorCount;
            }

            if (std.mem.indexOf(u8, &allowed_media_values, &.{bpb.media_descriptor_type}) == null) {
                return MountError.InvalidMediaType;
            }

            // const ebr: *align(1) const ExtendedBootRecord = std.mem.bytesAsValue(ExtendedBootRecord, first_sector_data[@sizeOf(BiosParameterBlock)..]);
            const ebr32: *align(1) const ExtendedBootRecord32 = std.mem.bytesAsValue(ExtendedBootRecord32, first_sector_data[@sizeOf(BiosParameterBlock)..]);

            const bytes_per_sector_shift: u4 = @intCast(std.math.log2(bytes_per_sector));
            const sectors_per_cluster_shift: u3 = @intCast(std.math.log2(sectors_per_cluster));

            const root_entries = std.mem.readInt(u16, std.mem.asBytes(&bpb.root_directory_entries), .little);
            const root_entries_size = root_entries * @sizeOf(DirectoryEntry);
            const root_entries_sectors = (root_entries_size + (bytes_per_sector - 1)) >> bytes_per_sector_shift;

            const directory_entries_per_sector_shift: u3 = @intCast(std.math.log2(bytes_per_sector / @sizeOf(DirectoryEntry)));

            const fat_size_16 = std.mem.readInt(u16, std.mem.asBytes(&bpb.sectors_per_fat), .little);
            const fat_size: FatSize = switch (config.maximum_supported_type) {
                .fat32 => if (fat_size_16 != 0) fat_size_16 else std.mem.readInt(u32, std.mem.asBytes(&ebr32.sectors_per_fat), .little),
                else => fat_size_16,
            };

            if (fat_size == 0) {
                return MountError.InvalidFatSize;
            }

            const sector_count_16 = std.mem.readInt(u16, std.mem.asBytes(&bpb.sector_count), .little);
            const sector_count: FatSize = switch (config.maximum_supported_type) {
                .fat32 => if (sector_count_16 != 0) sector_count_16 else std.mem.readInt(u32, std.mem.asBytes(&bpb.large_sector_count), .little),
                else => sector_count_16,
            };

            if (sector_count == 0) {
                return MountError.InvalidSectorCount;
            }

            const fats = bpb.fats;
            const root_entries_start = reserved_sector_count + (fats * @as(u32, fat_size));
            const data_sector_start = root_entries_start + root_entries_sectors;
            const data_sectors = sector_count - data_sector_start;
            const cluster_count: Cluster = @intCast(data_sectors >> sectors_per_cluster_shift);
            const max_cluster: Cluster = cluster_count + 1;

            const fat_type: Type = if (cluster_count < 4085) .fat12 else if (cluster_count < 65525) .fat16 else .fat32;

            return switch (config.maximum_supported_type) {
                .fat12 => if (fat_type != .fat12) MountError.UnsupportedFat else Self{
                    .misc = .{
                        .type = .fat12,
                        .mul = 0,
                        .div = 1,
                        .bytes_per_sector = bytes_per_sector_shift,
                        .sectors_per_cluster = sectors_per_cluster_shift,
                        .directory_entries_per_sector = directory_entries_per_sector_shift,
                    },
                    .root_entry_data = RootDirectoryEntryData{ .sector_info = .{ .sectors = root_entries_sectors } },
                    .fats = fats,
                    .fat_size = fat_size,
                    .reserved_sector_count = reserved_sector_count,
                    .data_sector_start = data_sector_start,
                    .max_cluster = max_cluster,
                },
                .fat16 => switch (fat_type) {
                    .fat32 => MountError.UnsupportedFat,
                    inline else => |t| Self{
                        .misc = .{
                            .type = t,
                            .mul = 0,
                            .div = comptime if (t == .fat12) 1 else 0,
                            .bytes_per_sector = bytes_per_sector_shift,
                            .sectors_per_cluster = sectors_per_cluster_shift,
                            .directory_entries_per_sector = directory_entries_per_sector_shift,
                        },
                        .root_entry_data = RootDirectoryEntryData{ .sector_info = .{ .sectors = root_entries_sectors } },
                        .fats = fats,
                        .fat_size = fat_size,
                        .reserved_sector_count = reserved_sector_count,
                        .data_sector_start = data_sector_start,
                        .max_cluster = max_cluster,
                    },
                },
                .fat32 => switch (fat_type) {
                    .fat32 => ctx: {
                        if (root_entries != 0) {
                            return MountError.InvalidRootEntries;
                        }

                        if (ebr32.backup_boot_sector != 6) {
                            return MountError.InvalidBackupSector;
                        }

                        const root_entry_cluster = std.mem.readInt(u32, std.mem.asBytes(&ebr32.root_cluster), .little);

                        break :ctx Self{
                            .misc = .{
                                .type = .fat32,
                                .mul = 1,
                                .div = 0,
                                .bytes_per_sector = bytes_per_sector_shift,
                                .sectors_per_cluster = sectors_per_cluster_shift,
                                .directory_entries_per_sector = directory_entries_per_sector_shift,
                            },
                            .root_entry_data = RootDirectoryEntryData{ .cluster = root_entry_cluster },
                            .fats = fats,
                            .fat_size = fat_size,
                            .reserved_sector_count = reserved_sector_count,
                            .data_sector_start = data_sector_start,
                            .max_cluster = max_cluster,
                        };
                    },
                    inline else => |t| Self{
                        .misc = .{
                            .type = t,
                            .mul = 0,
                            .div = comptime if (t == .fat12) 1 else 0,
                            .bytes_per_sector = bytes_per_sector_shift,
                            .sectors_per_cluster = sectors_per_cluster_shift,
                            .directory_entries_per_sector = directory_entries_per_sector_shift,
                        },
                        .root_entry_data = RootDirectoryEntryData{ .sector_info = .{ .sectors = root_entries_sectors } },
                        .fats = fats,
                        .fat_size = fat_size,
                        .reserved_sector_count = reserved_sector_count,
                        .data_sector_start = data_sector_start,
                        .max_cluster = max_cluster,
                    },
                },
            };
        }

        pub inline fn getType(fat_ctx: *Self) Type {
            return if (config.maximum_supported_type == .fat12) .fat12 else fat_ctx.misc.type;
        }

        pub const RootDirectoryEntriesIterator = struct {
            fat_ctx: *Self,
            current_sector_context: ?BlockReadResult,
            current_sector: u8,
            current_sector_entry: u8,

            pub fn init(fat_ctx: *Self) RootDirectoryEntriesIterator {
                return RootDirectoryEntriesIterator{
                    .fat_ctx = fat_ctx,
                    .current_sector_context = null,
                    .current_sector = 0,
                    .current_sector_entry = 0,
                };
            }

            pub fn next(it: *RootDirectoryEntriesIterator, blk: *BlockDevice) !?DirectoryEntry {
                const fat_ctx = it.fat_ctx;
                const root_entries_sectors = fat_ctx.root_entry_data.sector_info.sectors;
                const directory_entries_per_sector = @as(usize, 1) << fat_ctx.misc.directory_entries_per_sector;

                const root_directories_start: BlockSector = @as(BlockSector, fat_ctx.data_sector_start - fat_ctx.root_entry_data.sector_info.sectors);

                if (it.current_sector_context == null) {
                    it.current_sector_context = try blk.read(root_directories_start);
                }

                while (it.current_sector < root_entries_sectors) {
                    while (it.current_sector_entry < directory_entries_per_sector) {
                        const directories: []const DirectoryEntry = @alignCast(std.mem.bytesAsSlice(DirectoryEntry, it.current_sector_context.?.getData()));
                        const current_directory: DirectoryEntry = directories[it.current_sector_entry];

                        if (current_directory.isFirstEmptyEntry()) {
                            return null;
                        }

                        it.current_sector_entry += 1;
                        if (current_directory.isDeleted()) {
                            continue;
                        }

                        return current_directory;
                    }

                    it.current_sector += 1;
                    it.current_sector_entry = 0;

                    it.current_sector_context.?.deinit();
                    if (it.current_sector >= root_entries_sectors) {
                        break;
                    }

                    it.current_sector_context = try blk.read(root_directories_start + it.current_sector);
                }

                return null;
            }

            pub fn deinit(it: *RootDirectoryEntriesIterator) void {
                if (it.current_sector_context) |*sector| {
                    sector.deinit();
                }
            }
        };

        pub const ClusterDirectoryEntriesIterator = struct {
            fat_ctx: *Self,
            current_sector_context: ?BlockReadResult,
            current_cluster: Cluster,
            current_cluster_sector: u8,
            current_sector_entry: u8,

            pub fn init(fat_ctx: *Self, cluster: Cluster) ClusterDirectoryEntriesIterator {
                return ClusterDirectoryEntriesIterator{
                    .fat_ctx = fat_ctx,
                    .current_sector_context = null,
                    .current_cluster = cluster,
                    .current_cluster_sector = 0,
                    .current_sector_entry = 0,
                };
            }

            pub fn next(it: *ClusterDirectoryEntriesIterator, blk: *BlockDevice) !?DirectoryEntry {
                const fat_ctx = it.fat_ctx;
                const sectors_per_cluster = (@as(u8, 1) << fat_ctx.misc.sectors_per_cluster);
                const directory_entries_per_sector = @as(usize, 1) << fat_ctx.misc.directory_entries_per_sector;

                if (it.current_sector_context == null) {
                    it.current_sector_context = try blk.read(fat_ctx.cluster2Sector(it.current_cluster));
                }

                while (true) {
                    while (it.current_cluster_sector < sectors_per_cluster) {
                        while (it.current_sector_entry < directory_entries_per_sector) {
                            const directories: []const DirectoryEntry = @alignCast(std.mem.bytesAsSlice(DirectoryEntry, it.current_sector_context.?.getData()));
                            const current_directory: DirectoryEntry = directories[it.current_sector_entry];

                            if (current_directory.isFirstEmptyEntry()) {
                                return null;
                            }

                            it.current_sector_entry += 1;
                            if (current_directory.isDeleted()) {
                                continue;
                            }

                            return current_directory;
                        }

                        it.current_cluster_sector += 1;
                        it.current_sector_entry = 0;

                        it.current_sector_context.?.deinit();
                        if (it.current_cluster_sector >= sectors_per_cluster) {
                            break;
                        }

                        it.current_sector_context = try blk.read(fat_ctx.cluster2Sector(it.current_cluster) + it.current_cluster_sector);
                    }

                    if (try fat_ctx.nextCluster(blk, it.current_cluster)) |next_cluster| {
                        it.current_cluster = next_cluster;
                        it.current_cluster_sector = 0;
                        it.current_sector_context = try blk.read(fat_ctx.cluster2Sector(next_cluster));
                    } else {
                        return null;
                    }
                }

                return null;
            }

            pub fn deinit(it: *ClusterDirectoryEntriesIterator) void {
                if (it.current_sector_context) |*sector| {
                    sector.deinit();
                }
            }
        };

        pub const DirectoryEntriesIterator = union(enum) {
            root: RootDirectoryEntriesIterator,
            cluster: ClusterDirectoryEntriesIterator,

            pub fn next(iterator: *DirectoryEntriesIterator, blk: *BlockDevice) !?DirectoryEntry {
                return switch (iterator.*) {
                    inline else => |*it| it.next(blk),
                };
            }

            pub fn deinit(iterator: *DirectoryEntriesIterator) void {
                return switch (iterator.*) {
                    inline else => |*it| it.deinit(),
                };
            }
        };

        pub fn directoryIterator(fat_ctx: *Self, handle: Cluster) DirectoryIterator {
            if (@sizeOf(LongContext) != 0)
                @compileError("Cannot infer context " ++ @typeName(LongContext) ++ ", call directoryIteratorContext instead.");
            return fat_ctx.directoryIteratorContext(handle, undefined);
        }

        pub fn directoryIteratorContext(fat_ctx: *Self, handle: Cluster, ctx: LongContext) DirectoryIterator {
            return DirectoryIterator.initContext(fat_ctx.directoryEntryIterator(handle), ctx);
        }

        inline fn directoryEntryIterator(fat_ctx: *Self, handle: Cluster) DirectoryEntriesIterator {
            return switch (handle) {
                0x00 => fat_ctx.rootDirectoryEntryIterator(),
                else => DirectoryEntriesIterator{ .cluster = ClusterDirectoryEntriesIterator.init(fat_ctx, handle) },
            };
        }

        inline fn rootDirectoryEntryIterator(fat_ctx: *Self) DirectoryEntriesIterator {
            return switch (config.maximum_supported_type) {
                .fat32 => switch (fat_ctx.getType()) {
                    .fat32 => DirectoryEntriesIterator{ .cluster = ClusterDirectoryEntriesIterator.init(fat_ctx, fat_ctx.root_entry_data.cluster) },
                    else => DirectoryEntriesIterator{ .root = RootDirectoryEntriesIterator.init(fat_ctx) },
                },
                else => DirectoryEntriesIterator{ .root = RootDirectoryEntriesIterator.init(fat_ctx) },
            };
        }

        pub const SearchEntry = struct { attributes: Attributes, handle: Cluster, file_size: u32 };

        pub fn searchEntry(fat_ctx: *Self, blk: *BlockDevice, handle: Cluster, name: EntryName) !?SearchEntry {
            if (@sizeOf(LongContext) != 0)
                @compileError("Cannot infer context " ++ @typeName(LongContext) ++ ", call searchEntryContext instead.");
            return fat_ctx.searchEntryContext(blk, handle, name, undefined);
        }

        pub fn searchEntryContext(fat_ctx: *Self, blk: *BlockDevice, handle: Cluster, name: EntryName, ctx: LongContext) !?SearchEntry {
            var it = fat_ctx.directoryIteratorContext(handle, ctx);
            defer it.deinit();

            while (try it.next(blk)) |dirent| {
                if (config.long_filenames) |_| {
                    if (ctx.eqlIgnoreCase(dirent.name, name)) {
                        return SearchEntry{ .attributes = dirent.attributes, .handle = dirent.handle, .file_size = dirent.file_size };
                    }
                } else {
                    if (sfn.codepageEqlIgnoreCase(dirent.name, name)) {
                        return SearchEntry{ .attributes = dirent.attributes, .handle = dirent.handle, .file_size = dirent.file_size };
                    }
                }
            }

            return null;
        }

        pub const DirectoryIterator = struct {
            pub const Entry = struct {
                name: ReturnEntryName,
                attributes: Attributes,
                handle: Cluster,
                file_size: u32,
            };

            it: DirectoryEntriesIterator,
            buf: EntryNameBuffer = undefined,
            ctx: LongContext,

            pub fn initContext(it: DirectoryEntriesIterator, ctx: LongContext) DirectoryIterator {
                return DirectoryIterator{
                    .it = it,
                    .ctx = ctx,
                };
            }

            pub fn next(it: *DirectoryIterator, blk: *BlockDevice) !?Entry {
                const name_buf = &it.buf;

                next_entry: while (try it.it.next(blk)) |next_dirent| {
                    var current_entry: DirectoryEntry = next_dirent;

                    // We don't have goto's, we have to have this loop :)
                    retry_entry: while (true) {
                        if (config.long_filenames != null and current_entry.attributes.isLongName()) {
                            const lfn_entry: LongFileNameEntry = @bitCast(current_entry);

                            // This is an invalid entry, it must be the last entry
                            if (!lfn_entry.isLast()) {
                                continue :next_entry;
                            }

                            const checksum = lfn_entry.checksum;

                            var order = (lfn_entry.order & ~LongFileNameEntry.last_entry_mask) - 1;
                            var current_lfn_index = name_buf.len - 1;

                            // FIXME: Check if order fits into possible buffer, if not, truncate extra entries!
                            lfn_entry.appendLastEntryNamesReverse(name_buf, &current_lfn_index);

                            while (order > 0) : (order -= 1) {
                                if (try it.it.next(blk)) |lfn_dirent| {
                                    const next_lfn: LongFileNameEntry = @bitCast(lfn_dirent);

                                    if (next_lfn.order != order or next_lfn.checksum != checksum) {
                                        current_entry = lfn_dirent;
                                        continue :retry_entry;
                                    }

                                    next_lfn.appendEntryNamesReverse(name_buf, &current_lfn_index);
                                } else {
                                    return null;
                                }
                            }

                            const possibly_real_entry = try it.it.next(blk);

                            if (possibly_real_entry) |real_entry| {
                                if (real_entry.attributes.isLongName()) {
                                    current_entry = real_entry;
                                    continue :retry_entry;
                                }

                                const real_entry_checksum = real_entry.checksum();

                                if (checksum != real_entry_checksum) {
                                    current_entry = real_entry;
                                    continue :retry_entry;
                                }

                                if (real_entry.attributes.volume_id) {
                                    continue :next_entry;
                                }

                                return DirectoryIterator.Entry{
                                    .name = name_buf[current_lfn_index..(name_buf.len - 1) :0],
                                    .attributes = real_entry.attributes,
                                    .handle = unpackCluster(real_entry),
                                    .file_size = real_entry.file_size,
                                };
                            } else {
                                return null;
                            }
                        }

                        // Skip volume id's
                        if (current_entry.attributes.volume_id) {
                            continue :next_entry;
                        }

                        const written: usize = if (config.long_filenames) |_| it.ctx.shortFilenameToUtf16Le(name_buf, current_entry.name) else sfn.shortFilenameToCodepage(u8, name_buf, current_entry.name);

                        if (written < name_buf.len) {
                            name_buf[written] = 0;
                        }

                        return DirectoryIterator.Entry{
                            .name = name_buf[0..written :0],
                            .attributes = current_entry.attributes,
                            .handle = unpackCluster(current_entry),
                            .file_size = current_entry.file_size,
                        };
                    }
                }

                return null;
            }

            pub fn deinit(it: *DirectoryIterator) void {
                it.it.deinit();
            }
        };

        pub inline fn unpackCluster(entry: DirectoryEntry) Cluster {
            return if (config.maximum_supported_type != .fat32) @intCast(entry.first_cluster_lo) else ((@as(Cluster, entry.first_cluster_hi) << 16) | entry.first_cluster_lo);
        }

        pub inline fn cluster2Sector(fat_ctx: Self, cluster: Cluster) BlockSector {
            return @as(BlockSector, fat_ctx.data_sector_start) + (@as(BlockSector, (cluster -| 2)) << fat_ctx.misc.sectors_per_cluster);
        }

        pub fn nextCluster(fat_ctx: *Self, blk: *BlockDevice, cluster: Cluster) !?Cluster {
            return switch (try fat_ctx.readFatEntry(blk, cluster)) {
                .allocated => |next_cluster| next_cluster,
                .end_of_file => null,
                else => ClusterChainError.InvalidClusterValue,
            };
        }

        pub fn readFatEntry(fat_ctx: *Self, blk: *BlockDevice, cluster_index: Cluster) !TableEntry {
            // TODO: Caching of indices
            const fat_byte_index: usize = switch (config.maximum_supported_type) {
                .fat12 => @as(usize, cluster_index) + (cluster_index >> 1),
                .fat16 => @as(usize, cluster_index) + (cluster_index >> fat_ctx.misc.div),
                else => (@as(usize, cluster_index) + (cluster_index >> fat_ctx.misc.div)) << fat_ctx.misc.mul,
            };

            const fat_sector_index = @as(BlockSector, fat_ctx.reserved_sector_count) + (fat_byte_index >> fat_ctx.misc.bytes_per_sector);
            const bytes_per_sector_last = ((@as(usize, 1) << fat_ctx.misc.bytes_per_sector) - 1);
            const fat_sector_offset = (fat_byte_index & bytes_per_sector_last);

            return switch (fat_ctx.getType()) {
                .fat12 => e: {
                    const first_fat_sector: BlockReadResult = try blk.read(fat_sector_index);
                    defer first_fat_sector.deinit();

                    const word_value: u16 = if (fat_sector_offset == bytes_per_sector_last) v: {
                        const second_fat_sector: BlockReadResult = try blk.read(fat_sector_index + 1);
                        defer second_fat_sector.deinit();

                        break :v @as(u16, first_fat_sector.getData()[bytes_per_sector_last]) | (@as(u16, second_fat_sector.getData()[0]) << 8);
                    } else @bitCast(first_fat_sector.getData()[fat_sector_offset..][0..2].*);

                    const entry: Cluster = if ((cluster_index & 1) == 0) @intCast(word_value & 0x0FFF) else @intCast(word_value >> 4);

                    break :e switch (entry) {
                        0x000 => .free,
                        0xFF7 => .defective,
                        0xFF8...0xFFF => .end_of_file,
                        else => |v| if (v <= fat_ctx.max_cluster) .{ .allocated = v } else .reserved,
                    };
                },
                inline else => |t| if (config.maximum_supported_type == .fat12) unreachable else e: {
                    const fat_sector = try blk.read(fat_sector_index);
                    defer fat_sector.deinit();

                    break :e switch (t) {
                        .fat16 => switch (@as(u16, @bitCast(fat_sector.getData()[fat_sector_offset..][0..2]))) {
                            0x0000 => .free,
                            0xFFF7 => .defective,
                            0xFFF8...0xFFFF => .end_of_file,
                            else => |v| if (v <= fat_ctx.max_cluster) .{ .allocated = v } else .reserved,
                        },
                        .fat32 => if (config.maximum_supported_type == .fat16) unreachable else switch (@as(u32, @bitCast(fat_sector.getData()[fat_sector_offset..][0..4])) & 0x0FFFFFFF) {
                            0x0000000 => .free,
                            0xFFFFFF7 => .defective,
                            0xFFFFFF8...0xFFFFFFFF => .end_of_file,
                            else => |v| if (v <= fat_ctx.max_cluster) .{ .allocated = v } else .reserved,
                        },
                        else => unreachable,
                    };
                },
            };
        }
    };
}
