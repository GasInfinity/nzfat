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
    /// Invalid jump code, it must be 0xEB or 0xE9
    InvalidJump,
    /// Invalid bytes per sector, it must be 512 or 4096
    InvalidBytesPerSector,
    /// Invalid sectors per cluster, it must be non-zero and a power of two
    InvalidSectorsPerCluster,
    /// Invalid reserved sector count, it must be non-zero
    InvalidReservedSectorCount,
    /// Invalid media type, it must be one of these values: 0xF0, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF
    InvalidMediaType,
    /// Invalid FAT size, it must be non-zero
    InvalidFatSize,
    /// Invalid sector count, it must be non-zero
    InvalidSectorCount,
    /// Invalid root entry count in FAT12/16 filesystem.
    InvalidRootEntries,
    /// Invalid boot signature in the bios parameter block, it must be 0x55AA
    InvalidBootSignature,
    /// Invalid boot sector in the EBPB of a FAT32 filesystem, it must be 6.
    InvalidBackupSector,
    /// Trying to mount an unsupported higher bit count FAT filesystem.
    UnsupportedFat,
};

pub const DefaultLongContext = struct {
    pub fn codepageToUcs2Le(_: DefaultLongContext, ucs2: *[sfn.len + 1]u16, codepage: []const u8) void {
        return sfn.asciiToUcs2Le(ucs2, codepage);
    }

    pub fn ucs2LeToCodepage(_: DefaultLongContext, _: *[sfn.len]u8, _: []const u16) bool {
        // TODO: This will be used when creating directories with long filenames
        unreachable;
    }

    pub fn eql(_: DefaultLongContext, left: []const u16, right: []const u16) bool {
        return std.mem.eql(u16, left, right);
    }
};

// TODO: Different caching options and FAT mirroring support
/// The cache strategy for the primary File Allocation Table
pub const CacheStrategy = enum {
    /// The primary FAT won't be cached, every read and write will be directed to the BlockDevice directly
    none,
};

pub const Config = struct {
    pub const LongFilenameConfig = struct {
        /// Maximum supported length for VFAT long filenames, TODO: What to do when the filesystem contains longer names?
        maximum_supported_len: u8 = 255,
        /// The context used to convert between short filenames to long and viceversa. Also needed for UCS-2 case-insensitive comparison.
        /// The default context does compares strings as ASCII ignoring case and converts UCS-2 to ASCII when converting to the drive codepage.
        context: type = DefaultLongContext,
    };

    /// The maximum supported FAT of the FatFilesystem, affects code size.
    maximum_supported_type: Type = .fat32,

    /// Whether the FatFilesystem supports the VFAT extension for long filenames, affects code size greatly.
    long_filenames: ?LongFilenameConfig = LongFilenameConfig{},

    /// The cache strategy for the FAT
    cache: CacheStrategy = .none,
};

pub const EntryType = enum { file, directory };

pub const EntryCreationType = union(EntryType) {
    /// Create a file with the specified size and undefined contents. If a size of 0 is specified, no clusters will be allocated for the file.
    file: u32,

    /// Create a new directory and allocate at least N clusters to be able to hold at least the specified pre-allocated entries.
    directory: usize,
};

pub const ClusterError = error{ InvalidClusterValue, OutOfClusters };
pub const EntryCreationError = error{OutOfRootDirectoryEntries};
pub const EntryDeletionError = error{NonEmptyDirectory};

const MiscData = packed struct(u16) { type: Type, mul: u1, div: u1, bytes_per_sector: u4, sectors_per_cluster: u3, directory_entries_per_sector: u3, _: u2 = 0 };
const allowed_media_values = [_]u8{ 0xF0, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF };

/// Implements a FAT Filesystem as specified in official documentation with support for its VFAT extension.
/// TODO: Implement NT flags for short filenames with mixed casing
pub fn FatFilesystem(comptime BlockDevice: type, comptime config: Config) type {
    return struct {
        const Self = @This();

        const BlockSector = BlockDevice.Sector;
        const BlockSectorResult = BlockDevice.SectorResult;

        pub const Cluster = switch (config.maximum_supported_type) {
            .fat32 => u32,
            .fat16 => u16,
            .fat12 => u12,
        };

        pub const FatSize = switch (config.maximum_supported_type) {
            .fat32 => u32,
            else => u16,
        };

        pub const EntryName = if (config.long_filenames) |_| []const u16 else []const u8;

        // +1 for dot
        const LongCodepageConversionBuffer = if (config.long_filenames) |_| [sfn.len + 1:0]u8 else void;
        const LongSfnConversionBuffer = if (config.long_filenames) |_| [sfn.len:0]u8 else void;
        const LongContext = if (config.long_filenames) |long_config| long_config.context else void;

        const max_long_filename_entries = if (config.long_filenames) |long_config| ((@as(usize, long_config.maximum_supported_len) + LongFileNameEntry.stored_name_length - 1) / LongFileNameEntry.stored_name_length) else 0;
        const max_file_entries = max_long_filename_entries + 1;

        const max_first_long_filename_name_len = if (config.long_filenames) |long_config| (@as(usize, long_config.maximum_supported_len) + LongFileNameEntry.stored_name_length - 1) % LongFileNameEntry.stored_name_length else 0;

        pub const RootDirectoryEntryData = union {
            cluster: if (config.maximum_supported_type == .fat32) Cluster else void,
            sector_info: packed struct(u16) { sectors: u16 },
        };

        pub const TableEntryType = enum { free, allocated, defective, reserved, end_of_file };
        pub const TableEntry = union(TableEntryType) { free, allocated: Cluster, defective, reserved, end_of_file };

        misc: MiscData,
        root_entry_data: RootDirectoryEntryData,
        reserved_sector_count: u16,
        fats: u8,
        fat_size: FatSize,
        data_sector_start: u32,
        max_cluster: Cluster,

        // HACK: Validate informational-only filesys_type
        pub fn mount(blk: *BlockDevice) !Self {
            const first_sector: BlockSectorResult = try blk.map(0);
            defer blk.unmap(0, first_sector);

            const first_sector_data = first_sector.asSlice();
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

        pub fn unmount(fat_ctx: *Self, blk: *BlockDevice) !void {
            _ = fat_ctx;
            _ = blk;
        }

        pub inline fn getType(fat_ctx: Self) Type {
            return if (config.maximum_supported_type == .fat12) .fat12 else fat_ctx.misc.type;
        }

        pub inline fn getRoot(fat_ctx: Self) Cluster {
            return if (fat_ctx.getType() == .fat32) fat_ctx.root_entry_data.cluster else 0;
        }

        pub const SearchResult = struct {
            record: DirectoryIterator.RecordedEntry,
            attributes: Attributes,
            cluster: Cluster,
            file_size: u32,
        };

        pub fn searchEntry(fat_ctx: *Self, blk: *BlockDevice, cluster: Cluster, name: EntryName) !?SearchResult {
            if (@sizeOf(LongContext) != 0)
                @compileError("Cannot infer context " ++ @typeName(LongContext) ++ ", call searchEntryContext instead.");
            return fat_ctx.searchEntryContext(blk, cluster, name, undefined);
        }

        pub fn searchEntryContext(fat_ctx: *Self, blk: *BlockDevice, cluster: Cluster, name: EntryName, ctx: LongContext) !?SearchResult {
            if (config.long_filenames) |_| {
                var it = fat_ctx.directoryIterator(cluster);
                defer it.deinit(blk);

                while (try it.next(blk)) |dirent| {
                    if (dirent.lfn) |lfn| {
                        if (ctx.eql(lfn, name)) {
                            return SearchResult{
                                .record = dirent.record,
                                .attributes = dirent.attributes,
                                .cluster = dirent.cluster,
                                .file_size = dirent.file_size,
                            };
                        }
                    } else {
                        if (name.len > sfn.len + 1) {
                            continue;
                        }

                        var sfn_buf: [sfn.len + 1]u16 = undefined;
                        ctx.codepageToUcs2Le(&sfn_buf, dirent.sfn);

                        if (ctx.eql(sfn_buf[0..name.len], name)) {
                            return SearchResult{
                                .record = dirent.record,
                                .attributes = dirent.attributes,
                                .cluster = dirent.cluster,
                                .file_size = dirent.file_size,
                            };
                        }
                    }
                }

                return null;
            } else return searchShortEntry(fat_ctx, blk, cluster);
        }
        pub fn searchShortEntry(fat_ctx: *Self, blk: *BlockDevice, cluster: Cluster, name: []const u8) !?SearchResult {
            var it = fat_ctx.directoryIterator(cluster);
            defer it.deinit(blk);

            while (try it.next(blk)) |dirent| {
                if (std.ascii.eqlIgnoreCase(dirent.sfn, name)) {
                    return SearchResult{
                        .record = dirent.record,
                        .attributes = dirent.attributes,
                        .cluster = dirent.cluster,
                        .file_size = dirent.file_size,
                    };
                }
            }

            return null;
        }

        pub fn directoryIterator(fat_ctx: *Self, target: Cluster) DirectoryIterator {
            return DirectoryIterator.initContext(fat_ctx.directoryEntryIterator(target));
        }

        const DirectoryIterator = struct {
            const SelfIterator = @This();

            const LongEntryName = if (config.long_filenames) |_| ?[:0]const u16 else void;
            const LongEntryNameBuffer = if (config.long_filenames) |_| [config.long_filenames.?.maximum_supported_len:0]u16 else void;

            // NOTE: A long filename could span a maximum of three sectors if configured to the standard.
            const max_recorded_sectors = ((max_file_entries + 14) / 16) + 1;
            const StackIndex = if (max_recorded_sectors > 1) u8 else void;
            const RecordEndIndex = if (max_file_entries > 1) u8 else void;

            const RecordedEntry = struct {
                pub const is_single_entry = max_file_entries == 1;

                sector_stack: [max_recorded_sectors]BlockSector,
                sector_stack_current: StackIndex,
                sector_entry_start: u8,
                sector_entry_end: RecordEndIndex,

                pub inline fn getSectorStack(r: RecordedEntry) []const BlockSector {
                    return r.sector_stack[0..(if (max_recorded_sectors > 1) r.sector_stack_current else 1)];
                }
            };

            pub const Entry = struct {
                record: RecordedEntry,
                sfn: []const u8,
                lfn: LongEntryName,
                attributes: Attributes,
                cluster: Cluster,
                file_size: u32,
            };

            it: DirectoryEntriesIterator,
            record: RecordedEntry = undefined,
            sfn: [sfn.len + 1:0]u8 = undefined,
            lfn: LongEntryNameBuffer = undefined,

            pub fn initContext(it: DirectoryEntriesIterator) SelfIterator {
                return SelfIterator{ .it = it };
            }

            inline fn unpackDirectoryEntry(it: *SelfIterator, entry: DirectoryEntry, lfn: LongEntryName) Entry {
                const written: usize = sfn.shortFilenameToT(u8, &it.sfn, entry.name);

                if (written < it.sfn.len) {
                    it.sfn[written] = 0;
                }

                const cluster = unpackCluster(entry);

                if (max_file_entries > 1) {
                    it.record.sector_entry_end = it.it.lastSectorEntry();
                }

                return Entry{
                    .record = it.record,
                    .sfn = it.sfn[0..written :0],
                    .lfn = lfn,
                    .attributes = entry.attributes,
                    .cluster = cluster,
                    .file_size = entry.file_size,
                };
            }

            // TODO: What to do with invalid entries, skip them or return error?
            pub fn next(it: *SelfIterator, blk: *BlockDevice) !?Entry {
                next_entry: while (try it.it.next(blk)) |next_dirent| {
                    var current_entry: DirectoryEntry = next_dirent;

                    if (current_entry.isDeleted()) {
                        continue;
                    }

                    if (current_entry.isFirstEmptyEntry()) {
                        return null;
                    }

                    // We don't have goto's, we have to have this loop :)
                    retry_entry: while (true) {
                        it.record.sector_entry_start = it.it.lastSectorEntry();
                        it.record.sector_stack[0] = it.it.lastSector();

                        if (max_recorded_sectors > 1) {
                            it.record.sector_stack_current = 1;
                        }

                        if (config.long_filenames != null and current_entry.attributes.isLongName()) {
                            const lfn = &it.lfn;
                            const lfn_entry: LongFileNameEntry = @bitCast(current_entry);

                            // This is an invalid entry, it must be the last entry
                            if (!lfn_entry.isLast()) {
                                continue :next_entry;
                            }

                            const checksum = lfn_entry.checksum;

                            var order = (lfn_entry.order & ~LongFileNameEntry.last_entry_mask) - 1;
                            const lfn_index_end = lfn.len - 1;
                            var current_lfn_index = lfn_index_end;

                            // TODO: This will overflow, atm we'll skip them but should we truncate or throw an error? Same below
                            if (order > max_long_filename_entries) {
                                continue :next_entry;
                            }

                            // FIXME: This will overflow with a config that only supports 1 lfn entry
                            lfn_entry.appendLastEntryNamesReverse(lfn, &current_lfn_index);
                            if (order == max_long_filename_entries and (lfn_index_end - current_lfn_index) > max_first_long_filename_name_len) {
                                continue :next_entry;
                            }

                            while (order > 0) : (order -= 1) {
                                if (try it.it.next(blk)) |lfn_dirent| {
                                    if (lfn_dirent.isDeleted()) {
                                        continue :next_entry;
                                    }

                                    if (lfn_dirent.isFirstEmptyEntry()) {
                                        return null;
                                    }

                                    const next_lfn: LongFileNameEntry = @bitCast(lfn_dirent);

                                    if (next_lfn.order != order or next_lfn.checksum != checksum) {
                                        current_entry = lfn_dirent;
                                        continue :retry_entry;
                                    }

                                    const last_iterated_sector = it.it.lastSector();

                                    const record_stack_current = it.record.sector_stack_current;
                                    if (last_iterated_sector != it.record.sector_stack[record_stack_current - 1]) {
                                        it.record.sector_stack[record_stack_current] = last_iterated_sector;

                                        if (max_recorded_sectors > 1) {
                                            it.record.sector_stack_current += 1;
                                        }
                                    }

                                    next_lfn.appendEntryNamesReverse(lfn, &current_lfn_index);
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

                                return it.unpackDirectoryEntry(real_entry, lfn[current_lfn_index..(lfn.len - 1) :0]);
                            } else {
                                return null;
                            }
                        }

                        // Skip volume id's
                        if (current_entry.attributes.volume_id) {
                            continue :next_entry;
                        }

                        return it.unpackDirectoryEntry(current_entry, if (config.long_filenames) |_| null else undefined);
                    }
                }

                return null;
            }

            pub fn deinit(it: *SelfIterator, blk: *BlockDevice) void {
                it.it.deinit(blk);
            }
        };

        pub fn deleteEntry(fat_ctx: *Self, blk: *BlockDevice, entry: SearchResult) !void {
            if (entry.cluster != 0x00) {
                try fat_ctx.deleteClusterChain(blk, entry.cluster);
            }

            try fat_ctx.deleteDirectoryEntries(blk, entry);
        }

        pub inline fn isDirectoryEmpty(fat_ctx: *Self, blk: *BlockDevice, cluster: Cluster) !bool {
            var it = fat_ctx.directoryIterator(cluster);
            defer it.deinit(blk);

            const first_entry = try it.next(blk);
            if (first_entry) |dir| {
                if (!std.mem.eql(u8, dir.sfn, ".          ")) {
                    return false;
                }
            } else { // TODO: Error? The entry must be present
                return false;
            }

            const second_entry = try it.next(blk);
            if (second_entry) |dir| {
                if (!std.mem.eql(u8, dir.sfn, "..         ")) {
                    return false;
                }
            } else { // TODO: Error? The entry must be present
                return false;
            }

            return try it.next(blk) == null;
        }

        inline fn deleteClusterChain(fat_ctx: *Self, blk: *BlockDevice, start: Cluster) !void {
            var current = start;

            while (try fat_ctx.nextAllocatedCluster(blk, current, .{ .write = 0x00 })) |next| {
                current = next;
            }
        }

        inline fn deleteDirectoryEntries(fat_ctx: *Self, blk: *BlockDevice, entry: SearchResult) !void {
            const sector_stack = entry.record.getSectorStack();

            if (sector_stack.len == 1) {
                const sector_index = sector_stack[0];
                const sector = try blk.map(sector_index);
                defer blk.unmap(sector_index, sector);

                const directories: []DirectoryEntry = @alignCast(std.mem.bytesAsSlice(DirectoryEntry, sector.asSlice()));
                const start = entry.record.sector_entry_start;

                if (DirectoryIterator.RecordedEntry.is_single_entry) {
                    directories[start].name[0] = 0xE5;
                } else {
                    const end = entry.record.sector_entry_end + 1; // The end in the record is inclusive

                    for (start..end) |i| {
                        directories[i].name[0] = 0xE5;
                    }
                }

                try blk.commit(sector_index, sector);
                return;
            }

            const directory_entries_per_sector = @as(u8, 1) << fat_ctx.misc.directory_entries_per_sector;

            {
                const current_sector_index = sector_stack[0];
                try deleteSectorDirectoryEntries(blk, current_sector_index, entry.record.sector_entry_start, directory_entries_per_sector);
            }

            const full_sector_stack_end = sector_stack.len - 1;
            var current_stack_index: usize = 1;

            while (current_stack_index < full_sector_stack_end) : (current_stack_index += 1) {
                const current_sector_index = sector_stack[current_stack_index];
                try deleteSectorDirectoryEntries(blk, current_sector_index, 0, directory_entries_per_sector);
            }

            {
                const current_sector_index = sector_stack[current_stack_index];
                const end = entry.record.sector_entry_end + 1; // The end in the record is inclusive

                try deleteSectorDirectoryEntries(blk, current_sector_index, 0, end);
            }
        }

        inline fn deleteSectorDirectoryEntries(blk: *BlockDevice, sector_index: BlockSector, start: u8, end: u8) !void {
            const sector = try blk.map(sector_index);
            defer blk.unmap(sector_index, sector);

            const directories: []DirectoryEntry = @alignCast(std.mem.bytesAsSlice(DirectoryEntry, sector.asSlice()));

            for (start..end) |i| {
                directories[i].name[0] = 0xE5;
            }

            try blk.commit(sector_index, sector);
        }

        pub fn createShortEntry(fat_ctx: *Self, blk: *BlockDevice, cluster: Cluster, name: []const u8, entry: EntryCreationType) !void {
            var dir_it = fat_ctx.directoryEntryIterator(cluster);
            defer dir_it.deinit(blk);

            _ = entry;
            const FreeSingleEntryData = struct { free_sector: BlockSector, free_entry: u8 };
            const maybe_free: ?FreeSingleEntryData = while (try dir_it.next(blk)) |dirent| {
                if (dirent.isFree()) {
                    break FreeSingleEntryData{ .free_sector = dir_it.lastSector(), .free_entry = dir_it.lastSectorEntry() };
                }
            } else null;

            if (maybe_free) |free| {
                const sector = try blk.map(free.free_sector);
                defer blk.unmap(free.free_sector, sector);

                const directory_entries: []DirectoryEntry = std.mem.bytesAsSlice(DirectoryEntry, sector.asSlice());

                directory_entries[free.free_entry] = std.mem.zeroes(DirectoryEntry);
                directory_entries[free.free_entry].name = sfn.codepageToShortFilename(name);
                directory_entries[free.free_entry].file_size = 0;

                try blk.commit(free.free_sector, sector);
                return;
            }

            if (dir_it.current_cluster == 0) {
                return EntryCreationError.OutOfRootDirectoryEntries;
            }

            // TODO: Find next empty and grow cluster chain
            unreachable;
        }

        pub fn createEntry(fat_ctx: *Self, blk: *BlockDevice, target: Cluster, name: EntryName, entry: EntryCreationType) !void {
            if (@sizeOf(LongContext) != 0)
                @compileError("Cannot infer context " ++ @typeName(LongContext) ++ ", call createDirectoryEntryContext instead.");
            return fat_ctx.createDirectoryEntryContext(blk, target, name, entry, undefined);
        }

        // TODO: Maintain this bool return or return a named error?
        pub fn createEntryContext(fat_ctx: *Self, blk: *BlockDevice, target: Cluster, name: EntryName, entry: EntryCreationType, ctx: LongContext) !void {
            if (config.long_filenames) |_| {
                // TODO
                var dir_it = fat_ctx.directoryEntryIterator(.{ .skip_empty = false }, target);
                defer dir_it.deinit(blk);

                var longname_converted: LongCodepageConversionBuffer = undefined;
                const needs_long_name = if (config.long_filenames) |_| ctx.ucs2LeToCodepage(&longname_converted, name) and name.len <= (sfn.len + 1) else false;

                const needed_entries = if (needs_long_name) 1 else 1;

                switch (dir_it) {
                    .root => |r| {
                        var free_sector_end: u8 = 0;
                        var free_sector_entry_end: u8 = 0;
                        var current_free_sequential_entries: u8 = 0;

                        while (try r.next(blk)) |dirent| {
                            free_sector_end = r.current_sector;
                            free_sector_entry_end = r.current_sector_entry - 1;
                            current_free_sequential_entries = if (dirent.isFree()) current_free_sequential_entries + 1 else 0;

                            if (current_free_sequential_entries >= needed_entries) {
                                break;
                            }
                        }

                        if (current_free_sequential_entries < needed_entries) {
                            return false;
                        }

                        const last_sector = r.current_sector_context;
                        const last_sector_data = last_sector.asSlice();
                        const last_sector_entries: []DirectoryEntry = @alignCast(std.mem.bytesAsSlice(DirectoryEntry, last_sector_data));

                        last_sector_entries[free_sector_entry_end] = DirectoryEntry{};

                        return true;
                    },
                    .cluster => |_| {
                        unreachable; // TODO
                    },
                }
            } else fat_ctx.createShortEntry(blk, target, name, entry);
        }

        inline fn directoryEntryIterator(fat_ctx: *Self, cluster: Cluster) DirectoryEntriesIterator {
            return DirectoryEntriesIterator.init(fat_ctx, cluster);
        }

        const DirectoryEntriesIterator = struct {
            const EntriesSelf = @This();

            fat_ctx: *Self,
            current_sector_context: ?BlockSectorResult,
            current_cluster: Cluster,
            current_sector: u8,
            current_sector_entry: u8,

            pub fn init(fat_ctx: *Self, cluster: Cluster) EntriesSelf {
                return EntriesSelf{
                    .fat_ctx = fat_ctx,
                    .current_sector_context = null,
                    .current_cluster = cluster,
                    .current_sector = 0,
                    .current_sector_entry = 0,
                };
            }

            pub fn next(it: *EntriesSelf, blk: *BlockDevice) !?DirectoryEntry {
                const fat_ctx = it.fat_ctx;
                const directory_entries_per_sector = @as(usize, 1) << fat_ctx.misc.directory_entries_per_sector;

                if (it.current_sector_context == null) {
                    it.current_sector_context = try blk.map(if (it.current_cluster == 0) fat_ctx.data_sector_start - fat_ctx.root_entry_data.sector_info.sectors else fat_ctx.cluster2Sector(it.current_cluster));
                }

                while (true) {
                    while (it.current_sector_entry < directory_entries_per_sector) {
                        const directories: []const DirectoryEntry = @alignCast(std.mem.bytesAsSlice(DirectoryEntry, it.current_sector_context.?.asSlice()));
                        const current_directory: DirectoryEntry = directories[it.current_sector_entry];

                        it.current_sector_entry += 1;
                        return current_directory;
                    }

                    if (it.current_cluster == 0) {
                        const root_directories_start: BlockSector = fat_ctx.data_sector_start - fat_ctx.root_entry_data.sector_info.sectors;

                        blk.unmap(root_directories_start + it.current_sector, it.current_sector_context.?);
                        it.current_sector_context = null;

                        if (it.current_sector >= fat_ctx.root_entry_data.sector_info.sectors) {
                            return null;
                        }

                        it.current_sector_entry = 0;
                        it.current_sector += 1;
                        it.current_sector_context = try blk.map(root_directories_start + it.current_sector);
                    } else {
                        const sectors_per_cluster = (@as(u8, 1) << fat_ctx.misc.sectors_per_cluster);
                        const current_cluster_sector = fat_ctx.cluster2Sector(it.current_cluster);

                        blk.unmap(current_cluster_sector + it.current_sector, it.current_sector_context.?);
                        it.current_sector_context = null;

                        if (it.current_sector >= sectors_per_cluster) {
                            if (try fat_ctx.nextAllocatedCluster(blk, it.current_cluster, .read)) |next_cluster| {
                                it.current_cluster = next_cluster;
                                it.current_sector = 0;
                                it.current_sector_entry = 0;
                                it.current_sector_context = try blk.map(fat_ctx.cluster2Sector(next_cluster));
                                continue;
                            } else {
                                return null;
                            }
                        }

                        it.current_sector += 1;
                        it.current_sector_context = try blk.map(current_cluster_sector + it.current_sector);
                    }
                }

                return null;
            }

            pub inline fn lastSector(it: EntriesSelf) BlockSector {
                const fat_ctx = it.fat_ctx;
                return (if (it.current_cluster == 0) fat_ctx.data_sector_start - fat_ctx.root_entry_data.sector_info.sectors else fat_ctx.cluster2Sector(it.current_cluster)) + it.current_sector;
            }

            pub inline fn lastSectorEntry(it: EntriesSelf) u8 {
                return it.current_sector_entry - 1;
            }

            pub fn deinit(it: *EntriesSelf, blk: *BlockDevice) void {
                if (it.current_sector_context) |sector| {
                    blk.unmap(it.lastSector(), sector);
                }
            }
        };

        inline fn unpackCluster(entry: DirectoryEntry) Cluster {
            return if (config.maximum_supported_type != .fat32) @intCast(entry.first_cluster_lo) else ((@as(Cluster, entry.first_cluster_hi) << 16) | entry.first_cluster_lo);
        }

        pub inline fn cluster2Sector(fat_ctx: Self, cluster: Cluster) BlockSector {
            return @as(BlockSector, fat_ctx.data_sector_start) + (@as(BlockSector, (cluster -| 2)) << fat_ctx.misc.sectors_per_cluster);
        }

        // TODO: Cache last free cluster and deleted clusters
        pub fn searchFreeCluster(fat_ctx: *Self, blk: *BlockDevice, start: Cluster) !Cluster {
            var currentCluster: Cluster = start;
            return while (currentCluster < fat_ctx.max_cluster) : (currentCluster += 1) e: {
                switch (try fat_ctx.queryFatEntry(blk, currentCluster, .read)) {
                    .free => break :e currentCluster,
                    else => {},
                }
            } else ClusterError.OutOfClusters;
        }

        pub fn nextAllocatedCluster(fat_ctx: *Self, blk: *BlockDevice, cluster: Cluster, comptime query: FatQuery) !?Cluster {
            return switch (try fat_ctx.queryFatEntry(blk, cluster, query)) {
                .allocated => |next_cluster| next_cluster,
                .end_of_file => null,
                else => |v| {
                    std.debug.print("Invalid value {}\n", .{v});
                    return ClusterError.InvalidClusterValue;
                },
            };
        }

        pub const FatQuery = union(enum) { read, write: Cluster };
        pub fn queryFatEntry(fat_ctx: *Self, blk: *BlockDevice, cluster_index: Cluster, comptime query: FatQuery) !TableEntry {
            // TODO: Cache the FAT and write entries when needed
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
                    const first_fat_sector: BlockSectorResult = try blk.map(fat_sector_index);
                    defer blk.unmap(fat_sector_index, first_fat_sector);

                    const entry: Cluster = if (fat_sector_offset == bytes_per_sector_last) v: {
                        const second_index = fat_sector_index + 1;
                        const second_fat_sector: BlockSectorResult = try blk.map(fat_sector_index + 1);
                        defer blk.unmap(second_index, second_fat_sector);

                        const first_bytes = first_fat_sector.asSlice();
                        const second_bytes = second_fat_sector.asSlice();

                        const first_byte = first_bytes[bytes_per_sector_last];
                        const second_byte = second_bytes[0];

                        if ((cluster_index & 1) == 0) {
                            switch (query) {
                                .read => {},
                                .write => |cluster| {
                                    first_bytes[bytes_per_sector_last] = @intCast(cluster & 0xFF);
                                    second_bytes[0] = @intCast((second_byte & 0xF0) | ((cluster >> 8) & 0xFF));

                                    try blk.commit(fat_sector_index, first_fat_sector);
                                    try blk.commit(second_index, second_fat_sector);
                                },
                            }

                            break :v ((@as(u12, second_byte & 0x0F) << 8) | first_byte);
                        } else {
                            switch (query) {
                                .read => {},
                                .write => |cluster| {
                                    first_bytes[bytes_per_sector_last] = @intCast((first_byte & 0x0F) | (@as(u8, cluster & 0x0F) << 4));
                                    second_bytes[0] = @intCast((cluster >> 4) & 0xFF);

                                    try blk.commit(fat_sector_index, first_fat_sector);
                                    try blk.commit(second_index, second_fat_sector);
                                },
                            }
                            break :v ((@as(u12, second_byte) << 4) | (first_byte >> 4));
                        }
                    } else v: {
                        const entry_ptr: *align(1) u16 = @ptrCast(first_fat_sector.asSlice()[fat_sector_offset..][0..2]);

                        if ((cluster_index & 1) == 0) {
                            const last_entry = entry_ptr.*;

                            switch (query) {
                                .read => {},
                                .write => |cluster| {
                                    entry_ptr.* = @intCast(last_entry & 0xF000 | (cluster & 0xFFF));
                                    try blk.commit(fat_sector_index, first_fat_sector);
                                },
                            }
                            break :v @intCast(last_entry & 0x0FFF);
                        } else {
                            const last_entry = entry_ptr.*;

                            switch (query) {
                                .read => {},
                                .write => |cluster| {
                                    entry_ptr.* = @intCast((last_entry & 0x000F) | (@as(u16, cluster & 0xFFF) << 4));
                                    try blk.commit(fat_sector_index, first_fat_sector);
                                },
                            }
                            break :v @intCast(last_entry >> 4);
                        }
                    };

                    break :e switch (entry) {
                        0x000 => .free,
                        0xFF7 => .defective,
                        0xFF8...0xFFF => .end_of_file,
                        else => |v| if (v <= fat_ctx.max_cluster) .{ .allocated = v } else .reserved,
                    };
                },
                inline else => |t| if (config.maximum_supported_type == .fat12) unreachable else e: {
                    const fat_sector = try blk.map(fat_sector_index);
                    defer blk.unmap(fat_sector_index, fat_sector);

                    break :e switch (t) {
                        .fat16 => v: {
                            const entry_ptr: *u16 = @alignCast(@ptrCast(fat_sector.asSlice()[fat_sector_offset..][0..2]));
                            const last_entry = entry_ptr.*;

                            switch (query) {
                                .read => {},
                                .write => |cluster| {
                                    entry_ptr.* = cluster;
                                    try blk.commit(fat_sector_index, fat_sector);
                                },
                            }

                            break :v switch (last_entry) {
                                0x0000 => .free,
                                0xFFF7 => .defective,
                                0xFFF8...0xFFFF => .end_of_file,
                                else => |v| if (v <= fat_ctx.max_cluster) .{ .allocated = v } else .reserved,
                            };
                        },
                        .fat32 => if (config.maximum_supported_type == .fat16) unreachable else v: {
                            const entry_ptr: *u32 = @alignCast(@ptrCast(fat_sector.asSlice()[fat_sector_offset..][0..4]));
                            const last_entry = entry_ptr.*;

                            switch (query) {
                                .read => {},
                                .write => |cluster| {
                                    entry_ptr.* = ((last_entry & 0xF0000000) | (cluster & 0x0FFFFFFF));
                                    try blk.commit(fat_sector_index, fat_sector);
                                },
                            }

                            break :v switch (last_entry) {
                                0x0000000 => .free,
                                0xFFFFFF7 => .defective,
                                0xFFFFFF8...0xFFFFFFFF => .end_of_file,
                                else => |v| if (v <= fat_ctx.max_cluster) .{ .allocated = v } else .reserved,
                            };
                        },
                        else => unreachable,
                    };
                },
            };
        }
    };
}
