const std = @import("std");

pub const fat = @import("fat.zig");
pub const sfn = @import("sfn.zig");
pub const format = @import("format.zig");

const BiosParameterBlock = fat.BiosParameterBlock;
const ExtendedBootRecord = fat.ExtendedBootRecord;
const ExtendedBootRecord32 = fat.ExtendedBootRecord32;
const FSInfo32 = fat.FSInfo32;
const DiskAttributes = fat.Attributes;
const DiskDirectoryEntry = fat.DirectoryEntry;
const LongFileNameEntry = fat.LongFileNameEntry;

pub const Time = fat.Time;
pub const Date = fat.Date;
pub const Type = fat.Type;

// TODO: Maybe reorganize this

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
        if (left.len != right.len) return false;
        for (left, 0..) |left_c, i| {
            const right_c = right[i];

            if (left_c <= 127 and right_c <= 127) {
                if (std.ascii.toUpper(@intCast(left_c)) != std.ascii.toUpper(@intCast(right_c))) {
                    return false;
                }
            } else if (left_c != right_c) return false;
        }

        return true;
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

pub const EntryType = enum(u1) { file, directory };

pub const Attributes = packed struct(u8) {
    read_only: bool = false,
    hidden: bool = false,
    system: bool = false,
    _: u5 = 0,

    pub inline fn toDiskAttributes(attributes: Attributes, is_directory: bool) DiskAttributes {
        std.debug.assert(attributes._ == 0);
        var disk_attributes: DiskAttributes = @bitCast(attributes);
        disk_attributes.directory = is_directory;
        return disk_attributes;
    }
};

pub const CreationType = union(EntryType) {
    /// Create a file with the specified size and undefined contents. If a size of 0 is specified, no clusters will be allocated for the file.
    file: u32,

    /// Create a new directory and allocate at least N clusters to be able to hold at least the specified pre-allocated entries.
    directory: usize,
};

pub const CreationInfo = struct {
    type: CreationType,
    attributes: Attributes = std.mem.zeroes(Attributes),
    creation_time_tenth: u8 = 0,
    creation_time: Time = std.mem.zeroes(Time),
    creation_date: Date = std.mem.zeroes(Date),

    pub inline fn asDiskDirectoryEntry(info: CreationInfo, name: [sfn.len]u8, cluster: anytype, file_size: u32) DiskDirectoryEntry {
        return DiskDirectoryEntry{
            .name = name,
            .attributes = info.attributes.toDiskAttributes(info.type == .directory),
            .creation_time_tenth = info.creation_time_tenth,
            .creation_time = info.creation_time,
            .creation_date = info.creation_date,
            .last_access_date = info.creation_date,
            .first_cluster_hi = @intCast(cluster >> 16),
            .write_time = info.creation_time,
            .write_date = info.creation_date,
            .first_cluster_lo = @intCast(cluster & 0xFFFF),
            .file_size = file_size,
        };
    }
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

        pub const Cluster = fat.SuggestCluster(config.maximum_supported_type);
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

        pub const RootDirectoryData = union {
            cluster: if (config.maximum_supported_type == .fat32) Cluster else void,
            sector_info: packed struct(u16) { sectors: u16 },
        };

        pub const TableEntryType = enum { free, allocated, defective, reserved, end_of_file };
        pub const TableEntry = union(TableEntryType) {
            const end_of_file_value: Cluster = std.math.maxInt(Cluster);
            const defective_value: Cluster = std.math.maxInt(Cluster) - 8;

            free,
            allocated: Cluster,
            defective,
            reserved,
            end_of_file,

            pub inline fn fromClusterIndex(cluster_index: Cluster, max_cluster: Cluster, fat_type: Type) TableEntry {
                return switch (cluster_index) {
                    0x0 => .free,
                    else => |c| if (c <= max_cluster) .{ .allocated = c } else switch (fat_type) {
                        .fat12 => switch (c) {
                            0xFF7 => .defective,
                            0xFF8...0xFFF => .end_of_file,
                            else => .reserved,
                        },
                        .fat16 => switch (c) {
                            0xFFF7 => .defective,
                            0xFFF8...0xFFFF => .end_of_file,
                            else => .reserved,
                        },
                        .fat32 => switch (c) {
                            0xFFFFFF7 => .defective,
                            0xFFFFFF8...0xFFFFFFF => .end_of_file,
                            else => .reserved,
                        },
                    },
                };
            }

            pub inline fn asClusterIndex(entry: TableEntry) Cluster {
                return switch (entry) {
                    .free => 0x00,
                    .defective => defective_value,
                    .end_of_file => end_of_file_value,
                    .allocated => |v| v,
                    .reserved => unreachable,
                };
            }
        };

        misc: MiscData,
        root_entry_data: RootDirectoryData,
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
            const root_entries_size = root_entries * @sizeOf(DiskDirectoryEntry);
            const root_entries_sectors = (root_entries_size + (bytes_per_sector - 1)) >> bytes_per_sector_shift;

            const directory_entries_per_sector_shift: u3 = @intCast(std.math.log2(bytes_per_sector / @sizeOf(DiskDirectoryEntry)));

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

            const fat_type: Type = if (cluster_count <= fat.max_clusters.get(.fat12)) .fat12 else if (cluster_count <= fat.max_clusters.get(.fat16)) .fat16 else .fat32;

            return switch (fat_type) {
                .fat32 => if (config.maximum_supported_type != .fat32) MountError.UnsupportedFat else ctx: {
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
                            .mul = fat.mul_shift.get(.fat32),
                            .div = fat.div_shift.get(.fat32),
                            .bytes_per_sector = bytes_per_sector_shift,
                            .sectors_per_cluster = sectors_per_cluster_shift,
                            .directory_entries_per_sector = directory_entries_per_sector_shift,
                        },
                        .root_entry_data = RootDirectoryData{ .cluster = root_entry_cluster },
                        .fats = fats,
                        .fat_size = fat_size,
                        .reserved_sector_count = reserved_sector_count,
                        .data_sector_start = data_sector_start,
                        .max_cluster = max_cluster,
                    };
                },
                else => |t| if (config.maximum_supported_type == .fat12 and t == .fat16) MountError.UnsupportedFat else Self{
                    .misc = .{
                        .type = t,
                        .mul = fat.mul_shift.get(t),
                        .div = fat.div_shift.get(t),
                        .bytes_per_sector = bytes_per_sector_shift,
                        .sectors_per_cluster = sectors_per_cluster_shift,
                        .directory_entries_per_sector = directory_entries_per_sector_shift,
                    },
                    .root_entry_data = RootDirectoryData{ .sector_info = .{ .sectors = root_entries_sectors } },
                    .fats = fats,
                    .fat_size = fat_size,
                    .reserved_sector_count = reserved_sector_count,
                    .data_sector_start = data_sector_start,
                    .max_cluster = max_cluster,
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

        inline fn getRootCluster(fat_ctx: Self) Cluster {
            return if (fat_ctx.getType() == .fat32) fat_ctx.root_entry_data.cluster else 0;
        }

        const DirectoryEntrySectorLocation = struct {
            // NOTE: A long filename could span a maximum of three sectors if configured to the standard.
            pub const max_entry_sectors = ((max_file_entries + 14) / 16) + 1;

            pub const is_single_entry = max_file_entries == 1;
            pub const is_single_sector = max_entry_sectors == 1;

            pub const StackIndex = if (!is_single_sector) u8 else void;
            pub const EndIndex = if (!is_single_entry) u8 else void;

            sector_stack: [max_entry_sectors]BlockSector,
            sector_stack_current: StackIndex,
            sector_entry_start: u8,
            // NOTE: Inclusive index
            sector_entry_end: EndIndex,

            pub fn fromSingleEntry(sector: BlockSector, index: u8) DirectoryEntrySectorLocation {
                return DirectoryEntrySectorLocation{
                    .sector_stack = [_]BlockSector{sector} ++ std.mem.zeroes([max_entry_sectors - 1]BlockSector),
                    .sector_stack_current = if (!is_single_sector) 1 else undefined,
                    .sector_entry_start = index,
                    .sector_entry_end = if (!is_single_entry) index else undefined,
                };
            }

            pub inline fn getSectorStack(r: DirectoryEntrySectorLocation) []const BlockSector {
                return r.sector_stack[0..(if (max_entry_sectors > 1) r.sector_stack_current else 1)];
            }

            pub inline fn isSingleEntry(r: DirectoryEntrySectorLocation) bool {
                return if (is_single_entry) true else r.sector_entry_start == r.sector_entry_end;
            }

            pub inline fn getEnd(r: DirectoryEntrySectorLocation) u8 {
                return if (is_single_entry) r.sector_entry_start else r.sector_entry_end;
            }
        };

        pub const DirectoryEntry = struct {
            pub const MetadataUpdate = struct {
                attributes: ?Attributes = null,
                access_date: ?Date = null,
                write_time: ?Time = null,
                write_date: ?Date = null,
            };

            location: DirectoryEntrySectorLocation,
            type: EntryType,
            attributes: Attributes,
            creation_time_tenth: u8,
            creation_time: Time,
            creation_date: Date,
            last_access_date: Date,
            write_time: Time,
            write_date: Date,
            cluster: Cluster,
            file_size: u32,

            pub fn fromDiskEntry(entry: DiskDirectoryEntry, location: DirectoryEntrySectorLocation) DirectoryEntry {
                return DirectoryEntry{
                    .location = location,
                    .type = @enumFromInt(@as(u1, @bitCast(entry.attributes.directory))),
                    .attributes = @bitCast(entry.attributes),
                    .creation_time_tenth = entry.creation_time_tenth,
                    .creation_time = entry.creation_time,
                    .creation_date = entry.creation_date,
                    .last_access_date = entry.last_access_date,
                    .write_time = entry.write_time,
                    .write_date = entry.write_date,
                    .cluster = unpackCluster(entry),
                    .file_size = entry.file_size,
                };
            }

            pub fn updateMetadata(entry: *DirectoryEntry, blk: *BlockDevice, metadata: MetadataUpdate) !void {
                const sector_stack = entry.location.getSectorStack();
                const last_sector_index = sector_stack[sector_stack.len - 1];
                const last_sector = try blk.map(last_sector_index);
                defer blk.unmap(last_sector_index, last_sector);

                const directory_entries: []DiskDirectoryEntry = @alignCast(std.mem.bytesAsSlice(DiskDirectoryEntry, last_sector.asSlice()));
                const directory_entry = &directory_entries[entry.location.getEnd()];

                if (metadata.attributes) |attributes| {
                    directory_entry.attributes = attributes.toDiskAttributes(entry.type == .directory);
                    entry.attributes = attributes;
                }

                if (metadata.access_date) |access_date| {
                    directory_entry.last_access_date = access_date;
                    entry.last_access_date = access_date;
                }

                if (metadata.write_time) |write_time| {
                    directory_entry.write_time = write_time;
                    entry.write_time = write_time;
                }

                if (metadata.write_date) |write_date| {
                    directory_entry.write_date = write_date;
                    entry.write_date = write_date;
                }

                try blk.commit(last_sector_index, last_sector);
            }

            pub inline fn isShortnameOnly(entry: DirectoryEntry) bool {
                return entry.location.isSingleEntry();
            }

            pub inline fn asFile(entry: DirectoryEntry) void {
                std.debug.assert(entry.type == .file);
            }
        };

        pub const File = struct { cluster: Cluster, file_size: u32, last_loaded_cluster: Cluster, cluster_offset: usize };

        pub inline fn search(fat_ctx: *Self, blk: *BlockDevice, directory: ?DirectoryEntry, name: EntryName) !?DirectoryEntry {
            if (@sizeOf(LongContext) != 0)
                @compileError("Cannot infer context " ++ @typeName(LongContext) ++ ", call searchEntryContext instead.");
            return fat_ctx.searchContext(blk, directory, name, undefined);
        }

        pub fn searchContext(fat_ctx: *Self, blk: *BlockDevice, directory: ?DirectoryEntry, name: EntryName, ctx: LongContext) !?DirectoryEntry {
            if (config.long_filenames) |_| {
                var it = fat_ctx.directoryEntryIterator(directory);
                defer it.deinit(blk);

                while (try it.next(blk)) |it_entry| {
                    if (it_entry.lfn) |lfn| {
                        if (ctx.eql(lfn, name)) {
                            return it_entry.entry;
                        }
                    } else {
                        if (name.len > sfn.len + 1) {
                            continue;
                        }

                        var sfn_buf: [sfn.len + 1]u16 = undefined;
                        ctx.codepageToUcs2Le(&sfn_buf, it_entry.sfn);

                        if (ctx.eql(sfn_buf[0..name.len], name)) {
                            return it_entry.entry;
                        }
                    }
                }

                return null;
            } else return searchShort(fat_ctx, blk, directory);
        }

        pub fn searchShort(fat_ctx: *Self, blk: *BlockDevice, directory: ?DirectoryEntry, name: []const u8) !?DirectoryEntry {
            var it = fat_ctx.directoryEntryIterator(directory);
            defer it.deinit(blk);

            while (try it.next(blk)) |it_entry| {
                if (std.ascii.eqlIgnoreCase(it_entry.sfn, name)) {
                    return it_entry.entry;
                }
            }

            return null;
        }

        pub fn directoryEntryIterator(fat_ctx: *Self, directory: ?DirectoryEntry) DirectoryEntryIterator {
            const directory_cluster = if (directory) |entry| v: {
                std.debug.assert(entry.type == .directory);
                break :v entry.cluster;
            } else fat_ctx.getRootCluster();
            return DirectoryEntryIterator.initContext(fat_ctx.diskDirectoryEntryIterator(directory_cluster));
        }

        const DirectoryEntryIterator = struct {
            const LongEntryName = if (config.long_filenames) |_| ?[:0]const u16 else void;
            const LongEntryNameBuffer = if (config.long_filenames) |_| [config.long_filenames.?.maximum_supported_len:0]u16 else void;

            pub const Entry = struct {
                sfn: []const u8,
                lfn: LongEntryName,
                entry: DirectoryEntry,
            };

            it: DiskDirectoryEntryIterator,
            current_location: DirectoryEntrySectorLocation = undefined,
            sfn: [sfn.len + 1:0]u8 = undefined,
            lfn: LongEntryNameBuffer = undefined,

            pub inline fn initContext(it: DiskDirectoryEntryIterator) DirectoryEntryIterator {
                return DirectoryEntryIterator{ .it = it };
            }

            // TODO: What to do with invalid entries, skip them or return error?
            pub fn next(it: *DirectoryEntryIterator, blk: *BlockDevice) !?Entry {
                next_entry: while (try it.it.next(blk)) |next_dirent| {
                    var current_entry: DiskDirectoryEntry = next_dirent;

                    if (current_entry.isDeleted()) {
                        continue;
                    }

                    if (current_entry.isFirstEmptyEntry()) {
                        return null;
                    }

                    // We don't have goto's, we have to have this loop :)
                    retry_entry: while (true) {
                        it.current_location.sector_entry_start = it.it.lastSectorEntry();
                        it.current_location.sector_stack[0] = it.it.lastSector();

                        if (DirectoryEntrySectorLocation.max_entry_sectors > 1) {
                            it.current_location.sector_stack_current = 1;
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

                                    const record_stack_current = it.current_location.sector_stack_current;
                                    if (last_iterated_sector != it.current_location.sector_stack[record_stack_current - 1]) {
                                        it.current_location.sector_stack[record_stack_current] = last_iterated_sector;

                                        if (DirectoryEntrySectorLocation.max_entry_sectors > 1) {
                                            it.current_location.sector_stack_current += 1;
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

            inline fn unpackDirectoryEntry(it: *DirectoryEntryIterator, entry: DiskDirectoryEntry, lfn: LongEntryName) Entry {
                const written: usize = sfn.shortFilenameToT(u8, &it.sfn, entry.name);

                if (written < it.sfn.len) {
                    it.sfn[written] = 0;
                }

                if (max_file_entries > 1) {
                    it.current_location.sector_entry_end = it.it.lastSectorEntry();
                }

                return Entry{
                    .sfn = it.sfn[0..written :0],
                    .lfn = lfn,
                    .entry = DirectoryEntry.fromDiskEntry(entry, it.current_location),
                };
            }

            pub fn deinit(it: *DirectoryEntryIterator, blk: *BlockDevice) void {
                it.it.deinit(blk);
            }
        };

        pub fn delete(fat_ctx: *Self, blk: *BlockDevice, entry: DirectoryEntry) !void {
            if (entry.cluster != 0) {
                try fat_ctx.deleteClusterChain(blk, entry.cluster);
            }

            try fat_ctx.deleteDiskDirectoryEntries(blk, entry);
        }

        pub fn isDirectoryEmpty(fat_ctx: *Self, blk: *BlockDevice, directory: DirectoryEntry) !bool {
            std.debug.assert(directory.type == .directory);

            var it = fat_ctx.diskDirectoryEntryIterator(directory.cluster);
            defer it.deinit(blk);

            // NOTE: Should we fail only when reading?
            try expectDiskDirectoryEntry(&it, blk, DiskDirectoryEntry.dot_name);
            try expectDiskDirectoryEntry(&it, blk, DiskDirectoryEntry.dot_dot_name);

            while (try it.next(blk)) |dir| {
                if (!dir.isFree()) {
                    return false;
                }
            }

            return true;
        }

        inline fn expectDiskDirectoryEntry(it: *DiskDirectoryEntryIterator, blk: *BlockDevice, comptime name: *const [sfn.len]u8) !void {
            if (try it.next(blk)) |dir| {
                if (!std.mem.eql(u8, &dir.name, name)) {
                    return; // TODO: Error
                }

                return;
            }

            return; // TODO: Error
        }

        inline fn deleteClusterChain(fat_ctx: *Self, blk: *BlockDevice, start: Cluster) !void {
            var current = start;

            while (try fat_ctx.writeNextAllocatedCluster(blk, current, .free)) |next| {
                current = next;
            }
        }

        inline fn deleteDiskDirectoryEntries(fat_ctx: *Self, blk: *BlockDevice, entry: DirectoryEntry) !void {
            const sector_stack = entry.location.getSectorStack();

            if (sector_stack.len == 1) {
                const sector_index = sector_stack[0];
                const sector = try blk.map(sector_index);
                defer blk.unmap(sector_index, sector);

                const directories: []DiskDirectoryEntry = @alignCast(std.mem.bytesAsSlice(DiskDirectoryEntry, sector.asSlice()));
                const start = entry.location.sector_entry_start;

                if (DirectoryEntrySectorLocation.is_single_entry) {
                    directories[start].name[0] = DiskDirectoryEntry.deletion_flag;
                } else {
                    const end = entry.location.sector_entry_end + 1;

                    for (start..end) |i| {
                        directories[i].name[0] = DiskDirectoryEntry.deletion_flag;
                    }
                }

                try blk.commit(sector_index, sector);
                return;
            }

            const directory_entries_per_sector = @as(u8, 1) << fat_ctx.misc.directory_entries_per_sector;

            {
                const current_sector_index = sector_stack[0];
                try deleteSectorDirectoryEntries(blk, current_sector_index, entry.location.sector_entry_start, directory_entries_per_sector);
            }

            const full_sector_stack_end = sector_stack.len - 1;
            var current_stack_index: usize = 1;

            while (current_stack_index < full_sector_stack_end) : (current_stack_index += 1) {
                const current_sector_index = sector_stack[current_stack_index];
                try deleteSectorDirectoryEntries(blk, current_sector_index, 0, directory_entries_per_sector);
            }

            {
                const current_sector_index = sector_stack[current_stack_index];
                const end = entry.location.sector_entry_end + 1;

                try deleteSectorDirectoryEntries(blk, current_sector_index, 0, end);
            }
        }

        inline fn deleteSectorDirectoryEntries(blk: *BlockDevice, sector_index: BlockSector, start: u8, end: u8) !void {
            const sector = try blk.map(sector_index);
            defer blk.unmap(sector_index, sector);

            const directories: []DiskDirectoryEntry = @alignCast(std.mem.bytesAsSlice(DiskDirectoryEntry, sector.asSlice()));

            for (start..end) |i| {
                directories[i].name[0] = 0xE5;
            }

            try blk.commit(sector_index, sector);
        }

        pub inline fn create(fat_ctx: *Self, blk: *BlockDevice, directory: DirectoryEntry, name: EntryName, entry_info: CreationInfo) !DirectoryEntry {
            if (@sizeOf(LongContext) != 0)
                @compileError("Cannot infer context " ++ @typeName(LongContext) ++ ", call createEntryContext instead.");
            return fat_ctx.createEntryContext(blk, directory, name, entry_info, undefined);
        }

        // TODO: Maintain this bool return or return a named error?
        pub fn createContext(fat_ctx: *Self, blk: *BlockDevice, directory: DirectoryEntry, name: EntryName, entry_info: CreationInfo, ctx: LongContext) !DirectoryEntry {
            if (config.long_filenames) |_| {
                const directory_cluster = if (directory) |entry| v: {
                    std.debug.assert(entry.type == .directory);
                    break :v entry.cluster;
                } else fat_ctx.getRootCluster();

                // const needed_entries = (name.len + LongFileNameEntry.stored_name_length - 1) / LongFileNameEntry.stored_name_length;
                // TODO: This
                _ = ctx;
                _ = directory_cluster;
                unreachable;
            } else fat_ctx.createShortEntry(blk, directory, name, entry_info);
        }

        pub fn createShort(fat_ctx: *Self, blk: *BlockDevice, directory: ?DirectoryEntry, name: []const u8, info: CreationInfo) !DirectoryEntry {
            const directory_cluster = if (directory) |entry| v: {
                std.debug.assert(entry.type == .directory);
                break :v entry.cluster;
            } else fat_ctx.getRootCluster();

            var dir_it = fat_ctx.diskDirectoryEntryIterator(directory_cluster);
            defer dir_it.deinit(blk);

            var free_sector: ?BlockSector, const free_entry = while (try dir_it.next(blk)) |dirent| {
                if (dirent.isFree()) {
                    break .{ dir_it.lastSector(), dir_it.lastSectorEntry() };
                }
            } else .{ null, 0 };

            while (true) {
                if (free_sector) |free| {
                    const sector = try blk.map(free);
                    defer blk.unmap(free, sector);

                    const directory_entries: []DiskDirectoryEntry = std.mem.bytesAsSlice(DiskDirectoryEntry, sector.asSlice());

                    const allocated_cluster, const file_size = switch (info.type) {
                        .directory => |entries| v: {
                            const directory_entries_per_sector = @as(usize, 1) << fat_ctx.misc.directory_entries_per_sector;
                            const directory_entries_per_cluster = directory_entries_per_sector << fat_ctx.misc.sectors_per_cluster;

                            // NOTE: We add 2 as we must add the '.' and '..' entries.
                            const needed_clusters = ((2 + entries + directory_entries_per_cluster - 1) >> fat_ctx.misc.directory_entries_per_sector) >> fat_ctx.misc.sectors_per_cluster;
                            const first_allocated = try fat_ctx.allocateDirectoryClusters(blk, needed_clusters);
                            try fat_ctx.createDotEntries(blk, directory_cluster, first_allocated);

                            break :v .{ first_allocated, 0 };
                        },
                        .file => |size| v: {
                            const bytes_per_sector = @as(usize, 1) << fat_ctx.misc.bytes_per_sector;
                            const bytes_per_cluster = bytes_per_sector << fat_ctx.misc.sectors_per_cluster;

                            const needed_clusters = ((size + bytes_per_cluster - 1) >> fat_ctx.misc.bytes_per_sector) >> fat_ctx.misc.sectors_per_cluster;

                            if (needed_clusters == 0) {
                                break :v .{ 0, 0 };
                            }

                            const allocated_clusters = try fat_ctx.allocateClusters(blk, needed_clusters);
                            break :v .{ allocated_clusters, size };
                        },
                    };

                    directory_entries[free_entry] = info.asDiskDirectoryEntry(sfn.codepageToShortFilename(name), @as(Cluster, allocated_cluster), file_size);

                    try blk.commit(free, sector);
                    return DirectoryEntry.fromDiskEntry(directory_entries[free_entry], DirectoryEntrySectorLocation.fromSingleEntry(free, free_entry));
                }

                const last_cluster = dir_it.current_cluster;
                if (last_cluster == 0) {
                    return EntryCreationError.OutOfRootDirectoryEntries;
                }

                const newly_allocated_cluster = try fat_ctx.allocateDirectoryClusters(blk, 1);
                _ = try fat_ctx.writeFatEntry(blk, last_cluster, TableEntry.fromClusterIndex(newly_allocated_cluster, fat_ctx.max_cluster, fat_ctx.getType()));

                free_sector = fat_ctx.cluster2Sector(newly_allocated_cluster);
                // NOTE: The free entry will be at the start of the sector
            }
        }

        fn createDotEntries(fat_ctx: *Self, blk: *BlockDevice, from_cluster: Cluster, first_cluster: Cluster) !void {
            const sector_index = fat_ctx.cluster2Sector(first_cluster);
            const sector = try blk.map(sector_index);
            defer blk.unmap(sector_index, sector);

            const directory_entries: []DiskDirectoryEntry = std.mem.bytesAsSlice(DiskDirectoryEntry, sector.asSlice());

            @memset(directory_entries[0..2], std.mem.zeroes(DiskDirectoryEntry));
            directory_entries[0].name = DiskDirectoryEntry.dot_name.*;
            directory_entries[0].attributes.directory = true;
            directory_entries[0].first_cluster_hi = @intCast(first_cluster >> 16);
            directory_entries[0].first_cluster_lo = @intCast(first_cluster & 0xFFFF);
            directory_entries[1].name = DiskDirectoryEntry.dot_dot_name.*;
            directory_entries[1].attributes.directory = true;
            directory_entries[1].first_cluster_hi = @intCast(from_cluster >> 16);
            directory_entries[1].first_cluster_lo = @intCast(from_cluster & 0xFFFF);
            try blk.commit(sector_index, sector);
        }

        fn allocateDirectoryClusters(fat_ctx: *Self, blk: *BlockDevice, n: usize) !Cluster {
            const first_allocated = try fat_ctx.allocateClusters(blk, n);

            const sectors_per_cluster = (@as(u8, 1) << fat_ctx.misc.sectors_per_cluster);
            const directory_entries_per_sector = @as(usize, 1) << fat_ctx.misc.directory_entries_per_sector;

            var current_cluster = first_allocated;
            while (true) {
                const initial_sector_index = fat_ctx.cluster2Sector(current_cluster);

                for (0..sectors_per_cluster) |i| {
                    const sector_index = initial_sector_index + i;
                    const sector = try blk.map(sector_index);
                    defer blk.unmap(sector_index, sector);

                    const directories: []DiskDirectoryEntry = @alignCast(std.mem.bytesAsSlice(DiskDirectoryEntry, sector.asSlice()));

                    // HACK: Is it better to memset it?
                    for (0..directory_entries_per_sector) |d| {
                        directories[d].name[0] = 0x00;
                    }

                    try blk.commit(sector_index, sector);
                }

                if (try fat_ctx.readNextAllocatedCluster(blk, current_cluster)) |next_cluster| {
                    current_cluster = next_cluster;
                    continue;
                }

                break;
            }

            return first_allocated;
        }

        fn allocateClusters(fat_ctx: *Self, blk: *BlockDevice, n: usize) !Cluster {
            std.debug.assert(n > 0);

            const first_next = try fat_ctx.searchFreeCluster(blk);

            var current_cluster = first_next;
            var current_allocated: usize = 1;
            while (current_allocated < n) : (current_allocated += 1) {
                const next_free = try fat_ctx.searchFreeCluster(blk);

                _ = try fat_ctx.writeFatEntry(blk, current_cluster, .{ .allocated = next_free });
                current_cluster = next_free;
            }

            _ = try fat_ctx.writeFatEntry(blk, current_cluster, .end_of_file);
            return first_next;
        }

        inline fn diskDirectoryEntryIterator(fat_ctx: *Self, cluster: Cluster) DiskDirectoryEntryIterator {
            return DiskDirectoryEntryIterator.init(fat_ctx, cluster);
        }

        const DiskDirectoryEntryIterator = struct {
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

            pub fn next(it: *EntriesSelf, blk: *BlockDevice) !?DiskDirectoryEntry {
                const fat_ctx = it.fat_ctx;
                const directory_entries_per_sector = @as(usize, 1) << fat_ctx.misc.directory_entries_per_sector;

                if (it.current_sector_context == null) {
                    it.current_sector_context = try blk.map(if (it.current_cluster == 0) fat_ctx.data_sector_start - fat_ctx.root_entry_data.sector_info.sectors else fat_ctx.cluster2Sector(it.current_cluster));
                }

                while (true) {
                    while (it.current_sector_entry < directory_entries_per_sector) {
                        const directories: []const DiskDirectoryEntry = @alignCast(std.mem.bytesAsSlice(DiskDirectoryEntry, it.current_sector_context.?.asSlice()));
                        const current_directory: DiskDirectoryEntry = directories[it.current_sector_entry];

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
                            if (try fat_ctx.readNextAllocatedCluster(blk, it.current_cluster)) |next_cluster| {
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

        inline fn unpackCluster(entry: DiskDirectoryEntry) Cluster {
            return if (config.maximum_supported_type != .fat32) @intCast(entry.first_cluster_lo) else ((@as(Cluster, entry.first_cluster_hi) << 16) | entry.first_cluster_lo);
        }

        inline fn cluster2Sector(fat_ctx: Self, cluster: Cluster) BlockSector {
            return @as(BlockSector, fat_ctx.data_sector_start) + (@as(BlockSector, (cluster -| 2)) << fat_ctx.misc.sectors_per_cluster);
        }

        // TODO: Cache last free cluster and deleted clusters in FAT32
        inline fn searchFreeCluster(fat_ctx: *Self, blk: *BlockDevice) !Cluster {
            return fat_ctx.linearSearchFreeCluster(blk, 2);
        }

        fn linearSearchFreeCluster(fat_ctx: *Self, blk: *BlockDevice, start: Cluster) !Cluster {
            var currentCluster: Cluster = start;
            return e: while (currentCluster <= fat_ctx.max_cluster) : (currentCluster += 1) {
                switch (try fat_ctx.readFatEntry(blk, currentCluster)) {
                    .free => break :e currentCluster,
                    else => {},
                }
            } else ClusterError.OutOfClusters;
        }

        inline fn readNextAllocatedCluster(fat_ctx: *Self, blk: *BlockDevice, cluster_index: Cluster) !?Cluster {
            return fat_ctx.queryNextAllocatedCluster(blk, cluster_index, .read, undefined);
        }

        inline fn writeNextAllocatedCluster(fat_ctx: *Self, blk: *BlockDevice, cluster_index: Cluster, value: TableEntry) !?Cluster {
            return fat_ctx.queryNextAllocatedCluster(blk, cluster_index, .write, value);
        }

        inline fn readFatEntry(fat_ctx: *Self, blk: *BlockDevice, cluster_index: Cluster) !TableEntry {
            return fat_ctx.queryFatEntry(blk, cluster_index, .read, undefined);
        }

        inline fn writeFatEntry(fat_ctx: *Self, blk: *BlockDevice, cluster_index: Cluster, value: TableEntry) !TableEntry {
            return fat_ctx.queryFatEntry(blk, cluster_index, .write, value);
        }

        const FatQuery = enum(u1) { read, write };

        inline fn queryNextAllocatedCluster(fat_ctx: *Self, blk: *BlockDevice, cluster: Cluster, comptime query: FatQuery, value: (if (query == .write) TableEntry else void)) !?Cluster {
            return switch (try fat_ctx.queryFatEntry(blk, cluster, query, value)) {
                .allocated => |next_cluster| next_cluster,
                .end_of_file => null,
                else => ClusterError.InvalidClusterValue,
            };
        }

        // TODO: Query the other FAT's when needed
        fn queryFatEntry(fat_ctx: *Self, blk: *BlockDevice, cluster_index: Cluster, comptime query: FatQuery, value: (if (query == .write) TableEntry else void)) !TableEntry {
            std.debug.assert(cluster_index <= fat_ctx.max_cluster);

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
                                .write => {
                                    const cluster = value.asClusterIndex();

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
                                .write => {
                                    const cluster = value.asClusterIndex();

                                    first_bytes[bytes_per_sector_last] = @intCast((first_byte & 0x0F) | (@as(u8, @intCast(cluster & 0x0F)) << 4));
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
                                .write => {
                                    entry_ptr.* = @intCast(last_entry & 0xF000 | (value.asClusterIndex() & 0xFFF));
                                    try blk.commit(fat_sector_index, first_fat_sector);
                                },
                            }
                            break :v @intCast(last_entry & 0x0FFF);
                        } else {
                            const last_entry = entry_ptr.*;

                            switch (query) {
                                .read => {},
                                .write => {
                                    entry_ptr.* = @intCast((last_entry & 0x000F) | (@as(u16, @intCast(value.asClusterIndex() & 0xFFF)) << 4));
                                    try blk.commit(fat_sector_index, first_fat_sector);
                                },
                            }
                            break :v @intCast(last_entry >> 4);
                        }
                    };

                    break :e TableEntry.fromClusterIndex(entry, fat_ctx.max_cluster, .fat12);
                },
                inline else => |t| if (config.maximum_supported_type == .fat12) unreachable else e: {
                    const fat_sector = try blk.map(fat_sector_index);
                    defer blk.unmap(fat_sector_index, fat_sector);

                    break :e switch (t) {
                        .fat16 => {
                            const entry_ptr: *u16 = @alignCast(@ptrCast(fat_sector.asSlice()[fat_sector_offset..][0..2]));
                            const last_entry = entry_ptr.*;

                            switch (query) {
                                .read => {},
                                .write => {
                                    entry_ptr.* = @intCast(value.asClusterIndex() & 0xFFFF);
                                    try blk.commit(fat_sector_index, fat_sector);
                                },
                            }

                            break :e TableEntry.fromClusterIndex(last_entry, fat_ctx.max_cluster, .fat16);
                        },
                        .fat32 => if (config.maximum_supported_type == .fat16) unreachable else {
                            const entry_ptr: *u32 = @alignCast(@ptrCast(fat_sector.asSlice()[fat_sector_offset..][0..4]));
                            const last_entry = entry_ptr.*;

                            switch (query) {
                                .read => {},
                                .write => {
                                    entry_ptr.* = ((last_entry & 0xF0000000) | (value.asClusterIndex() & 0x0FFFFFFF));
                                    try blk.commit(fat_sector_index, fat_sector);
                                },
                            }

                            break :e TableEntry.fromClusterIndex(last_entry, fat_ctx.max_cluster, .fat32);
                        },
                        else => unreachable,
                    };
                },
            };
        }
    };
}

test {
    _ = format;
}
