pub const format = @import("format.zig");

pub const Type = fat.Type;
pub const Time = fat.Time;
pub const Date = fat.Date;
pub const ShortFilenameDisplay = fat.sfn.Display;

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
    /// Invalid root cluster in FAT32 filesystem.
    InvalidRootCluster,
    /// Invalid boot signature in the bios parameter block, it must be 0x55AA
    InvalidBootSignature,
    /// Invalid boot sector in the EBPB of a FAT32 filesystem, it must be 6.
    InvalidBackupSector,
    /// Invalid Filesystem type inside the EBR32 or EBR.
    InvalidFilesystemType,
    /// Invalid FSInfo sector in the EBR32. It must be 0 or 1.
    InvalidFSInfo,
    /// Trying to mount an unsupported higher bit count FAT filesystem.
    UnsupportedFat,
};

pub const AsciiOnlyLongContext = struct {
    pub fn utf16LeToCodepage(_: AsciiOnlyLongContext, filename: *ShortFilenameDisplay, utf16: []const u16) bool {
        const last_possible_dot = std.mem.lastIndexOf(u16, utf16, std.unicode.utf8ToUtf16LeStringLiteral("."));
        const base, const extension = if (last_possible_dot) |last_dot|
            .{ utf16[0..last_dot], utf16[(last_dot + 1)..] }
        else
            .{ utf16, &[_]u16{} };

        var lossy = false;

        const copied_base = if (base.len > fat.sfn.max_base_len) v: {
            lossy = true;
            break :v base[0..fat.sfn.max_base_len];
        } else base;

        const copied_extension = if (extension.len > fat.sfn.max_extension_len) v: {
            lossy = true;
            break :v extension[0..fat.sfn.max_extension_len];
        } else extension;

        for (copied_base) |c| {
            if (c > 127) {
                lossy = true;
                continue;
            }

            filename.appendAssumeCapacity(@intCast(c));
        }

        if (copied_extension.len > 0) {
            filename.appendAssumeCapacity('.');

            for (copied_extension) |c| {
                if (c > 127) {
                    lossy = true;
                    continue;
                }

                filename.appendAssumeCapacity(@intCast(c));
            }
        }

        return lossy;
    }

    pub fn eql(_: AsciiOnlyLongContext, left: []const u16, right: []const u16) bool {
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
        context: type = AsciiOnlyLongContext,
    };

    /// The maximum supported FAT of the FatFilesystem, affects code size.
    maximum_supported_type: Type = .fat32,

    /// The context for the stored FAT codepage
    codepage_context: type = fat.AsciiCodepageContext,

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
        var disk_attributes: DiskAttributes = @bitCast(attributes);
        disk_attributes.directory = is_directory;
        return disk_attributes;
    }
};

pub const CreationType = union(EntryType) {
    /// Create a file with the specified size and undefined contents. If a size of 0 is specified, no clusters will be allocated for the file.
    file: u32,

    /// Create a new directory and allocate at least N clusters to be able to hold at least the specified pre-allocated entries.
    directory: u16,
};

pub const CreationInfo = struct {
    type: CreationType,
    attributes: Attributes = std.mem.zeroes(Attributes),
    creation_time_tenth: u8 = 0,
    creation_time: Time = std.mem.zeroes(Time),
    creation_date: Date = std.mem.zeroes(Date),

    pub inline fn asDiskDirectoryEntry(info: CreationInfo, name: [fat.sfn.stored_len]u8, nt_flags: fat.ExtraAttributes, cluster: anytype, file_size: u32) DiskDirectoryEntry {
        return DiskDirectoryEntry{
            .name = name,
            .attributes = info.attributes.toDiskAttributes(info.type == .directory),
            .reserved = nt_flags,
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

pub const ClusterAllocationError = error{NoSpaceLeft};
pub const ClusterTraversalError = error{InvalidCluster};
pub const EntryCreationError = error{ OutOfRootDirectoryEntries, NoSpaceLeft };
pub const EntryDeletionError = error{DirectoryNotEmpty};
pub const WriteError = error{ FileTooBig, NoSpaceLeft };

const MiscData = packed struct(u16) { type: Type, mul: u1, div: u1, bytes_per_sector: u4, sectors_per_cluster: u3, directory_entries_per_sector: u3, _: u2 = 0 };

/// Implements a FAT Filesystem as specified in official documentation with support for its VFAT extension.
pub fn FatFilesystem(comptime BlockDevice: type, comptime config: Config) type {
    return struct {
        const Self = @This();

        const BlockSector = BlockDevice.Sector;
        const BlockSectorResult = BlockDevice.SectorResult;
        const BlockMapError = BlockDevice.MapError;
        const BlockCommitError = BlockDevice.CommitError;
        const BlockSizeError = BlockDevice.BlockSizeError;

        // FIXME: Proper error propagation
        const BlockMapOrCommitError = BlockMapError || BlockCommitError;
        const BlockMapOrClusterTraversalError = BlockMapError || ClusterTraversalError;
        const BlockMapOrCommitOrClusterTraversalError = BlockMapError || BlockCommitError || ClusterTraversalError;
        const BlockMapOrClusterAllocationError = BlockMapError || ClusterAllocationError;
        const BlockMapOrCommitOrClusterAllocationError = BlockMapOrClusterAllocationError || BlockCommitError;
        const DeleteClustersError = BlockMapError || BlockCommitError || ClusterTraversalError;
        const CreateEntryError = BlockMapError || BlockCommitError || ClusterTraversalError || ClusterAllocationError || EntryCreationError;

        pub const Cluster = fat.SuggestCluster(config.maximum_supported_type);
        pub const FatSize = switch (config.maximum_supported_type) {
            .fat32 => u32,
            else => u16,
        };

        pub const EntryName = if (config.long_filenames) |_| []const u16 else []const u8;

        const CodepageContext = config.codepage_context;
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
        last_known_available_cluster: Cluster,
        last_known_free_clusters: Cluster,

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

            if (std.mem.indexOf(u8, &fat.allowed_media_values, &.{bpb.media_descriptor_type}) == null) {
                return MountError.InvalidMediaType;
            }

            const ebr: *align(1) const ExtendedBootRecord = std.mem.bytesAsValue(ExtendedBootRecord, first_sector_data[@sizeOf(BiosParameterBlock)..]);
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

            var fat_ctx = switch (fat_type) {
                .fat32 => ctx: {
                    if (config.maximum_supported_type != .fat32) {
                        return MountError.UnsupportedFat;
                    }
                    if (root_entries != 0) {
                        return MountError.InvalidRootEntries;
                    }

                    if (!std.mem.eql(u8, "FAT32   ", &ebr32.system_identifier)) {
                        return MountError.InvalidFilesystemType;
                    }

                    if (ebr32.backup_boot_sector != 6) {
                        return MountError.InvalidBackupSector;
                    }

                    const root_entry_cluster = std.mem.readInt(u32, std.mem.asBytes(&ebr32.root_cluster), .little);

                    if (root_entry_cluster < 2) {
                        return MountError.InvalidRootCluster;
                    }

                    const fsinfo_sector_index = std.mem.readInt(u16, std.mem.asBytes(&ebr32.fsinfo_sector), .little);

                    if (fsinfo_sector_index != 0 and fsinfo_sector_index != 1) {
                        return MountError.InvalidFSInfo;
                    }
                    const last_known_available_cluster: Cluster, const last_known_free_clusters: Cluster = if (fsinfo_sector_index == 0)
                        .{ 0xFFFFFFFF, 0xFFFFFFFF }
                    else fsinfo: {
                        const fsinfo_sector = try blk.map(fsinfo_sector_index);
                        defer blk.unmap(fsinfo_sector_index, fsinfo_sector);
                        const fsinfo: *const FSInfo32 = std.mem.bytesAsValue(FSInfo32, fsinfo_sector.asSlice());

                        if (fsinfo.lead_signature != FSInfo32.lead_signature_value or fsinfo.signature != FSInfo32.signature_value or fsinfo.trail_signature != FSInfo32.trail_signature_value) {
                            return MountError.InvalidFSInfo;
                        }

                        break :fsinfo .{ fsinfo.last_known_available_cluster, fsinfo.last_known_free_cluster_count };
                    };

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
                        .last_known_available_cluster = last_known_available_cluster,
                        .last_known_free_clusters = last_known_free_clusters,
                    };
                },
                else => |t| ctx: {
                    if (config.maximum_supported_type == .fat12 and t == .fat16) {
                        return MountError.UnsupportedFat;
                    }

                    if (!std.mem.eql(u8, "FAT     ", &ebr.system_identifier) and (!std.mem.eql(u8, "FAT12   ", &ebr.system_identifier) and t == .fat12) and (!std.mem.eql(u8, "FAT16   ", &ebr.system_identifier) and t == .fat16)) {
                        return MountError.InvalidFilesystemType;
                    }

                    break :ctx Self{
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
                        .last_known_available_cluster = 2,
                        .last_known_free_clusters = std.math.maxInt(Cluster),
                    };
                },
            };

            if (fat_ctx.getType() != .fat12) {
                // TODO: Do something about this? Error if had errors or is not clean?
                // const dirty_flags = try fat_ctx.readDirtyFlags(blk);
                try fat_ctx.writeDirtyFlags(blk, DirtyVolumeFlags{ .clean = false, .no_error = false });
            }

            return fat_ctx;
        }

        pub fn unmount(fat_ctx: *Self, blk: *BlockDevice, no_error: bool) !void {
            if (fat_ctx.getType() != .fat12) {
                try fat_ctx.writeDirtyFlags(blk, DirtyVolumeFlags{ .clean = true, .no_error = no_error });
            }
        }

        const DirtyVolumeFlags = struct { clean: bool, no_error: bool };

        inline fn readDirtyFlags(fat_ctx: *Self, blk: *BlockDevice) DirtyVolumeFlags {
            return switch (try fat_ctx.readFatEntry(blk, 0x01)) {
                .end_of_file => DirtyVolumeFlags{ .clean = true, .no_error = true },
                .allocated => |v| switch (fat_ctx.getType()) {
                    .fat16 => DirtyVolumeFlags{ .clean = ((v >> 15) & 0x01) != 0, .no_error = ((v >> 14) & 0x01) != 0 },
                    .fat32 => DirtyVolumeFlags{ .clean = ((v >> 27) & 0x01) != 0, .no_error = ((v >> 26) & 0x01) != 0 },
                    else => unreachable,
                },
                else => DirtyVolumeFlags{ .clean = false, .no_error = false },
            };
        }

        fn writeDirtyFlags(fat_ctx: *Self, blk: *BlockDevice, flags: DirtyVolumeFlags) !void {
            _ = try fat_ctx.writeFatEntry(blk, 0x01, .{ .allocated = switch (fat_ctx.getType()) {
                .fat16 => (std.math.maxInt(u16) & 0x3FFF) | (@as(u16, @intFromBool(flags.clean)) << 15) | (@as(u16, @intFromBool(flags.no_error)) << 14),
                .fat32 => (std.math.maxInt(u32) & 0x03FFFFFF) | (@as(u32, @intFromBool(flags.clean)) << 27) | (@as(u32, @intFromBool(flags.no_error)) << 26),
                else => unreachable,
            } });
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

            // Do we really need to have two conditionals, if we dont have a single entry, we won't span a single sector...
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

            pub fn toDiskEntry(entry: DirectoryEntry, stored_name: fat.sfn.StoreResult) DiskDirectoryEntry {
                return DiskDirectoryEntry{
                    .name = stored_name.result,
                    .attributes = entry.attributes.toDiskAttributes(entry.type == .directory),
                    .reserved = fat.ExtraAttributes{ .lower_base = stored_name.lower_base, .lower_extension = stored_name.lower_extension },
                    .creation_date = entry.creation_date,
                    .creation_time = entry.creation_time,
                    .creation_time_tenth = entry.creation_time_tenth,
                    .last_access_date = entry.last_access_date,
                    .write_date = entry.write_date,
                    .write_time = entry.write_time,
                    .first_cluster_hi = @intCast(entry.cluster >> 16),
                    .first_cluster_lo = @intCast(entry.cluster & 0xFFFF),
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

            pub inline fn toDir(entry: DirectoryEntry) Dir {
                std.debug.assert(entry.type == .directory);
                return Dir.init(entry);
            }

            pub inline fn toFile(entry: DirectoryEntry) File {
                std.debug.assert(entry.type == .file);
                return File.init(entry);
            }
        };

        pub const Dir = struct {
            entry: DirectoryEntry,

            pub inline fn init(entry: DirectoryEntry) Dir {
                return Dir{ .entry = entry };
            }
        };

        pub const File = struct {
            entry: DirectoryEntry,
            cluster_offset: Cluster,
            sector_offset: u8,
            byte_offset: u16,
            offset: u32,

            pub inline fn init(entry: DirectoryEntry) File {
                std.debug.assert(entry.type == .file);
                return File{ .entry = entry, .cluster_offset = entry.cluster, .sector_offset = 0, .byte_offset = 0, .offset = 0 };
            }

            pub fn seekTo(file: *File, fat_ctx: *Self, blk: *BlockDevice, offset: u32) !void {
                if (offset == file.offset) return;
                // FIXME: I don't think this is right
                if (offset > file.entry.file_size) return file.setEndPos(fat_ctx, blk, offset);

                const bytes_per_sector = @as(u16, 1) << fat_ctx.misc.bytes_per_sector;
                // const sectors_per_cluster = @as(u8, 1) << fat_ctx.misc.sectors_per_cluster;
                const bytes_per_cluster = @as(u32, bytes_per_sector) << fat_ctx.misc.sectors_per_cluster;

                // TODO: Finish this, which will speed up relative forward seeks
                // if(offset > file.offset) {
                //     const offseted_bytes = offset - file.offset;
                //     const remaining_cluster_bytes = file.offset & (bytes_per_cluster - 1);
                //
                //     if(offseted_bytes < remaining_cluster_bytes) {
                //         const new_byte_offset = @as(u32, file.byte_offset) + offseted_bytes;
                //         file.sector_offset += @intCast(new_byte_offset >> bytes_per_sector);
                //         file.byte_offset = @intCast(new_byte_offset & (bytes_per_sector - 1));
                //         return;
                //     }
                //
                //     const next_cluster_bytes = offseted_bytes - remaining_cluster_bytes;
                //
                //     file.offset = offset;
                //     return;
                // }

                const clusters_from_start = (offset >> fat_ctx.misc.bytes_per_sector) >> fat_ctx.misc.sectors_per_cluster;
                const cluster_byte_offset = offset & (bytes_per_cluster - 1);

                var current_cluster: Cluster = file.entry.cluster;

                var cluster_index: usize = 0;
                while (cluster_index < clusters_from_start) : (cluster_index += 1) {
                    current_cluster = (try fat_ctx.readNextAllocatedCluster(blk, current_cluster)).?;
                }

                file.cluster_offset = current_cluster;
                file.sector_offset = @intCast(cluster_byte_offset >> fat_ctx.misc.bytes_per_sector);
                file.byte_offset = @intCast(cluster_byte_offset & (bytes_per_sector - 1));
                file.offset = offset;
            }

            pub fn setEndPos(file: *File, fat_ctx: *Self, blk: *BlockDevice, length: u32) !void {
                const bytes_per_sector = @as(u16, 1) << fat_ctx.misc.bytes_per_sector;
                const bytes_per_cluster = @as(u32, bytes_per_sector) << fat_ctx.misc.sectors_per_cluster;
                const new_cluster_count: u32 = ((length +| (bytes_per_cluster - 1)) >> fat_ctx.misc.bytes_per_sector) >> fat_ctx.misc.sectors_per_cluster;
                const current_cluster_count: u32 = ((length +| (bytes_per_cluster - 1)) >> fat_ctx.misc.bytes_per_sector) >> fat_ctx.misc.sectors_per_cluster;

                if (new_cluster_count > current_cluster_count) {
                    const allocated_cluster_count = new_cluster_count - current_cluster_count;
                    const allocated_clusters = try fat_ctx.allocateClusters(blk, allocated_cluster_count);

                    if (file.entry.cluster > 0) {
                        var last_cluster = file.entry.cluster;
                        while (try fat_ctx.readNextAllocatedCluster(blk, last_cluster)) |next_cluster| {
                            last_cluster = next_cluster;
                        }

                        _ = try fat_ctx.writeFatEntry(blk, last_cluster, .{ .allocated = allocated_clusters });
                    } else {
                        try file.updateFileInfo(blk, length, allocated_clusters);
                        file.cluster_offset = allocated_clusters;
                    }
                } else if (new_cluster_count < current_cluster_count) {
                    var last_used_cluster = file.entry.cluster;

                    if (new_cluster_count > 0) {
                        var current_cluster_idx: u32 = 0;

                        while (true) {
                            const next_cluster = try fat_ctx.readNextAllocatedCluster(blk, last_used_cluster);

                            if (next_cluster == null) {
                                return ClusterTraversalError.InvalidCluster;
                            }

                            last_used_cluster = next_cluster.?;
                            current_cluster_idx += 1;

                            if (current_cluster_idx == new_cluster_count) {
                                break;
                            }
                        }
                    }

                    try fat_ctx.deleteClusterChain(blk, last_used_cluster);
                    try file.updateFileInfo(blk, length, if (new_cluster_count == 0) 0 else null);
                }
            }

            inline fn updateFileInfo(file: *File, blk: *BlockDevice, file_size: u32, first_cluster: ?Cluster) BlockMapOrCommitError!void {
                const sector_stack = file.entry.location.getSectorStack();
                const last_sector_index = sector_stack[sector_stack.len - 1];
                const last_sector = try blk.map(last_sector_index);
                defer blk.unmap(last_sector_index, last_sector);

                const directory_entries: []DiskDirectoryEntry = @alignCast(std.mem.bytesAsSlice(DiskDirectoryEntry, last_sector.asSlice()));
                const directory_entry = &directory_entries[file.entry.location.getEnd()];
                directory_entry.file_size = file_size;
                file.entry.file_size = file_size;

                if (first_cluster) |cluster| {
                    directory_entry.first_cluster_hi = @intCast(cluster >> 16);
                    directory_entry.first_cluster_lo = @intCast(cluster & 0xFFFF);
                    file.entry.cluster = cluster;
                }

                if (file.offset > file_size) {
                    file.offset = file_size;
                }

                try blk.commit(last_sector_index, last_sector);
            }

            pub fn read(file: *File, fat_ctx: *Self, blk: *BlockDevice, buffer: []u8) BlockMapOrClusterTraversalError!usize {
                if (buffer.len == 0 or file.offset == file.entry.file_size) return 0;
                if (file.offset == file.entry.file_size) return 0;

                const bytes_per_sector = @as(u16, 1) << fat_ctx.misc.bytes_per_sector;
                const sectors_per_cluster = @as(u8, 1) << fat_ctx.misc.sectors_per_cluster;

                const unread_bytes = file.entry.file_size - file.offset;
                const unread_sector_bytes = bytes_per_sector - file.byte_offset;
                const read_buffer = buffer[0..@min(unread_bytes, unread_sector_bytes, buffer.len)];
                const sector_index = fat_ctx.cluster2Sector(file.cluster_offset) + file.sector_offset;
                const sector = try blk.map(sector_index);
                defer blk.unmap(sector_index, sector);
                @memcpy(read_buffer, sector.asSlice()[file.byte_offset..][0..read_buffer.len]);

                const small_offset: u16 = @intCast(read_buffer.len);
                file.offset += small_offset;
                file.byte_offset += small_offset;
                if (file.byte_offset == bytes_per_sector) {
                    file.byte_offset = 0;
                    file.sector_offset += 1;
                }

                if (file.offset < file.entry.file_size and file.sector_offset == sectors_per_cluster) {
                    file.sector_offset = 0;

                    const next_cluster = try fat_ctx.readNextAllocatedCluster(blk, file.cluster_offset);

                    // NOTE: This must always return a new cluster, as we have more data to consume
                    if (next_cluster == null) {
                        return ClusterTraversalError.InvalidCluster;
                    }

                    file.cluster_offset = next_cluster.?;
                }

                return read_buffer.len;
            }

            pub fn write(file: *File, fat_ctx: *Self, blk: *BlockDevice, bytes: []const u8) !usize {
                if (bytes.len == 0) return 0;
                if (file.offset == std.math.maxInt(u32)) return WriteError.FileTooBig;

                const bytes_per_sector = @as(u16, 1) << fat_ctx.misc.bytes_per_sector;
                const sectors_per_cluster = @as(u8, 1) << fat_ctx.misc.sectors_per_cluster;
                const bytes_per_cluster = @as(u32, bytes_per_sector) << fat_ctx.misc.sectors_per_cluster;

                if (file.offset == file.entry.file_size) end_of_file: {
                    const unwritten_file_bytes = std.math.maxInt(u32) - file.offset;
                    const written_cluster_bytes = (@as(u16, file.sector_offset) << fat_ctx.misc.bytes_per_sector) + file.byte_offset;
                    const unwritten_cluster_bytes = bytes_per_cluster - written_cluster_bytes;
                    const remaining_free_bytes = @min(unwritten_cluster_bytes, unwritten_file_bytes);

                    if (file.cluster_offset != 0 and remaining_free_bytes > 0) {
                        try file.updateFileInfo(blk, file.entry.file_size + @min(bytes.len, remaining_free_bytes), null);
                        break :end_of_file;
                    }

                    const writing_bytes = bytes[0..@min(bytes.len, unwritten_file_bytes)];
                    const needed_clusters: u32 = @intCast((writing_bytes.len +| bytes_per_cluster - 1) >> fat_ctx.misc.bytes_per_sector >> fat_ctx.misc.sectors_per_cluster);
                    const new_allocated = try fat_ctx.allocateClusters(blk, needed_clusters);

                    // This means we're not growing an empty file
                    if (file.entry.cluster != 0) {
                        _ = try fat_ctx.writeFatEntry(blk, file.cluster_offset, .{ .allocated = new_allocated });
                    }

                    var currently_written_bytes: u32 = 0;
                    var remaining_written_bytes: usize = writing_bytes.len;
                    var current_cluster = new_allocated;
                    writing: while (true) {
                        const cluster_sector_start = fat_ctx.cluster2Sector(current_cluster);

                        for (0..sectors_per_cluster) |current_sector| {
                            const sector_index = cluster_sector_start + current_sector;
                            const sector = try blk.map(sector_index);
                            defer blk.unmap(sector_index, sector);

                            const written_bytes = @min(remaining_written_bytes, bytes_per_sector);
                            @memcpy(sector.asSlice()[0..written_bytes], writing_bytes[currently_written_bytes..][0..written_bytes]);
                            try blk.commit(sector_index, sector);

                            currently_written_bytes += written_bytes;
                            remaining_written_bytes -= written_bytes;

                            if (remaining_written_bytes == 0) {
                                break :writing;
                            }
                        }

                        // NOTE: Can't ever happend as we already check above if we finished writing
                        current_cluster = (try fat_ctx.readNextAllocatedCluster(blk, current_cluster)).?;
                    }

                    // Write data
                    file.cluster_offset = current_cluster;
                    file.offset += @intCast(writing_bytes.len);
                    try file.updateFileInfo(blk, file.offset, if (file.entry.cluster == 0) new_allocated else null);
                    return writing_bytes.len;
                }

                const unwritten_sector_bytes = bytes_per_sector - file.byte_offset;
                const writing_bytes = bytes[0..@min(unwritten_sector_bytes, bytes.len)];
                const sector_index = fat_ctx.cluster2Sector(file.cluster_offset) + file.sector_offset;
                const sector = try blk.map(sector_index);
                defer blk.unmap(sector_index, sector);

                @memcpy(sector.asSlice()[file.byte_offset..][0..writing_bytes.len], writing_bytes);
                try blk.commit(sector_index, sector);

                const small_written: u16 = @intCast(writing_bytes.len);
                file.offset += small_written;
                file.byte_offset += small_written;

                if (file.byte_offset == bytes_per_sector) {
                    file.byte_offset = 0;
                    file.sector_offset += 1;
                }

                if (file.sector_offset == sectors_per_cluster and file.offset != file.entry.file_size) {
                    file.sector_offset = 0;

                    const next_cluster = try fat_ctx.readNextAllocatedCluster(blk, file.cluster_offset);

                    if (next_cluster == null) {
                        return ClusterTraversalError.InvalidCluster;
                    }

                    file.cluster_offset = next_cluster.?;
                }

                return writing_bytes.len;
            }

            pub fn writeAll(file: *File, fat_ctx: *Self, blk: *BlockDevice, bytes: []const u8) !void {
                var index: usize = 0;
                while (index < bytes.len) {
                    index += try file.write(fat_ctx, blk, bytes[index..]);
                }
            }

            // TODO: generic writer()/reader()?
        };

        pub fn directoryEntryIterator(fat_ctx: *Self, directory: ?Dir) DirectoryEntryIterator {
            const directory_cluster = if (directory) |dir| v: {
                break :v dir.entry.cluster;
            } else fat_ctx.getRootCluster();
            return DirectoryEntryIterator.init(fat_ctx.diskDirectoryEntryIterator(directory_cluster));
        }

        pub inline fn search(fat_ctx: *Self, blk: *BlockDevice, directory: ?Dir, name: EntryName) BlockMapOrClusterTraversalError!?DirectoryEntry {
            if (@sizeOf(LongContext) != 0) @compileError("Cannot infer context " ++ @typeName(LongContext) ++ ", call searchContext instead.");
            if (@sizeOf(CodepageContext) != 0) @compileError("Cannot infer context " ++ @typeName(CodepageContext) ++ ", call searchContext instead.");
            return fat_ctx.searchContext(blk, directory, name, undefined, undefined);
        }

        pub inline fn searchShort(fat_ctx: *Self, blk: *BlockDevice, directory: ?Dir, name: EntryName) BlockMapOrClusterTraversalError!?DirectoryEntry {
            if (@sizeOf(CodepageContext) != 0) @compileError("Cannot infer context " ++ @typeName(CodepageContext) ++ ", call searchContext instead.");
            return fat_ctx.searchShortContext(blk, directory, name, undefined);
        }

        pub fn searchContext(fat_ctx: *Self, blk: *BlockDevice, directory: ?Dir, name: EntryName, cctx: CodepageContext, lctx: LongContext) BlockMapOrClusterTraversalError!?DirectoryEntry {
            if (config.long_filenames) |_| {
                var it = fat_ctx.directoryEntryIterator(directory);
                defer it.deinit(blk);

                var codepage_filename = ShortFilenameDisplay.init(0) catch unreachable;
                const codepage_conversion_lossy = lctx.utf16LeToCodepage(&codepage_filename, name);
                const codepage_name = codepage_filename.constSlice();
                const stored = fat.sfn.store(codepage_name, cctx);

                while (try it.next(blk)) |it_entry| {
                    if (it_entry.lfn) |lfn| {
                        if (lctx.eql(lfn, name)) {
                            return it_entry.entry;
                        }
                    } else {
                        if (codepage_conversion_lossy or !std.mem.eql(u8, it_entry.sfn, &stored.result)) {
                            continue;
                        }

                        return it_entry.entry;
                    }
                }

                return null;
            } else return searchShortContext(fat_ctx, blk, directory, cctx);
        }

        pub fn searchShortContext(fat_ctx: *Self, blk: *BlockDevice, directory: ?Dir, name: []const u8, ctx: CodepageContext) BlockMapOrClusterTraversalError!?DirectoryEntry {
            const stored = fat.sfn.store(name, ctx);

            if (stored.lossy) {
                // HACK: Return error?
                return null;
            }

            var it = fat_ctx.directoryEntryIterator(directory);
            defer it.deinit(blk);

            while (try it.next(blk)) |it_entry| {
                if (std.mem.eql(it_entry.sfn, stored.result)) {
                    return it_entry.entry;
                }
            }

            return null;
        }

        pub fn delete(fat_ctx: *Self, blk: *BlockDevice, entry: DirectoryEntry) DeleteClustersError!void {
            if (entry.cluster != 0) {
                try fat_ctx.deleteClusterChain(blk, entry.cluster);
            }

            try fat_ctx.deleteDiskDirectoryEntries(blk, entry);
        }

        pub inline fn create(fat_ctx: *Self, blk: *BlockDevice, directory: ?Dir, name: EntryName, entry_info: CreationInfo) !DirectoryEntry {
            if (@sizeOf(LongContext) != 0) @compileError("Cannot infer context " ++ @typeName(LongContext) ++ ", call createContext instead.");
            if (@sizeOf(CodepageContext) != 0) @compileError("Cannot infer context " ++ @typeName(CodepageContext) ++ ", call createContext instead.");
            return fat_ctx.createContext(blk, directory, name, entry_info, undefined, undefined);
        }

        pub inline fn createShort(fat_ctx: *Self, blk: *BlockDevice, directory: ?Dir, name: EntryName, entry_info: CreationInfo) !DirectoryEntry {
            if (@sizeOf(CodepageContext) != 0) @compileError("Cannot infer context " ++ @typeName(CodepageContext) ++ ", call createShortContext instead.");
            return fat_ctx.createShortKindContext(blk, directory, name, .{ .new = entry_info }, undefined);
        }

        pub inline fn createShortContext(fat_ctx: *Self, blk: *BlockDevice, directory: ?Dir, name: EntryName, entry_info: CreationInfo, ctx: CodepageContext) !DirectoryEntry {
            return fat_ctx.createShortKindContext(blk, directory, name, .{ .new = entry_info }, ctx);
        }

        pub inline fn createContext(fat_ctx: *Self, blk: *BlockDevice, directory: ?Dir, name: EntryName, entry_info: CreationInfo, cctx: CodepageContext, lctx: LongContext) !DirectoryEntry {
            return fat_ctx.createKindContext(blk, directory, name, .{ .new = entry_info }, cctx, lctx);
        }

        pub inline fn move(fat_ctx: *Self, blk: *BlockDevice, entry: DirectoryEntry, new_location: ?Dir, new_name: EntryName) !DirectoryEntry {
            if (@sizeOf(LongContext) != 0) @compileError("Cannot infer context " ++ @typeName(LongContext) ++ ", call moveContext instead.");
            if (@sizeOf(CodepageContext) != 0) @compileError("Cannot infer context " ++ @typeName(CodepageContext) ++ ", call moveContext instead.");
            return fat_ctx.moveContext(blk, entry, new_location, new_name, undefined, undefined);
        }

        pub inline fn moveShort(fat_ctx: *Self, blk: *BlockDevice, entry: DirectoryEntry, new_location: ?Dir, new_name: EntryName) !DirectoryEntry {
            if (@sizeOf(CodepageContext) != 0) @compileError("Cannot infer context " ++ @typeName(CodepageContext) ++ ", call moveShortContext instead.");
            return fat_ctx.moveShortContext(blk, entry, new_location, new_name, undefined);
        }

        // XXX: This may fail when we reach maxInt(u16) entries or the limit of root entries, FIX IT!
        pub inline fn moveShortContext(fat_ctx: *Self, blk: *BlockDevice, entry: DirectoryEntry, new_location: ?Dir, new_name: []const u8, ctx: CodepageContext) !DirectoryEntry {
            try fat_ctx.deleteDiskDirectoryEntries(blk, entry);
            return fat_ctx.createShortKindContext(blk, new_location, new_name, .{ .move = entry }, ctx);
        }

        pub inline fn moveContext(fat_ctx: *Self, blk: *BlockDevice, entry: DirectoryEntry, new_location: ?Dir, new_name: EntryName, cctx: CodepageContext, lctx: LongContext) !DirectoryEntry {
            try fat_ctx.deleteDiskDirectoryEntries(blk, entry);
            return fat_ctx.createKindContext(blk, new_location, new_name, .{ .move = entry }, cctx, lctx);
        }

        pub fn isDirectoryEmpty(fat_ctx: *Self, blk: *BlockDevice, directory: Dir) BlockMapOrClusterTraversalError!bool {
            var it = fat_ctx.diskDirectoryEntryIterator(directory.entry.cluster);
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

        fn expectDiskDirectoryEntry(it: *DiskDirectoryEntryIterator, blk: *BlockDevice, comptime name: *const [fat.sfn.stored_len]u8) BlockMapOrClusterTraversalError!void {
            if (try it.next(blk)) |dir| {
                if (!std.mem.eql(u8, &dir.name, name)) {
                    return; // TODO: Error
                }

                return;
            }

            return; // TODO: Error
        }

        fn deleteClusterChain(fat_ctx: *Self, blk: *BlockDevice, start: Cluster) DeleteClustersError!void {
            var current = start;

            while (try fat_ctx.writeNextAllocatedCluster(blk, current, .free)) |next| {
                current = next;
            }
        }

        fn deleteDiskDirectoryEntries(fat_ctx: *Self, blk: *BlockDevice, entry: DirectoryEntry) BlockMapOrCommitError!void {
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

        fn deleteSectorDirectoryEntries(blk: *BlockDevice, sector_index: BlockSector, start: u8, end: u8) BlockMapOrCommitError!void {
            const sector = try blk.map(sector_index);
            defer blk.unmap(sector_index, sector);

            const directories: []DiskDirectoryEntry = @alignCast(std.mem.bytesAsSlice(DiskDirectoryEntry, sector.asSlice()));

            for (start..end) |i| {
                directories[i].name[0] = 0xE5;
            }

            try blk.commit(sector_index, sector);
        }

        fn createShortKindContext(fat_ctx: *Self, blk: *BlockDevice, directory: ?Dir, name: []const u8, kind: CreationKind, ctx: CodepageContext) CreateEntryError!DirectoryEntry {
            const directory_cluster = if (directory) |dir| v: {
                break :v dir.entry.cluster;
            } else fat_ctx.getRootCluster();

            var dir_it = fat_ctx.diskDirectoryEntryIterator(directory_cluster);
            defer dir_it.deinit(blk);

            var iterated_entries: u16 = 0;
            var free_sector: ?BlockSector, const free_entry = while (try dir_it.next(blk)) |dirent| {
                iterated_entries += 1;

                if (dirent.isFree()) {
                    break .{ dir_it.lastSector(), dir_it.lastSectorEntry() };
                }
            } else .{ null, 0 };

            if (iterated_entries == std.math.maxInt(u16)) {
                return EntryCreationError.NoSpaceLeft;
            }

            while (true) {
                if (free_sector) |free| {
                    const sector = try blk.map(free);
                    defer blk.unmap(free, sector);
                    const directory_entries: []DiskDirectoryEntry = std.mem.bytesAsSlice(DiskDirectoryEntry, sector.asSlice());

                    // NOTE: Here we don't care if the conversion is lossy or not
                    // TODO: Codepage context
                    const store_result = fat.sfn.store(name, ctx);
                    try fat_ctx.createDiskDirectoryEntry(blk, directory_cluster, &directory_entries[free_entry], store_result, kind);

                    try blk.commit(free, sector);
                    return DirectoryEntry.fromDiskEntry(directory_entries[free_entry], DirectoryEntrySectorLocation.fromSingleEntry(free, free_entry));
                }

                const last_cluster = dir_it.current_cluster;
                if (last_cluster == 0) {
                    return EntryCreationError.OutOfRootDirectoryEntries;
                }

                const newly_allocated_cluster = try fat_ctx.allocateDirectoryClusters(blk, 1);
                _ = try fat_ctx.writeFatEntry(blk, last_cluster, .{ .allocated = newly_allocated_cluster });

                free_sector = fat_ctx.cluster2Sector(newly_allocated_cluster);
                // NOTE: The free entry will be at the start of the sector
            }
        }

        const CreationKind = union(enum) { new: CreationInfo, move: DirectoryEntry };
        fn createKindContext(fat_ctx: *Self, blk: *BlockDevice, directory: ?Dir, name: EntryName, kind: CreationKind, cctx: CodepageContext, lctx: LongContext) !DirectoryEntry {
            if (config.long_filenames) |_| {
                const directory_cluster = if (directory) |dir| v: {
                    break :v dir.entry.cluster;
                } else fat_ctx.getRootCluster();

                var codepage_filename = ShortFilenameDisplay.init(0) catch unreachable;
                // TODO: Check duplicate short names and do something?
                const codepage_conversion_lossy = lctx.utf16LeToCodepage(&codepage_filename, name);
                const codepage_name = codepage_filename.constSlice();

                // TODO: Codepage context
                const stored_sfn = fat.sfn.store(codepage_name, cctx);

                const needs_lfn = codepage_conversion_lossy or stored_sfn.lossy;
                const needed_lfn_entries: u8 = if (needs_lfn) (1 + (@as(u8, @intCast(name.len)) / LongFileNameEntry.stored_name_length)) else 0;
                const needed_entries = needed_lfn_entries + 1;

                const entry_location: DirectoryEntrySectorLocation = try fat_ctx.searchFreeDiskDirectoryEntries(blk, directory_cluster, needed_entries);
                const sector_stack = entry_location.getSectorStack();

                if (sector_stack.len == 1) {
                    const start = entry_location.sector_entry_start;
                    const end = entry_location.sector_entry_end;

                    const sector_index = entry_location.sector_stack[0];
                    const sector = try blk.map(sector_index);
                    defer blk.unmap(sector_index, sector);

                    const directory_entries: []DiskDirectoryEntry = std.mem.bytesAsSlice(DiskDirectoryEntry, sector.asSlice());

                    if (start != end) {
                        const checksum = fat.sfn.checksum(stored_sfn.result);

                        var current_entry = end - 1;
                        var lfn_current_character: u8 = 0;

                        for (1..needed_lfn_entries) |current| {
                            const current_lfn_entry: *LongFileNameEntry = @ptrCast(&directory_entries[current_entry]);
                            const order: u8 = @intCast(current);

                            current_lfn_entry.* = LongFileNameEntry.init(order, checksum, name[lfn_current_character..]);
                            lfn_current_character += LongFileNameEntry.stored_name_length;
                            current_entry -= 1;
                        }

                        const last_lfn_entry: *LongFileNameEntry = @ptrCast(&directory_entries[current_entry]);
                        last_lfn_entry.* = LongFileNameEntry.initLast(needed_lfn_entries, checksum, name[lfn_current_character..]);
                    }

                    try fat_ctx.createDiskDirectoryEntry(blk, directory_cluster, &directory_entries[end], stored_sfn, kind);
                    try blk.commit(sector_index, sector);
                    return DirectoryEntry.fromDiskEntry(directory_entries[end], entry_location);
                } else {
                    const directory_entries_per_sector = @as(u8, 1) << fat_ctx.misc.directory_entries_per_sector;
                    const checksum = fat.sfn.checksum(stored_sfn.result);

                    var current_order: u8 = 1;
                    var current_stack_index = sector_stack.len - 1;
                    var current_sector_index = sector_stack[current_stack_index];
                    var current_sector = try blk.map(current_sector_index);
                    var current_entry_reversed = entry_location.sector_entry_end;
                    var lfn_current_character: u8 = 0;

                    const sfn_entry = v: {
                        const last_directory_entries: []DiskDirectoryEntry = std.mem.bytesAsSlice(DiskDirectoryEntry, current_sector.asSlice());
                        const last_directory_entry = &last_directory_entries[current_entry_reversed];

                        try fat_ctx.createDiskDirectoryEntry(blk, directory_cluster, last_directory_entry, stored_sfn, kind);
                        break :v last_directory_entry.*;
                    };

                    while (true) {
                        while (current_entry_reversed >= 1 and current_order < needed_lfn_entries) : ({
                            current_entry_reversed -= 1;
                            current_order += 1;
                        }) {
                            const lfn_entry = current_entry_reversed - 1;
                            const directory_entries: []DiskDirectoryEntry = std.mem.bytesAsSlice(DiskDirectoryEntry, current_sector.asSlice());
                            const lfn: *LongFileNameEntry = @ptrCast(&directory_entries[lfn_entry]);

                            lfn.* = LongFileNameEntry.init(current_order, checksum, name[lfn_current_character..]);
                            lfn_current_character += LongFileNameEntry.stored_name_length;
                        }

                        if (current_order == needed_lfn_entries) {
                            const first_sector_index, const first_sector, const first_entry = if (current_entry_reversed == 0) v: {
                                std.debug.assert(current_stack_index > 0);

                                defer blk.unmap(current_sector_index, current_sector);
                                try blk.commit(current_sector_index, current_sector);

                                current_stack_index -= 1;
                                std.debug.assert(current_stack_index == 0);

                                const first_sector_index = sector_stack[current_stack_index];
                                const first_sector = try blk.map(first_sector_index);

                                break :v .{ first_sector_index, first_sector, directory_entries_per_sector - 1 };
                            } else .{ current_sector_index, current_sector, current_entry_reversed - 1 };

                            defer blk.unmap(first_sector_index, first_sector);

                            const directory_entries: []DiskDirectoryEntry = std.mem.bytesAsSlice(DiskDirectoryEntry, current_sector.asSlice());
                            const lfn: *LongFileNameEntry = @ptrCast(&directory_entries[first_entry]);
                            lfn.* = LongFileNameEntry.initLast(needed_lfn_entries, checksum, name[lfn_current_character..]);

                            try blk.commit(first_sector_index, first_sector);
                            return DirectoryEntry.fromDiskEntry(sfn_entry, entry_location);
                        }

                        {
                            defer blk.unmap(current_sector_index, current_sector);
                            try blk.commit(current_sector_index, current_sector);
                        }

                        std.debug.assert(current_stack_index > 0);
                        current_stack_index -= 1;
                        current_sector_index = sector_stack[current_stack_index];
                        current_sector = try blk.map(current_sector_index);
                        current_entry_reversed = directory_entries_per_sector;
                    }
                }
            } else fat_ctx.createShortContext(blk, directory, name, kind);
        }

        fn searchFreeDiskDirectoryEntries(fat_ctx: *Self, blk: *BlockDevice, directory_cluster: Cluster, needed_entries: u8) !DirectoryEntrySectorLocation {
            const directory_entries_per_sector = @as(u8, 1) << fat_ctx.misc.directory_entries_per_sector;

            var entry_location: DirectoryEntrySectorLocation = std.mem.zeroes(DirectoryEntrySectorLocation);

            var iterated_entries: u16 = 0;
            var sequential_entries: u32 = 0;

            var dir_it = fat_ctx.diskDirectoryEntryIterator(directory_cluster);
            defer dir_it.deinit(blk);

            while (true) {
                // HACK: We do this as we know the implementation of the iterator. It allows us to continue iterating if we added a cluster
                while (try dir_it.next(blk)) |dirent| {
                    iterated_entries += 1;

                    if (iterated_entries == std.math.maxInt(u16)) {
                        return EntryCreationError.NoSpaceLeft;
                    }

                    if (!dirent.isFree()) {
                        entry_location.sector_entry_start = 0;
                        entry_location.sector_entry_end = 0;
                        entry_location.sector_stack_current = 0;
                        continue;
                    }

                    if (entry_location.sector_stack_current == 0) {
                        entry_location.sector_stack[0] = dir_it.lastSector();
                        entry_location.sector_stack_current += 1;

                        entry_location.sector_entry_start = dir_it.lastSectorEntry();
                        entry_location.sector_entry_end = entry_location.sector_entry_start;
                    } else {
                        entry_location.sector_entry_end = dir_it.lastSectorEntry();

                        const last_sector = entry_location.sector_stack[entry_location.sector_stack_current - 1];
                        const current_sector = dir_it.lastSector();

                        if (last_sector != current_sector) {
                            entry_location.sector_stack[entry_location.sector_stack_current] = current_sector;
                            entry_location.sector_stack_current += 1;
                        }
                    }

                    sequential_entries += 1;
                    if (sequential_entries == needed_entries) {
                        return entry_location;
                    }
                }

                const last_cluster = dir_it.current_cluster;

                if (last_cluster == 0) {
                    return EntryCreationError.OutOfRootDirectoryEntries;
                }

                const needed_clusters: u32 = (((needed_entries - sequential_entries) + directory_entries_per_sector) >> fat_ctx.misc.directory_entries_per_sector) >> fat_ctx.misc.sectors_per_cluster;
                const newly_allocated_cluster = try fat_ctx.allocateDirectoryClusters(blk, needed_clusters);
                _ = try fat_ctx.writeFatEntry(blk, last_cluster, .{ .allocated = newly_allocated_cluster });
            }
        }

        fn createDiskDirectoryEntry(fat_ctx: *Self, blk: *BlockDevice, directory_cluster: Cluster, entry: *DiskDirectoryEntry, stored_name: fat.sfn.StoreResult, kind: CreationKind) !void {
            switch (kind) {
                .move => |last_entry| entry.* = last_entry.toDiskEntry(stored_name),
                .new => |new_entry_info| {
                    const allocated_cluster, const file_size = switch (new_entry_info.type) {
                        .directory => |entries| v: {
                            const directory_entries_per_sector = @as(u16, 1) << fat_ctx.misc.directory_entries_per_sector;
                            const directory_entries_per_cluster = directory_entries_per_sector << fat_ctx.misc.sectors_per_cluster;

                            // NOTE: We add 2 as we must add the '.' and '..' entries.
                            const needed_clusters = (((1 + entries) +| directory_entries_per_cluster) >> fat_ctx.misc.directory_entries_per_sector) >> fat_ctx.misc.sectors_per_cluster;
                            const first_allocated = try fat_ctx.allocateDirectoryClusters(blk, needed_clusters);
                            try fat_ctx.createDotEntries(blk, directory_cluster, first_allocated);

                            break :v .{ first_allocated, 0 };
                        },
                        .file => |size| v: {
                            const bytes_per_sector = @as(u32, 1) << fat_ctx.misc.bytes_per_sector;
                            const bytes_per_cluster = bytes_per_sector << fat_ctx.misc.sectors_per_cluster;

                            const needed_clusters = ((size + bytes_per_cluster - 1) >> fat_ctx.misc.bytes_per_sector) >> fat_ctx.misc.sectors_per_cluster;

                            if (needed_clusters == 0) {
                                break :v .{ 0, 0 };
                            }

                            const allocated_clusters = try fat_ctx.allocateClusters(blk, needed_clusters);
                            break :v .{ allocated_clusters, size };
                        },
                    };

                    entry.* = new_entry_info.asDiskDirectoryEntry(stored_name.result, fat.ExtraAttributes{ .lower_base = stored_name.lower_base, .lower_extension = stored_name.lower_extension }, @as(Cluster, allocated_cluster), file_size);
                },
            }
        }

        fn createDotEntries(fat_ctx: *Self, blk: *BlockDevice, from_cluster: Cluster, first_cluster: Cluster) BlockMapOrCommitError!void {
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

        fn allocateDirectoryClusters(fat_ctx: *Self, blk: *BlockDevice, n: u32) !Cluster {
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

                const next_possible_cluster = fat_ctx.readNextAllocatedCluster(blk, current_cluster) catch |e| switch (e) {
                    ClusterTraversalError.InvalidCluster => unreachable,
                    else => return e,
                };

                if (next_possible_cluster) |next_cluster| {
                    current_cluster = next_cluster;
                    continue;
                }

                break;
            }

            return first_allocated;
        }

        fn allocateClusters(fat_ctx: *Self, blk: *BlockDevice, n: u32) BlockMapOrCommitOrClusterTraversalError!Cluster {
            std.debug.assert(n > 0);

            const last_available_cluster = fat_ctx.last_known_available_cluster;

            const first_next = try fat_ctx.searchFreeCluster(blk);
            _ = try fat_ctx.writeFatEntry(blk, first_next, .end_of_file);

            var current_cluster = first_next;
            var current_allocated: usize = 1;
            while (current_allocated < n) : (current_allocated += 1) {
                // TODO: Wraparound when searching
                const next_free = fat_ctx.linearSearchFreeCluster(blk, current_cluster + 1) catch |e| switch (e) {
                    ClusterAllocationError.NoSpaceLeft => {
                        fat_ctx.last_known_available_cluster = last_available_cluster;
                        try fat_ctx.deleteClusterChain(blk, first_next);
                        return e;
                    },
                    else => return e,
                };

                _ = try fat_ctx.writeFatEntry(blk, current_cluster, .{ .allocated = next_free });
                current_cluster = next_free;
            }

            _ = try fat_ctx.writeFatEntry(blk, current_cluster, .end_of_file);

            if (fat_ctx.last_known_free_clusters != std.math.maxInt(Cluster)) {
                fat_ctx.last_known_free_clusters -|= n;
            }

            return first_next;
        }

        const DirectoryEntryIterator = struct {
            const LongEntryName = if (config.long_filenames) |_| ?[:0]const u16 else void;
            const LongEntryNameBuffer = if (config.long_filenames) |_| [config.long_filenames.?.maximum_supported_len:0]u16 else void;
            const ShortFilenameCasing = fat.ExtraAttributes;

            pub const Entry = struct {
                sfn: *const [fat.sfn.stored_len:0]u8,
                lfn: LongEntryName,
                entry: DirectoryEntry,
                _casing: ShortFilenameCasing,

                pub inline fn displayShortFilename(entry: Entry, filename: *ShortFilenameDisplay) void {
                    if (@sizeOf(CodepageContext) != 0) @compileError("Cannot infer context " ++ @typeName(CodepageContext) ++ ", call displayShortFilenameContext instead.");
                    entry.displayShortFilenameContext(filename, undefined);
                }

                pub inline fn displayShortFilenameContext(entry: Entry, filename: *ShortFilenameDisplay, ctx: CodepageContext) void {
                    fat.sfn.display(filename, entry.sfn.*, entry._casing.lower_base, entry._casing.lower_extension, ctx);
                }
            };

            it: DiskDirectoryEntryIterator,
            current_location: DirectoryEntrySectorLocation = undefined,
            sfn: [fat.sfn.stored_len:0]u8 = undefined,
            lfn: LongEntryNameBuffer = undefined,

            pub inline fn init(it: DiskDirectoryEntryIterator) DirectoryEntryIterator {
                return DirectoryEntryIterator{ .it = it };
            }

            // TODO: What to do with invalid entries, skip them or return error?
            pub fn next(it: *DirectoryEntryIterator, blk: *BlockDevice) BlockMapOrClusterTraversalError!?Entry {
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
                            lfn_entry.appendLastEntryNameReverse(lfn, &current_lfn_index);
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

                                    next_lfn.appendEntryNameReverse(lfn, &current_lfn_index);
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

                                const real_entry_checksum = fat.sfn.checksum(real_entry.name);

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
                if (max_file_entries > 1) {
                    it.current_location.sector_entry_end = it.it.lastSectorEntry();
                }

                @memcpy(&it.sfn, &entry.name);

                if (it.sfn[0] == DiskDirectoryEntry.stored_e5_flag) {
                    it.sfn[0] = 0xE5;
                }

                return Entry{ .sfn = &it.sfn, .lfn = lfn, .entry = DirectoryEntry.fromDiskEntry(entry, it.current_location), ._casing = entry.reserved };
            }

            pub inline fn deinit(it: *DirectoryEntryIterator, blk: *BlockDevice) void {
                it.it.deinit(blk);
            }
        };

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

            pub fn next(it: *EntriesSelf, blk: *BlockDevice) BlockMapOrClusterTraversalError!?DiskDirectoryEntry {
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

        inline fn searchFreeCluster(fat_ctx: *Self, blk: *BlockDevice) BlockMapOrClusterAllocationError!Cluster {
            const start = if (fat_ctx.last_known_available_cluster == std.math.maxInt(Cluster))
                2
            else
                fat_ctx.last_known_available_cluster;

            return fat_ctx.linearSearchFreeCluster(blk, start);
        }

        fn linearSearchFreeCluster(fat_ctx: *Self, blk: *BlockDevice, start: Cluster) BlockMapOrClusterAllocationError!Cluster {
            var currentCluster: Cluster = start;
            return e: while (currentCluster <= fat_ctx.max_cluster) : (currentCluster = fat_ctx.incrementCluster(currentCluster)) {
                switch (try fat_ctx.readFatEntry(blk, currentCluster)) {
                    .free => {
                        fat_ctx.last_known_available_cluster = fat_ctx.incrementCluster(currentCluster);
                        break :e currentCluster;
                    },
                    else => {},
                }
            } else ClusterAllocationError.NoSpaceLeft;
        }

        inline fn incrementCluster(fat_ctx: Self, cluster: Cluster) Cluster {
            const new = cluster + 1;
            return if (cluster == fat_ctx.max_cluster) 2 else new;
        }

        inline fn readNextAllocatedCluster(fat_ctx: *Self, blk: *BlockDevice, cluster_index: Cluster) BlockMapOrClusterTraversalError!?Cluster {
            return fat_ctx.queryNextAllocatedCluster(blk, cluster_index, .read, undefined);
        }

        inline fn writeNextAllocatedCluster(fat_ctx: *Self, blk: *BlockDevice, cluster_index: Cluster, value: TableEntry) BlockMapOrCommitOrClusterTraversalError!?Cluster {
            return fat_ctx.queryNextAllocatedCluster(blk, cluster_index, .write, value);
        }

        inline fn readFatEntry(fat_ctx: *Self, blk: *BlockDevice, cluster_index: Cluster) BlockMapError!TableEntry {
            return fat_ctx.queryFatEntry(blk, cluster_index, .read, undefined);
        }

        inline fn writeFatEntry(fat_ctx: *Self, blk: *BlockDevice, cluster_index: Cluster, value: TableEntry) BlockMapOrCommitError!TableEntry {
            return fat_ctx.queryFatEntry(blk, cluster_index, .write, value);
        }

        const FatQuery = enum(u1) { read, write };

        inline fn queryNextAllocatedCluster(fat_ctx: *Self, blk: *BlockDevice, cluster: Cluster, comptime query: FatQuery, value: (if (query == .write) TableEntry else void)) (if (query == .write) BlockMapOrCommitOrClusterTraversalError!?Cluster else BlockMapOrClusterTraversalError!?Cluster) {
            return switch (try fat_ctx.queryFatEntry(blk, cluster, query, value)) {
                .allocated => |next_cluster| next_cluster,
                .end_of_file => null,
                else => ClusterTraversalError.InvalidCluster,
            };
        }

        // TODO: Query the other FAT's when needed
        fn queryFatEntry(fat_ctx: *Self, blk: *BlockDevice, cluster_index: Cluster, comptime query: FatQuery, value: (if (query == .write) TableEntry else void)) if (query == .write) BlockMapOrCommitError!TableEntry else BlockMapError!TableEntry {
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
    _ = fat;
    _ = format;
}

const std = @import("std");
const fat = @import("fat.zig");

const BiosParameterBlock = fat.BiosParameterBlock;
const ExtendedBootRecord = fat.ExtendedBootRecord;
const ExtendedBootRecord32 = fat.ExtendedBootRecord32;
const FSInfo32 = fat.FSInfo32;
const DiskAttributes = fat.Attributes;
const DiskDirectoryEntry = fat.DirectoryEntry;
const LongFileNameEntry = fat.LongFileNameEntry;

const log = std.log.scoped(.nzfat);
