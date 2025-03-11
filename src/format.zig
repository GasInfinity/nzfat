const std = @import("std");
const fat = @import("fat.zig");

const BiosParameterBlock = fat.BiosParameterBlock;
const ExtendedBootRecord = fat.ExtendedBootRecord;
const ExtendedBootRecord32 = fat.ExtendedBootRecord32;
const FSInfo32 = fat.FSInfo32;
const DiskDirectoryEntry = fat.DirectoryEntry;

const log = std.log.scoped(.nzfat_format);

pub const Type = fat.Type;

pub const Config = struct {
    volume_id: [4]u8,
    label: [11]u8 = "NO NAME    ".*,

    boot_code: ?[]const u8 = null,
    fat_type: ?Type = null,
    align_data: ?bool = null,
    drive_number: ?u8 = null,
    fats: ?u8 = null,
    root_directory_entries: ?u16 = null,
    reserved_sectors: ?u16 = null,
    bytes_per_sector: ?u16 = null,
    sectors_per_cluster: ?u8 = null,
};

pub const Error = error{
    BootCodeTooBig,
    InvalidReservedSectors,
    InvalidSectorsPerCluster,
    IncompatibleFat,
    IncompatibleDevice,
};

pub fn make(blk: anytype, config: Config) !FatParameters {
    const bytes_per_sector: u16 = @intCast(if (config.bytes_per_sector) |bytes_per_sector| v: {
        std.debug.assert(bytes_per_sector >= 512 and bytes_per_sector <= 4096 and std.math.isPowerOfTwo(bytes_per_sector));
        try blk.setLogicalBlockSize(bytes_per_sector);

        break :v bytes_per_sector;
    } else blk.getLogicalBlockSize());

    const blk_size = blk.getSize();

    if (blk_size > std.math.maxInt(u32)) {
        return Error.IncompatibleDevice;
    }

    const fat_blk_size: u32 = @intCast(blk_size);
    const fat_parameters = try getFatParameters(fat_blk_size, bytes_per_sector, config);

    const boot_sector = try blk.map(0);
    defer blk.unmap(0, boot_sector);

    const sector_data = boot_sector.asSlice();
    const bpb: *BiosParameterBlock = std.mem.bytesAsValue(BiosParameterBlock, sector_data);

    bpb.* = BiosParameterBlock{
        .jmp = undefined,
        .oem_identifier = "nzfat0.0".*,
        .bytes_per_sector = bytes_per_sector,
        .sectors_per_cluster = fat_parameters.sectors_per_cluster,
        .reserved_sectors = fat_parameters.reserved_sectors,
        .fats = fat_parameters.fats,
        .root_directory_entries = fat_parameters.root_directory_entries,
        .sector_count = undefined,
        .media_descriptor_type = fat_parameters.media_type,
        .sectors_per_fat = undefined,
        .sectors_per_track = fat_parameters.sectors_per_track,
        .heads = fat_parameters.heads,
        .hidden_sectors = 0, // FIXME: Hidden sectors!
        .large_sector_count = undefined,
    };

    if (fat_blk_size > std.math.maxInt(u16)) {
        bpb.sector_count = 0;
        bpb.large_sector_count = fat_blk_size;
    } else {
        bpb.sector_count = @intCast(fat_blk_size);
        bpb.large_sector_count = 0;
    }

    const fat_start = fat_parameters.reserved_sectors;

    // Zeroing all FAT'S
    for (0..fat_parameters.fats) |current_fat| {
        const current_fat_start = fat_start + current_fat * fat_parameters.fat_size;
        for (0..fat_parameters.fat_size) |current_sector| {
            const fat_sector_index = current_fat_start + current_sector;
            const fat_sector = try blk.map(fat_sector_index);
            defer blk.unmap(fat_sector_index, fat_sector);

            @memset(fat_sector.asSlice(), 0x00);
            try blk.commit(fat_sector_index, fat_sector);
        }
    }

    if (fat_parameters.fat_type == .fat32) {
        bpb.jmp = [3]u8{ 0xEB, 0x58, 0x90 };
        bpb.sectors_per_fat = 0;

        const ebr32: *align(1) ExtendedBootRecord32 = std.mem.bytesAsValue(ExtendedBootRecord32, sector_data[@sizeOf(BiosParameterBlock)..]);
        ebr32.* = ExtendedBootRecord32{
            .sectors_per_fat = fat_parameters.fat_size,
            .flags = 0,
            .fat_version = 0,
            .root_cluster = 2,
            .fsinfo_sector = 1,
            .backup_boot_sector = 6,
            .drive_number = config.drive_number orelse (if (fat_parameters.fat_type == .fat12) 0x00 else 0x80),
            .nt_flags = 0,
            .volume_id = config.volume_id,
            .label = config.label,
            .boot_code = undefined,
        };

        if (config.boot_code) |boot_code| {
            if (boot_code.len > ebr32.boot_code.len) {
                return Error.BootCodeTooBig;
            }

            @memcpy(ebr32.boot_code[0..boot_code.len], boot_code);
            @memset(ebr32.boot_code[boot_code.len..], 0x00);
        } else @memset(&ebr32.boot_code, 0x00); // TODO: Write a simple x86 bootsector to display: Oops! Trying to boot a non-bootable FATXX drive

        const fsinfo_sector = try blk.map(1);
        defer blk.unmap(1, fsinfo_sector);

        const fsinfo_slice = fsinfo_sector.asSlice();
        const fsinfo32: *align(1) FSInfo32 = std.mem.bytesAsValue(FSInfo32, fsinfo_slice);

        const cluster_count = (fat_blk_size - fat_parameters.reserved_sectors - fat_parameters.fat_size * fat_parameters.fats) / fat_parameters.sectors_per_cluster;

        fsinfo32.* = FSInfo32{
            .last_known_free_cluster_count = cluster_count - 1,
            .last_known_available_cluster = 0x3,
        };

        try blk.commit(1, fsinfo_sector);
        // TODO: Copy the boot record and fsinfo ot the backup sectors!
        // TODO: Create root directory
    } else {
        bpb.jmp = [3]u8{ 0xEB, 0x3C, 0x90 };
        bpb.sectors_per_fat = @intCast(fat_parameters.fat_size);

        const ebr: *align(1) ExtendedBootRecord = std.mem.bytesAsValue(ExtendedBootRecord, sector_data[@sizeOf(BiosParameterBlock)..]);

        ebr.* = ExtendedBootRecord{
            .drive_number = config.drive_number orelse (if (fat_parameters.fat_type == .fat12) 0x00 else 0x80),
            .nt_flags = 0,
            .volume_id = config.volume_id,
            .label = config.label,
            .system_identifier = (if (fat_parameters.fat_type == .fat12) "FAT12   " else "FAT16   ").*,
            .boot_code = undefined,
        };

        if (config.boot_code) |boot_code| {
            if (boot_code.len > ebr.boot_code.len) {
                return Error.BootCodeTooBig;
            }

            @memcpy(ebr.boot_code[0..boot_code.len], boot_code);
            @memset(ebr.boot_code[boot_code.len..], 0x00);
        } else @memset(&ebr.boot_code, 0x00); // Same as above

        const root_entries_sectors = ((fat_parameters.root_directory_entries * @sizeOf(DiskDirectoryEntry)) + (bytes_per_sector - 1)) / bytes_per_sector;
        const root_entries_start = fat_parameters.reserved_sectors + (fat_parameters.fats * fat_parameters.fat_size);

        // Zero out all possible root entries
        for (0..root_entries_sectors) |current_root_sector| {
            const root_sector_index = root_entries_start + current_root_sector;
            const root_sector = try blk.map(root_sector_index);
            defer blk.unmap(root_sector_index, root_sector);

            @memset(root_sector.asSlice(), 0x00);
            try blk.commit(root_sector_index, root_sector);
        }
    }

    try blk.commit(0, boot_sector);
    return fat_parameters;
}

pub const FatParameters = struct {
    fat_type: Type,
    fats: u8,
    reserved_sectors: u16,
    media_type: u8,
    heads: u8,
    sectors_per_track: u8,
    root_directory_entries: u16,
    sectors_per_cluster: u8,
    fat_size: u32,

    pub inline fn init(fat_type: Type, fats: u8, reserved_sectors: u16, media_type: u8, heads: u8, sectors_per_track: u8, root_directory_entries: u16, sectors_per_cluster: u8, fat_size: u32) FatParameters {
        return FatParameters{
            .fat_type = fat_type,
            .fats = fats,
            .reserved_sectors = reserved_sectors,
            .media_type = media_type,
            .heads = heads,
            .sectors_per_track = sectors_per_track,
            .root_directory_entries = root_directory_entries,
            .sectors_per_cluster = sectors_per_cluster,
            .fat_size = fat_size,
        };
    }
};

// FIXME: Simplify this!
fn getFatParameters(blk_size: u32, bytes_per_sector: u16, config: Config) !FatParameters {
    const suggested_floppy_parameters = suggestFloppyParameters(blk_size, bytes_per_sector);

    const initial_root_entries: u16 = if (config.root_directory_entries) |root_directory_entries| v: {
        std.debug.assert(root_directory_entries > 0);
        break :v root_directory_entries;
    } else if (suggested_floppy_parameters) |floppy_suggestion|
        floppy_suggestion.root_directory_entries
    else
        0;

    const bytes_per_sector_shift: u4 = @intCast(std.math.log2(bytes_per_sector));
    const initial_reserved_sectors = config.reserved_sectors orelse 1;
    std.debug.assert(initial_reserved_sectors > 0);

    const root_sectors = (initial_root_entries * @sizeOf(fat.DirectoryEntry) + bytes_per_sector - 1) >> bytes_per_sector_shift;
    const usable_sectors = blk_size - (initial_reserved_sectors + root_sectors);
    const fats = config.fats orelse 2;

    // FAT is truly an amazing filesystem :D (Sarcasm)
    const fat_type, const sectors_per_cluster, const fat_size = if (config.fat_type) |f_t| v: {
        if (config.sectors_per_cluster) |s_p_c| {
            std.debug.assert(s_p_c > 0 and s_p_c <= 128);

            const sectors_per_cluster_shift: u3 = @intCast(std.math.log2(s_p_c));

            if (supportsSectorsPerCluster(f_t, fats, usable_sectors, bytes_per_sector_shift, sectors_per_cluster_shift)) |fat_size| {
                break :v .{ f_t, s_p_c, fat_size };
            }

            return Error.InvalidSectorsPerCluster;
        }

        if (suggested_floppy_parameters) |floppy_parameters| {
            if (f_t == floppy_parameters.fat_type) {
                break :v .{ f_t, floppy_parameters.sectors_per_cluster, floppy_parameters.fat_size };
            }
        }

        if (suggestSectorsPerCluster(f_t, fats, usable_sectors, bytes_per_sector_shift, 0)) |suggestion| {
            break :v .{ f_t, suggestion.sectors_per_cluster, suggestion.fat_size };
        }

        return Error.IncompatibleFat;
    } else if (suggested_floppy_parameters) |floppy_parameters|
        .{ floppy_parameters.fat_type, floppy_parameters.sectors_per_cluster, floppy_parameters.fat_size }
    else if (suggestFat(fats, blk_size, usable_sectors, bytes_per_sector_shift)) |fat_params|
        .{ fat_params.fat_type, fat_params.sectors_per_cluster, fat_params.fat_size }
    else
        return Error.IncompatibleDevice;

    const root_entries: u16 = if (fat_type == .fat32)
        0
    else if (initial_root_entries != 0)
        initial_root_entries
    else if (blk_size <= 2880)
        112
    else if (blk_size <= 5760)
        224
    else
        512;

    const final_reserved_sectors: u16 = if (config.reserved_sectors) |sectors| v: {
        if (fat_type == .fat32 and sectors < 9) {
            return Error.InvalidReservedSectors;
        }

        break :v sectors;
    } else switch (fat_type) {
        .fat32 => 9,
        else => 1,
    };

    const root_entry_sectors = ((root_entries * @sizeOf(fat.DirectoryEntry) + bytes_per_sector - 1) >> bytes_per_sector_shift);
    const total_non_data_sectors = final_reserved_sectors + root_entry_sectors;
    const should_align = if (config.align_data) |align_data| align_data else (blk_size > 8400);
    const reserved_sectors = if (should_align) (std.mem.alignForward(u16, total_non_data_sectors, sectors_per_cluster) - root_entry_sectors) else final_reserved_sectors;

    const media_type = if (suggested_floppy_parameters) |floppy_parameters| floppy_parameters.media_type else 0xF8;
    const heads, const sectors_per_track = if (suggested_floppy_parameters) |floppy_parameters|
        .{ floppy_parameters.heads, floppy_parameters.sectors_per_track }
    else v: {
        const geometry = getDriveGeometry(usable_sectors);
        break :v .{ geometry.heads, geometry.sectors_per_track };
    };

    return FatParameters.init(fat_type, fats, reserved_sectors, media_type, heads, sectors_per_track, root_entries, sectors_per_cluster, fat_size);
}

fn getDriveGeometry(usable_sectors: u32) DriveGeometry {
    return v: inline for (drive_geometry_table) |sc_geom| {
        if (usable_sectors <= sc_geom.min_sectors) {
            break :v sc_geom.geometry;
        }
    } else DriveGeometry.init(255, 63);
}

const DriveGeometry = struct {
    heads: u8,
    sectors_per_track: u8,

    pub inline fn init(heads: u8, sectors_per_track: u8) DriveGeometry {
        return DriveGeometry{ .heads = heads, .sectors_per_track = sectors_per_track };
    }
};

const SectorsToDriveGeometry = struct {
    min_sectors: u32,
    geometry: DriveGeometry,

    pub inline fn init(min_sectors: u32, geometry: DriveGeometry) SectorsToDriveGeometry {
        return SectorsToDriveGeometry{ .min_sectors = min_sectors, .geometry = geometry };
    }
};

// NOTE: Taken from SD Memory Card Specifications and ATA/IDE Capacity Limitations for Various Sector Addressing Methods
const drive_geometry_table = [_]SectorsToDriveGeometry{
    SectorsToDriveGeometry.init(4096, DriveGeometry.init(2, 16)),
    SectorsToDriveGeometry.init(32768, DriveGeometry.init(2, 32)),
    SectorsToDriveGeometry.init(65536, DriveGeometry.init(2, 32)),
    SectorsToDriveGeometry.init(262144, DriveGeometry.init(8, 32)),
    SectorsToDriveGeometry.init(524288, DriveGeometry.init(16, 32)),
    SectorsToDriveGeometry.init(1032192, DriveGeometry.init(16, 63)),
    SectorsToDriveGeometry.init(2064384, DriveGeometry.init(32, 63)),
    SectorsToDriveGeometry.init(4128768, DriveGeometry.init(64, 63)),
    SectorsToDriveGeometry.init(8257536, DriveGeometry.init(128, 63)),
};

fn suggestFloppyParameters(blk_size: anytype, bytes_per_sector: u16) ?FatParameters {
    return v: inline for (floppy_fat12_parameters) |floppy_params| {
        if (floppy_params.bytes_per_sector == bytes_per_sector and floppy_params.sectors == blk_size) {
            break :v floppy_params.fat_parameters;
        }
    } else null;
}

const FloppyFatParameters = struct {
    bytes_per_sector: u16,
    sectors: u16,
    fat_parameters: FatParameters,

    pub inline fn init(bytes_per_sector: u16, sectors: u16, fat_parameters: FatParameters) FloppyFatParameters {
        return FloppyFatParameters{
            .bytes_per_sector = bytes_per_sector,
            .sectors = sectors,
            .fat_parameters = fat_parameters,
        };
    }
};

// NOTE: Taken from https://jeffpar.github.io/kbarchive/kb/075/Q75131/
const floppy_fat12_parameters = [_]FloppyFatParameters{
    // 8-inch
    // XXX: Do we need these two 128-byte parameters here? We don't even support a value less than 512 (Maybe we can support them?)
    FloppyFatParameters.init(128, 2002, FatParameters.init(.fat12, 2, 1, 0xFE, 1, 26, 68, 4, 6)),
    FloppyFatParameters.init(128, 4004, FatParameters.init(.fat12, 2, 1, 0xFD, 2, 26, 68, 4, 6)),
    FloppyFatParameters.init(1024, 1232, FatParameters.init(.fat12, 2, 1, 0xFE, 2, 8, 192, 1, 2)),

    // 5 1/4 inch
    FloppyFatParameters.init(512, 320, FatParameters.init(.fat12, 2, 1, 0xFE, 1, 8, 64, 1, 1)),
    FloppyFatParameters.init(512, 360, FatParameters.init(.fat12, 2, 1, 0xFC, 1, 9, 64, 1, 2)),
    FloppyFatParameters.init(512, 640, FatParameters.init(.fat12, 2, 1, 0xFF, 2, 8, 112, 2, 1)),
    FloppyFatParameters.init(512, 720, FatParameters.init(.fat12, 2, 1, 0xFD, 2, 9, 112, 2, 2)),
    FloppyFatParameters.init(512, 2400, FatParameters.init(.fat12, 2, 1, 0xF9, 2, 15, 224, 1, 7)),

    // 3 1/2 inch
    FloppyFatParameters.init(512, 1440, FatParameters.init(.fat12, 2, 1, 0xF9, 2, 9, 112, 2, 3)),
    FloppyFatParameters.init(512, 2880, FatParameters.init(.fat12, 2, 1, 0xF0, 2, 18, 224, 1, 9)),
    FloppyFatParameters.init(512, 5760, FatParameters.init(.fat12, 2, 1, 0xF0, 2, 36, 240, 2, 9)),
};

const FatSuggestion = struct { fat_type: Type, sectors_per_cluster: u8, fat_size: u32 };

fn suggestFat(fats: u8, total_sectors: u32, usable_sectors: u32, bytes_per_sector_shift: u5) ?FatSuggestion {
    if (total_sectors >= 1048576) {
        const initial_sectors_per_cluster: u8 = v: inline for (fat32_size_parameters) |sz_params| {
            if (usable_sectors < sz_params.min_usable_sectors) {
                break :v sz_params.sectors_per_cluster;
            }
        } else 128;

        const initial_sectors_per_cluster_shift: u3 = @intCast(std.math.log2(initial_sectors_per_cluster));
        if (suggestSectorsPerCluster(.fat32, fats, usable_sectors, bytes_per_sector_shift, initial_sectors_per_cluster_shift)) |suggestion| {
            return .{ .fat_type = .fat32, .sectors_per_cluster = suggestion.sectors_per_cluster, .fat_size = suggestion.fat_size };
        }
    }

    // NOTE: Arbitrary start, always try 4 sectors per cluster first with 512-byte sectors
    const fat16_sectors_per_cluster = v: inline for (fat16_size_parameters) |sz_params| {
        if (usable_sectors < sz_params.min_usable_sectors) {
            break :v sz_params.sectors_per_cluster;
        }
    } else 0;

    if (fat16_sectors_per_cluster > 0) {
        const fat16_sectors_per_cluster_shift: u3 = @intCast(std.math.log2(fat16_sectors_per_cluster));

        if (supportsSectorsPerCluster(.fat16, fats, usable_sectors, bytes_per_sector_shift, fat16_sectors_per_cluster_shift)) |fat_size| {
            return .{ .fat_type = .fat16, .sectors_per_cluster = fat16_sectors_per_cluster, .fat_size = fat_size };
        }
    }

    // Fallback to FAT12 if nothing worked
    var current_sectors_per_cluster_shift: u4 = if (bytes_per_sector_shift == 9) 2 else 0;
    while (current_sectors_per_cluster_shift <= fat.max_sectors_per_cluster_shift) : (current_sectors_per_cluster_shift += 1) {
        const sectors_per_cluster_shift: u3 = @intCast(current_sectors_per_cluster_shift);

        if (supportsSectorsPerCluster(.fat12, fats, usable_sectors, bytes_per_sector_shift, sectors_per_cluster_shift)) |fat_size| {
            return .{ .fat_type = .fat12, .sectors_per_cluster = @as(u8, 1) << sectors_per_cluster_shift, .fat_size = fat_size };
        }
    }

    return null;
}

const SectorsPerClusterSuggestion = struct { sectors_per_cluster: u8, fat_size: u32 };

fn suggestSectorsPerCluster(fat_type: Type, fats: u8, usable_sectors: u32, bytes_per_sector_shift: u5, initial: u3) ?SectorsPerClusterSuggestion {
    var current_sectors_per_cluster_shift: u4 = initial;

    while (current_sectors_per_cluster_shift <= fat.max_sectors_per_cluster_shift) : (current_sectors_per_cluster_shift += 1) {
        const sectors_per_cluster_shift: u3 = @intCast(current_sectors_per_cluster_shift);

        if (supportsSectorsPerCluster(fat_type, fats, usable_sectors, bytes_per_sector_shift, sectors_per_cluster_shift)) |fat_size| {
            return SectorsPerClusterSuggestion{ .sectors_per_cluster = @as(u8, 1) << sectors_per_cluster_shift, .fat_size = fat_size };
        }
    }

    return null;
}

const SizeToSectorsPerCluster = struct {
    min_usable_sectors: u32,
    sectors_per_cluster: u8,

    pub inline fn init(min_usable_sectors: u32, sectors_per_cluster: u8) SizeToSectorsPerCluster {
        return SizeToSectorsPerCluster{ .min_usable_sectors = min_usable_sectors, .sectors_per_cluster = sectors_per_cluster };
    }
};

const fat16_size_parameters = [_]SizeToSectorsPerCluster{
    SizeToSectorsPerCluster.init(8400, 0),
    SizeToSectorsPerCluster.init(32680, 2),
    SizeToSectorsPerCluster.init(262144, 4),
    SizeToSectorsPerCluster.init(524288, 8),

    // Unused unless specified
    SizeToSectorsPerCluster.init(1048576, 16),
    SizeToSectorsPerCluster.init(2097152, 32),
    SizeToSectorsPerCluster.init(4194304, 64),
    SizeToSectorsPerCluster.init(8388608, 128),
    SizeToSectorsPerCluster.init(std.math.maxInt(u32), 0),
};

const fat32_size_parameters = [_]SizeToSectorsPerCluster{
    SizeToSectorsPerCluster.init(66600, 0),
    SizeToSectorsPerCluster.init(532480, 1),
    SizeToSectorsPerCluster.init(16777216, 8),
    SizeToSectorsPerCluster.init(33554432, 16),
    SizeToSectorsPerCluster.init(67108864, 32),
    SizeToSectorsPerCluster.init(std.math.maxInt(u32), 64),
};

pub fn supportsSectorsPerCluster(fat_type: Type, fats: u8, sectors: u32, bytes_per_sector_shift: u5, sectors_per_cluster_shift: u3) ?u32 {
    std.debug.assert(bytes_per_sector_shift >= fat.min_bytes_per_sector_shift);

    const bytes_per_sector = (@as(u32, 1) << bytes_per_sector_shift);
    const sectors_per_cluster = (@as(u32, 1) << sectors_per_cluster_shift);

    const min_clusters = fat.min_clusters.get(fat_type);
    const max_clusters = fat.max_clusters.get(fat_type);

    const total_clusters = (sectors >> sectors_per_cluster_shift);
    // NOTE: This multiplication is safe as bytes_per_sector_shift will always be >= 9
    const maximum_fats_clusters = (fats * ((max_clusters + (bytes_per_sector << sectors_per_cluster_shift) - 1) >> (bytes_per_sector_shift + sectors_per_cluster_shift))) - 1;

    // Too small or Too big, then discard
    if (total_clusters < maximum_fats_clusters or (total_clusters - maximum_fats_clusters) > max_clusters) {
        return null;
    }

    // HACK: With the above check we know we'll be staying in range of FAT32 atmost, so we take advantage of knowing that the 4 msb's are unused (as FAT32 only uses 28 bits) so we're able to stay within the u32 range without overflowing and avoiding higher bit widths!
    const fat_size: u32 = @intCast(((total_clusters + total_clusters >> fat.div_shift.get(fat_type)) + (@as(u32, 1) << bytes_per_sector_shift) - 1) >> bytes_per_sector_shift);
    const fats_clusters = fats * ((fat_size + (sectors_per_cluster - 1)) >> sectors_per_cluster_shift);
    const data_clusters = total_clusters - fats_clusters;

    if (data_clusters < min_clusters or data_clusters > max_clusters) {
        return null;
    }

    return fat_size;
}

const testing = std.testing;

test {}
