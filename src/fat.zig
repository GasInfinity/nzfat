const std = @import("std");

pub const min_bytes_per_sector = 512;
pub const min_bytes_per_sector_shift = std.math.log2(min_bytes_per_sector);

pub const max_sectors_per_cluster = 128;
pub const max_sectors_per_cluster_shift = std.math.log2(max_sectors_per_cluster);

pub const Type = enum(u2) { fat12, fat16, fat32 };
pub const min_clusters = std.EnumArray(Type, u32).initDefault(null, .{
    .fat12 = 0x1,
    .fat16 = 0xFF5,
    .fat32 = 0xFFF5,
});

pub const max_clusters = std.EnumArray(Type, u32).initDefault(null, .{
    .fat12 = 0xFF4,
    .fat16 = 0xFFF4,
    .fat32 = 0xFFFFFF6,
});

// NOTE: These are used in the formula -> (cluster_index + cluster_index >> div_shift) << mul_shift
pub const mul_shift = std.EnumArray(Type, u1).initDefault(null, .{
    .fat12 = 0,
    .fat16 = 0,
    .fat32 = 1,
});

pub const div_shift = std.EnumArray(Type, u1).initDefault(null, .{
    .fat12 = 1,
    .fat16 = 0,
    .fat32 = 0,
});

pub fn SuggestCluster(comptime maximum_supported_fat_type: Type) type {
    return switch (maximum_supported_fat_type) {
        .fat12 => u12,
        .fat16 => u16,
        .fat32 => u32,
    };
}

comptime {
    std.debug.assert(@sizeOf(LongFileNameEntry) == @sizeOf(DirectoryEntry));
}

pub const BiosParameterBlock = extern struct {
    jmp: [3]u8 align(1),
    oem_identifier: [8]u8 align(1),
    bytes_per_sector: u16 align(1),
    sectors_per_cluster: u8 align(1),
    reserved_sectors: u16 align(1),
    fats: u8 align(1),
    root_directory_entries: u16 align(1),
    sector_count: u16 align(1),
    media_descriptor_type: u8 align(1),
    sectors_per_fat: u16 align(1),
    sectors_per_track: u16 align(1),
    heads: u16 align(1),
    hidden_sectors: u32 align(1),
    large_sector_count: u32 align(1),
};

pub const ExtendedBootRecord = extern struct {
    drive_number: u8 align(1),
    nt_flags: u8 align(1),
    signature: u8 align(1) = 0x29,
    volume_id: [4]u8 align(1),
    label: [11]u8 align(1),
    system_identifier: [8]u8 align(1) = "FAT     ".*,
    boot_code: [448]u8,
    boot_signature: u16 = 0xAA55,
};

pub const ExtendedBootRecord32 = extern struct {
    sectors_per_fat: u32 align(1),
    flags: u16 align(1), // FIXME: This must be a packed struct
    fat_version: u16 align(1),
    root_cluster: u32 align(1),
    fsinfo_sector: u16 align(1),
    backup_boot_sector: u16 align(1),
    reserved: [12]u8 align(1) = std.mem.zeroes([12]u8),
    drive_number: u8 align(1),
    nt_flags: u8 align(1),
    signature: u8 align(1) = 0x28,
    volume_id: [4]u8 align(1),
    label: [11]u8 align(1),
    system_identifier: [8]u8 align(1) = "FAT32   ".*,
    boot_code: [420]u8,
    boot_signature: u16 = 0xAA55,
};

pub const FSInfo32 = extern struct {
    lead_signature: u32 align(1) = 0x41615252,
    reserved1: [480]u8 align(1) = std.mem.zeroes([480]u8),
    signature: u32 align(1) = 0x61417272,
    last_known_free_cluster_count: u32 align(1),
    last_known_available_cluster: u32 align(1),
    reserved2: [12]u8 align(1) = std.mem.zeroes([12]u8),
    trail_signature: u32 align(1) = 0xAA550000,
};

pub const Attributes = packed struct(u8) {
    pub const long_name = Attributes{ .read_only = true, .hidden = true, .system = true, .volume_id = true };

    read_only: bool = false,
    hidden: bool = false,
    system: bool = false,
    volume_id: bool = false,
    directory: bool = false,
    archive: bool = false,
    _: u2 = 0,

    pub fn isLongName(attributes: Attributes) bool {
        return attributes.read_only and attributes.hidden and attributes.hidden and attributes.volume_id;
    }
};

pub const Time = packed struct(u16) { seconds: u5, minutes: u6, hours: u5 };
pub const Date = packed struct(u16) { day: u5, month: u4, year: u7 };

pub const DirectoryEntry = extern struct {
    pub const deletion_flag = 0xE5;
    pub const dot_name = ".          ";
    pub const dot_dot_name = "..         ";

    name: [11]u8 align(1),
    attributes: Attributes align(1),
    reserved: u8 align(1) = 0,
    creation_time_tenth: u8 align(1),
    creation_time: Time align(1),
    creation_date: Date align(1),
    last_access_date: Date align(1),
    first_cluster_hi: u16 align(1),
    write_time: Time align(1),
    write_date: Date align(1),
    first_cluster_lo: u16 align(1),
    file_size: u32 align(1),

    pub fn isFirstEmptyEntry(entry: DirectoryEntry) bool {
        return entry.name[0] == 0x00;
    }

    pub fn isDeleted(entry: DirectoryEntry) bool {
        return entry.name[0] == deletion_flag;
    }

    pub fn isFree(entry: DirectoryEntry) bool {
        return entry.isFirstEmptyEntry() or entry.isDeleted();
    }
};

pub const LongFileNameEntry = extern struct {
    const name1_len = 5;
    const name2_len = 6;
    const name3_len = 2;

    pub const last_entry_mask: u8 = 0x40;
    pub const stored_name_length = name1_len + name2_len + name3_len;

    order: u8 align(1),
    name1: [name1_len]u16 align(1),
    attributes: Attributes align(1) = Attributes.long_name,
    type: u8 align(1) = 0,
    checksum: u8 align(1),
    name2: [name2_len]u16 align(1),
    first_cluster_lo: u16 align(1) = 0,
    name3: [name3_len]u16 align(1),

    pub fn init(order: u8, checksum: u8, utf16: []const u16) LongFileNameEntry {
        return LongFileNameEntry{
            .order = order,
            .checksum = checksum,
            .name1 = utf16[0..name1_len].*,
            .name2 = utf16[name1_len..][0..name2_len].*,
            .name3 = utf16[(name1_len + name2_len)..][0..name3_len].*,
        };
    }

    pub fn initLast(order: u8, checksum: u8, utf16: []const u16) LongFileNameEntry {
        if (utf16.len == stored_name_length) {
            return init(order, checksum, utf16);
        }

        const name1, const name2, const name3 = names: {
            if (utf16.len > name1_len + name2_len) {
                break :names .{ utf16[0..name1_len].*, utf16[name1_len..][0..name2_len].*, [_]u16{ utf16[name1_len + name2_len], 0x0000 } };
            }

            if (utf16.len > name1_len) {
                const utf16_next = utf16[name1_len..];

                const name2, const name3 = if (utf16_next.len == name2_len)
                    .{ utf16_next[0..name2_len].*, [_]u16{ 0x0000, 0xFFFF } }
                else v: {
                    var name2: [name2_len]u16 = undefined;
                    @memcpy(name2[0..utf16_next.len], utf16_next);
                    name2[utf16_next.len] = 0x0000;

                    if ((utf16_next.len + 1) < name2_len) {
                        @memset(name2[(utf16_next.len + 1)..], 0xFFFF);
                    }

                    break :v .{ name2, [_]u16{ 0xFFFF, 0xFFFF } };
                };

                break :names .{ utf16[0..name1_len].*, name2, name3 };
            }

            const name1, const name2 = if (utf16.len == name1_len)
                .{ utf16[0..name1_len].*, ([_]u16{0x0000} ++ [_]u16{0xFFFF} ** (name2_len - 1)) }
            else v: {
                var name1: [name1_len]u16 = undefined;
                @memcpy(name1[0..utf16.len], utf16);
                name1[utf16.len] = 0x0000;

                if ((utf16.len + 1) < name1_len) {
                    @memset(name1[(utf16.len + 1)..], 0xFFFF);
                }

                break :v .{ name1, [_]u16{0xFFFF} ** name2_len };
            };

            break :names .{ name1, name2, [_]u16{0xFFFF} ** name3_len };
        };

        return LongFileNameEntry{
            .order = order,
            .checksum = checksum,
            .name1 = name1,
            .name2 = name2,
            .name3 = name3,
        };
    }

    pub fn isLast(lfn: LongFileNameEntry) bool {
        return (lfn.order & last_entry_mask) != 0;
    }

    pub fn appendEntryNameReverse(lfn: LongFileNameEntry, buf: []u16, current_end: *usize) void {
        @memcpy(buf[(current_end.* - lfn.name3.len)..current_end.*], &lfn.name3);
        current_end.* -= lfn.name3.len;

        @memcpy(buf[(current_end.* - lfn.name2.len)..current_end.*], &lfn.name2);
        current_end.* -= lfn.name2.len;

        @memcpy(buf[(current_end.* - lfn.name1.len)..current_end.*], &lfn.name1);
        current_end.* -= lfn.name1.len;
    }

    pub fn appendLastEntryNameReverse(lfn: LongFileNameEntry, buf: []u16, current_end: *usize) void {
        var tmp: [6]u16 = undefined;

        @memcpy(tmp[0..lfn.name3.len], &lfn.name3);
        if (!tryAppendNamePartiallyReverse(tmp[0..lfn.name3.len], buf, current_end)) {
            @memcpy(tmp[0..lfn.name2.len], &lfn.name2);
            if (!tryAppendNamePartiallyReverse(tmp[0..lfn.name2.len], buf, current_end)) {
                @memcpy(tmp[0..lfn.name1.len], &lfn.name1);
                _ = tryAppendNamePartiallyReverse(tmp[0..lfn.name1.len], buf, current_end);
                return;
            }

            @memcpy(buf[(current_end.* - lfn.name1.len)..current_end.*], &lfn.name1);
            current_end.* -= lfn.name1.len;
            return;
        }

        @memcpy(buf[(current_end.* - lfn.name2.len)..current_end.*], &lfn.name2);
        current_end.* -= lfn.name2.len;

        @memcpy(buf[(current_end.* - lfn.name1.len)..current_end.*], &lfn.name1);
        current_end.* -= lfn.name1.len;
    }

    inline fn tryAppendNamePartiallyReverse(name: []const u16, buf: []u16, current_end: *usize) bool {
        const first_index = std.mem.indexOfAny(u16, name, &[_]u16{ 0x0000, 0xFFFF });

        if (first_index) |first| {
            const appending_name = name[0..first];
            @memcpy(buf[(current_end.* - appending_name.len)..current_end.*], appending_name);
            current_end.* -= appending_name.len;
            return name[first] == 0x0000;
        }

        @memcpy(buf[(current_end.* - name.len)..current_end.*], name);
        return true;
    }
};
