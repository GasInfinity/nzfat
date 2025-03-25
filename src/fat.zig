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

pub const allowed_media_values = [_]u8{ 0xF0, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF };
pub const allowed_symbols = "$%'-_@~`!(){}^#&";
pub const extended_allowed_symbols = allowed_symbols ++ "+,;=[].";

pub const AsciiCodepageContext = struct {
    pub const AsciiCaseResult = struct { std.BoundedArray(u8, 1), ?bool };

    pub inline fn toUpper(_: AsciiCodepageContext, slice: []const u8) AsciiCaseResult {
        const c = slice[0];
        const converted, const is_lower = if (std.ascii.isAlphabetic(c)) v: {
            const as_upper = std.ascii.toUpper(c);
            break :v .{ as_upper, c != as_upper };
        } else .{ c, null };

        return .{ std.BoundedArray(u8, 1).fromSlice(&[_]u8{converted}) catch unreachable, is_lower };
    }

    pub inline fn toLower(_: AsciiCodepageContext, slice: []const u8) AsciiCaseResult {
        const c = slice[0];
        const converted, const is_lower = if (std.ascii.isAlphabetic(c)) v: {
            const as_lower = std.ascii.toLower(c);
            break :v .{ as_lower, c == as_lower };
        } else .{ c, null };

        return .{ std.BoundedArray(u8, 1).fromSlice(&[_]u8{converted}) catch unreachable, is_lower };
    }
};

pub const sfn = struct {
    pub const max_base_len = 8;
    pub const max_extension_len = 3;
    pub const stored_len = max_base_len + max_extension_len;
    pub const max_len = stored_len + 1;
    // NOTE: +1 Because we may want to add a null terminator
    pub const Display = std.BoundedArray(u8, max_len + 1);

    pub fn isAllowedCharacter(c: u8) bool {
        return c > 127 or std.ascii.isAlphanumeric(c) or std.mem.indexOf(u8, allowed_symbols, &[_]u8{c}) != null;
    }

    pub fn checksum(value: [stored_len]u8) u8 {
        var sum: u8 = 0;

        inline for (0..value.len) |i| {
            sum = std.math.rotr(u8, sum, 1) +% value[i];
        }

        return sum;
    }

    pub fn display(filename: *Display, stored: [stored_len]u8, base_lower: bool, extension_lower: bool, oem_ctx: anytype) void {
        const base = std.mem.trimRight(u8, stored[0..max_base_len], " ");
        const extension = std.mem.trimRight(u8, stored[max_base_len..], " ");

        if (base_lower) {
            for (0..base.len) |i| {
                const lower_bytes, _ = oem_ctx.toLower(base[i..]);
                filename.appendSliceAssumeCapacity(lower_bytes.constSlice());
            }
        } else {
            for (0..base.len) |i| {
                filename.appendAssumeCapacity(base[i]);
            }
        }

        if (extension.len > 0) {
            filename.appendAssumeCapacity('.');

            if (extension_lower) {
                for (0..extension.len) |i| {
                    const lower_bytes, _ = oem_ctx.toLower(extension[i..]);
                    filename.appendSliceAssumeCapacity(lower_bytes.constSlice());
                }
            } else {
                for (0..extension.len) |i| {
                    filename.appendAssumeCapacity(extension[i]);
                }
            }
        }
    }

    pub const StoreResult = struct { result: [stored_len]u8, lossy: bool, lower_base: bool, lower_extension: bool };
    pub fn store(filename: []const u8, codepage_ctx: anytype) StoreResult {
        const last_possible_dot = std.mem.lastIndexOf(u8, filename, ".");
        const base, const extension = if (last_possible_dot) |last_dot|
            .{ filename[0..last_dot], filename[(last_dot + 1)..] }
        else
            .{ filename, &[_]u8{} };

        var stored_sfn: [stored_len]u8 = [_]u8{' '} ** stored_len;
        const base_result = storePart(max_base_len, stored_sfn[0..max_base_len], base, codepage_ctx);
        const extension_result = storePart(max_extension_len, stored_sfn[max_base_len..], extension, codepage_ctx);

        if (stored_sfn[0] == DirectoryEntry.deletion_flag) {
            stored_sfn[0] = DirectoryEntry.stored_e5_flag;
        }

        const lossy = base_result.lossy or extension_result.lossy;
        return StoreResult{
            .result = stored_sfn,
            .lossy = lossy,
            .lower_base = !lossy and base_result.lower,
            .lower_extension = !lossy and extension_result.lower,
        };
    }

    const StorePartResult = struct { lossy: bool, lower: bool };
    fn storePart(comptime max_part_len: comptime_int, buf: *[max_part_len]u8, filename_part: []const u8, oem_ctx: anytype) StorePartResult {
        var lossy = filename_part.len > max_part_len;
        var lower: ?bool = null;
        var index: usize = 0;
        while (index < filename_part.len and index < max_part_len) {
            const current_part_slice = filename_part[index..];
            const upper_bytes, const is_lower = oem_ctx.toUpper(current_part_slice);
            std.debug.assert(upper_bytes.len <= current_part_slice.len);

            if (index + upper_bytes.len > max_part_len) {
                break;
            }

            if (lower) |was_lower| {
                if (was_lower != is_lower or lossy) {
                    lossy = true;
                    lower = false;
                }
            } else {
                lower = is_lower;
            }

            @memcpy(buf[index..][0..upper_bytes.len], upper_bytes.constSlice());
            index += upper_bytes.len;
        }

        return StorePartResult{ .lossy = lossy, .lower = lower orelse false };
    }
};

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
    pub const max_boot_code_len = 448;

    drive_number: u8 align(1),
    nt_flags: u8 align(1),
    signature: u8 align(1) = 0x29,
    volume_id: [4]u8 align(1),
    label: [11]u8 align(1),
    system_identifier: [8]u8 align(1) = "FAT     ".*,
    boot_code: [max_boot_code_len]u8,
    boot_signature: u16 = 0xAA55,
};

pub const ExtendedBootRecord32 = extern struct {
    pub const max_boot_code_len = 420;

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
    boot_code: [max_boot_code_len]u8,
    boot_signature: u16 = 0xAA55,
};

pub const FSInfo32 = extern struct {
    pub const lead_signature_value = 0x41615252;
    pub const signature_value = 0x61417272;
    pub const trail_signature_value = 0xAA550000;

    lead_signature: u32 align(1) = lead_signature_value,
    reserved1: [480]u8 align(1) = std.mem.zeroes([480]u8),
    signature: u32 align(1) = signature_value,
    last_known_free_cluster_count: u32 align(1),
    last_known_available_cluster: u32 align(1),
    reserved2: [12]u8 align(1) = std.mem.zeroes([12]u8),
    trail_signature: u32 align(1) = trail_signature_value,
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

pub const ExtraAttributes = packed struct(u8) {
    _: u3 = 0,
    lower_base: bool,
    lower_extension: bool,
    _2: u3 = 0,
};

pub const DirectoryEntry = extern struct {
    pub const deletion_flag = 0xE5;
    pub const stored_e5_flag = 0x05;
    pub const dot_name = ".          ";
    pub const dot_dot_name = "..         ";

    name: [11]u8 align(1),
    attributes: Attributes align(1),
    reserved: ExtraAttributes align(1) = std.mem.zeroes(ExtraAttributes),
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
            return init(last_entry_mask | order, checksum, utf16);
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
            .order = last_entry_mask | order,
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
        current_end.* -= name.len;
        return true;
    }
};

const testing = std.testing;

test "sfn.store handles non-lossy uppercase basename only" {
    try testing.expectEqualDeep(sfn.StoreResult{
        .result = "HELLO      ".*,
        .lossy = false,
        .lower_base = false,
        .lower_extension = false,
    }, sfn.store("HELLO", AsciiCodepageContext{}));
}

test "sfn.store handles non-lossy lowercase basename only" {
    try testing.expectEqualDeep(sfn.StoreResult{
        .result = "HELLO      ".*,
        .lossy = false,
        .lower_base = true,
        .lower_extension = false,
    }, sfn.store("hello", AsciiCodepageContext{}));
}

test "sfn.store handles non-lossy uppercase basename and uppercase extension" {
    try testing.expectEqualDeep(sfn.StoreResult{
        .result = "HELLO   TXT".*,
        .lossy = false,
        .lower_base = false,
        .lower_extension = false,
    }, sfn.store("HELLO.TXT", AsciiCodepageContext{}));
}

test "sfn.store handles non-lossy lowercase basename and uppercase extension" {
    try testing.expectEqualDeep(sfn.StoreResult{
        .result = "HELLO   TXT".*,
        .lossy = false,
        .lower_base = true,
        .lower_extension = false,
    }, sfn.store("hello.TXT", AsciiCodepageContext{}));
}

test "sfn.store handles non-lossy uppercase basename and lowercase extension" {
    try testing.expectEqualDeep(sfn.StoreResult{
        .result = "HELLO   TXT".*,
        .lossy = false,
        .lower_base = false,
        .lower_extension = true,
    }, sfn.store("HELLO.txt", AsciiCodepageContext{}));
}

test "sfn.store handles non-lossy lowercase basename and lowercase extension" {
    try testing.expectEqualDeep(sfn.StoreResult{
        .result = "HELLO   TXT".*,
        .lossy = false,
        .lower_base = true,
        .lower_extension = true,
    }, sfn.store("hello.txt", AsciiCodepageContext{}));
}

test "sfn.store handles lossy basename" {
    try testing.expectEqualDeep(sfn.StoreResult{
        .result = "HELLOWORTXT".*,
        .lossy = true,
        .lower_base = false,
        .lower_extension = false,
    }, sfn.store("helloworld.txt", AsciiCodepageContext{}));
}

test "sfn.store handles lossy extension" {
    try testing.expectEqualDeep(sfn.StoreResult{
        .result = "HELLO   TXT".*,
        .lossy = true,
        .lower_base = false,
        .lower_extension = false,
    }, sfn.store("hello.txtwhat", AsciiCodepageContext{}));
}

test "sfn.store handles uppercase basename with 0xE5" {
    try testing.expectEqualDeep(sfn.StoreResult{
        .result = "\x05LLO       ".*,
        .lossy = false,
        .lower_base = false,
        .lower_extension = false,
    }, sfn.store("\xE5LLO", AsciiCodepageContext{}));
}

test "sfn.store handles lowercase basename with 0xE5" {
    try testing.expectEqualDeep(sfn.StoreResult{
        .result = "\x05LLO       ".*,
        .lossy = false,
        .lower_base = true,
        .lower_extension = false,
    }, sfn.store("\xE5llo", AsciiCodepageContext{}));
}

test "sfn.display handles uppercase basename only" {
    var buf = sfn.Display.init(0) catch unreachable;
    sfn.display(&buf, "HELLO      ".*, false, false, AsciiCodepageContext{});

    try testing.expectEqualSlices(u8, "HELLO", buf.constSlice());
}

test "sfn.display handles lowercase basename only" {
    var buf = sfn.Display.init(0) catch unreachable;
    sfn.display(&buf, "HELLO      ".*, true, false, AsciiCodepageContext{});

    try testing.expectEqualSlices(u8, "hello", buf.constSlice());
}

test "sfn.display handles uppercase extension only" {
    var buf = sfn.Display.init(0) catch unreachable;
    sfn.display(&buf, "        TXT".*, false, false, AsciiCodepageContext{});

    try testing.expectEqualSlices(u8, ".TXT", buf.constSlice());
}

test "sfn.display handles lowercase extension only" {
    var buf = sfn.Display.init(0) catch unreachable;
    sfn.display(&buf, "        TXT".*, false, true, AsciiCodepageContext{});

    try testing.expectEqualSlices(u8, ".txt", buf.constSlice());
}

test "sfn.display handles uppercase basename and uppercase extension" {
    var buf = sfn.Display.init(0) catch unreachable;
    sfn.display(&buf, "HELLO   TXT".*, false, false, AsciiCodepageContext{});

    try testing.expectEqualSlices(u8, "HELLO.TXT", buf.constSlice());
}

test "sfn.display handles lowercase basename and uppercase extension" {
    var buf = sfn.Display.init(0) catch unreachable;
    sfn.display(&buf, "HELLO   TXT".*, true, false, AsciiCodepageContext{});

    try testing.expectEqualSlices(u8, "hello.TXT", buf.constSlice());
}

test "sfn.display handles uppercase basename and lowercase extension" {
    var buf = sfn.Display.init(0) catch unreachable;
    sfn.display(&buf, "HELLO   TXT".*, false, true, AsciiCodepageContext{});

    try testing.expectEqualSlices(u8, "HELLO.txt", buf.constSlice());
}

test "sfn.display handles lowercase basename and lowercase extension" {
    var buf = sfn.Display.init(0) catch unreachable;
    sfn.display(&buf, "HELLO   TXT".*, true, true, AsciiCodepageContext{});

    try testing.expectEqualSlices(u8, "hello.txt", buf.constSlice());
}
