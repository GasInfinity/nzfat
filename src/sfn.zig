const std = @import("std");

pub const allowed_symbols = "$%'-_@~`!(){}^#&";
pub const extended_allowed_symbols = allowed_symbols ++ "+,;=[].";

pub const base_len = 8;
pub const extension_len = 3;
pub const len = base_len + extension_len;

pub fn isAllowedCharacter(c: u8) bool {
    return c > 127 or std.ascii.isAlphanumeric(c) or std.mem.indexOf(u8, allowed_symbols, &[_]u8{c}) != null;
}

pub fn checksum(value: [len]u8) u8 {
    var sum: u8 = 0;

    inline for (0..value.len) |i| {
        sum = std.math.rotr(u8, sum, 1) +% value[i];
    }

    return sum;
}

const ShortFilenameResult = struct {
    sfn: [len]u8,
    lossy: bool,
};

// TODO: Return case information for NT flags?
// FIXME: Refactor this?
pub fn codepageToShortFilename(value: []const u8) ShortFilenameResult {
    const trimmed = std.mem.trim(u8, value, " ");

    var sfn: [len]u8 = [_]u8{' '} ** len;
    var lossy = false;

    const last_possible_dot = std.mem.lastIndexOf(u8, trimmed, ".");

    const base_copying_characters = if (last_possible_dot) |last_dot| base: {
        const extension = trimmed[(last_dot + 1)..];
        const extension_copied_characters = @min(extension.len, extension_len);

        for (0..extension_copied_characters) |i| {
            const real_c = extension[i];
            const c = std.ascii.toUpper(real_c);

            if (real_c != c) {
                lossy = true;
            }

            sfn[base_len..][i] = c;
        }

        break :base @min(trimmed[0..last_dot].len, base_len);
    } else @min(trimmed.len, base_len);

    if (base_copying_characters > 0) {
        const first_real_c = trimmed[0];
        const first_c = std.ascii.toUpper(first_real_c);
        sfn[0] = if (first_c == 0xE5) 0x05 else first_c;

        if (first_real_c != first_c) {
            lossy = true;
        }

        for (1..base_copying_characters) |i| {
            const real_c = trimmed[i];
            const c = std.ascii.toUpper(real_c);

            if (real_c != c) {
                lossy = true;
            }

            sfn[i] = c;
        }
    }

    return ShortFilenameResult{
        .sfn = sfn,
        .lossy = lossy,
    };
}

pub fn shortFilenameToT(comptime T: type, buf: *[len + 1]T, sfn: [len]u8) usize {
    const base = std.mem.trimRight(u8, sfn[0..base_len], " ");
    const extension = std.mem.trimRight(u8, sfn[base_len..], " ");

    var written: usize = 0;

    if (base.len > 0) {
        const first_v = base[0];
        buf[written] = std.mem.nativeToLittle(T, (if (first_v == 0x05) 0xE5 else first_v));
        written += 1;

        for (base[1..]) |v| {
            buf[written] = std.mem.nativeToLittle(T, v);
            written += 1;
        }
    }

    if (extension.len > 0) {
        buf[written] = std.mem.nativeToLittle(T, '.');
        written += 1;

        for (extension) |v| {
            buf[written] = std.mem.nativeToLittle(T, v);
            written += 1;
        }
    }

    return written;
}

const testing = std.testing;

test "codepageToShortFilename converts only base" {
    try testing.expectEqualSlices(u8, "HELLO      ", &codepageToShortFilename("hello"));
}

test "codepageToShortFilename converts base and extension" {
    try testing.expectEqualSlices(u8, "HELLO   TXT", &codepageToShortFilename("hello.txt"));
}

test "codepageToShortFilename truncates base" {
    try testing.expectEqualSlices(u8, "AREALLYL   ", &codepageToShortFilename("areallylongfile"));
}

test "codepageToShortFilename truncates base with extension" {
    try testing.expectEqualSlices(u8, "AREALLYLTXT", &codepageToShortFilename("areallylongfile.txt"));
}

test "codepageToShortFilename truncates base and extension" {
    try testing.expectEqualSlices(u8, "AREALLYLLON", &codepageToShortFilename("areallylongfile.longtxt"));
}

test "codepageToShortFilename trims base" {
    try testing.expectEqualSlices(u8, "HELLO      ", &codepageToShortFilename("    hello"));
}

test "codepageToShortFilename trims base and extension" {
    try testing.expectEqualSlices(u8, "HELLO   TXT", &codepageToShortFilename("    hello.txt    "));
}
