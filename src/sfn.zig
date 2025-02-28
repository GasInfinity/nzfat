const std = @import("std");

pub const allowed_symbols = "$%'-_@~`!(){}^#&";
pub const base_len = 8;
pub const extension_len = 3;
pub const len = base_len + extension_len;

pub fn isAllowedCharacter(c: u8) bool {
    return c > 127 or std.ascii.isAlphanumeric(c) or std.mem.indexOf(u8, allowed_symbols, &[_]u8{c}) != null;
}

pub fn codepageToShortFilename(value: []const u8) [len]u8 {
    const trimmed = std.mem.trim(u8, value, " ");

    var sfn: [len]u8 = [_]u8{' '} ** len;
    const last_possible_dot = std.mem.lastIndexOf(u8, trimmed, ".");

    const base_copied_characters = if (last_possible_dot) |last_dot| base: {
        const extension = trimmed[(last_dot + 1)..];
        const extension_copied_characters = @min(extension.len, extension_len);

        for (0..extension_copied_characters) |i| {
            const c = std.ascii.toUpper(extension[i]);
            sfn[base_len..][i] = if (isAllowedCharacter(c)) c else '_';
        }

        break :base @min(trimmed[0..last_dot].len, base_len);
    } else @min(trimmed.len, base_len);

    for (0..base_copied_characters) |i| {
        const c = std.ascii.toUpper(trimmed[i]);
        sfn[i] = if (isAllowedCharacter(c)) c else '_';
    }

    return sfn;
}

pub fn shortFilenameToCodepage(comptime T: type, buf: []T, sfn: [len]u8) usize {
    const base = std.mem.trimRight(u8, sfn[0..base_len], " ");
    const extension = std.mem.trimRight(u8, sfn[base_len..], " ");

    var written: usize = 0;

    for (base) |v| {
        buf[written] = std.mem.nativeToLittle(T, @as(T, v));
        written += 1;
    }

    if (extension.len > 0) {
        buf[written] = std.mem.nativeToLittle(T, @as(T, '.'));
        written += 1;

        for (extension) |v| {
            buf[written] = std.mem.nativeToLittle(T, @as(T, v));
            written += 1;
        }
    }

    return written;
}

pub fn codepageEqlIgnoreCase(left: []const u8, right: []const u8) bool {
    return std.ascii.eqlIgnoreCase(left, right);
}

const testing = std.testing;

test "asciiToShortFilename converts only base" {
    try testing.expectEqualSlices(u8, "HELLO      ", &codepageToShortFilename("hello"));
}

test "asciiToShortFilename converts base and extension" {
    try testing.expectEqualSlices(u8, "HELLO   TXT", &codepageToShortFilename("hello.txt"));
}

test "asciiToShortFilename truncates base" {
    try testing.expectEqualSlices(u8, "AREALLYL   ", &codepageToShortFilename("areallylongfile"));
}

test "asciiToShortFilename truncates base with extension" {
    try testing.expectEqualSlices(u8, "AREALLYLTXT", &codepageToShortFilename("areallylongfile.txt"));
}

test "asciiToShortFilename truncates base and extension" {
    try testing.expectEqualSlices(u8, "AREALLYLLON", &codepageToShortFilename("areallylongfile.longtxt"));
}

test "asciiToShortFilename trims base" {
    try testing.expectEqualSlices(u8, "HELLO      ", &codepageToShortFilename("    hello"));
}

test "asciiToShortFilename trims base and extension" {
    try testing.expectEqualSlices(u8, "HELLO   TXT", &codepageToShortFilename("    hello.txt    "));
}
