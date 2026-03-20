// Key-class pseudonymization layer.
//
// Maps Linux evdev keycodes to one of 14 keyboard-region classes.
// SIGINT never stores which specific letter was pressed — only the
// region of the keyboard, preserving timing patterns while preventing
// content reconstruction from exfiltrated profiles.

/// Pseudonymized keyboard region. Timing features are computed against
/// digraphs of these classes, not literal character pairs.
pub const KeyClass = enum(u8) {
    home_l, // ASDF row, left hand (A, S, D, F, G)
    home_r, // ASDF row, right hand (H, J, K, L, ;, ')
    upper_l, // QWERTY row, left hand (Q, W, E, R, T)
    upper_r, // QWERTY row, right hand (Y, U, I, O, P)
    lower_l, // ZXCV row, left hand (Z, X, C, V, B)
    lower_r, // ZXCV row, right hand (N, M, ,, ., /)
    mod_l, // Left modifiers (LShift, LCtrl, LAlt, LMeta)
    mod_r, // Right modifiers (RShift, RCtrl, RAlt, RMeta)
    space, // Spacebar
    punct, // Punctuation cluster (-, =, [, ], \, `, etc.)
    num, // Number row (1-9, 0)
    func, // Function keys (F1-F12, Esc)
    numpad, // Numpad keys
    nav, // Navigation (Backspace, Enter, Tab, Delete, arrows, Home, End, PgUp, PgDn, Ins)

    /// Sentinel for unknown/unmapped keycodes. Excluded from feature extraction.
    pub const unknown: ?KeyClass = null;
};

/// Map a Linux evdev keycode to its KeyClass.
/// Returns null for keycodes that should be ignored (multimedia, power, etc.).
pub fn evdevToClass(code: u16) ?KeyClass {
    return switch (code) {
        // Number row
        2...11 => .num, // KEY_1 through KEY_0

        // Upper row (QWERTY)
        16 => .upper_l, // KEY_Q
        17 => .upper_l, // KEY_W
        18 => .upper_l, // KEY_E
        19 => .upper_l, // KEY_R
        20 => .upper_l, // KEY_T
        21 => .upper_r, // KEY_Y
        22 => .upper_r, // KEY_U
        23 => .upper_r, // KEY_I
        24 => .upper_r, // KEY_O
        25 => .upper_r, // KEY_P

        // Home row (ASDF)
        30 => .home_l, // KEY_A
        31 => .home_l, // KEY_S
        32 => .home_l, // KEY_D
        33 => .home_l, // KEY_F
        34 => .home_l, // KEY_G
        35 => .home_r, // KEY_H
        36 => .home_r, // KEY_J
        37 => .home_r, // KEY_K
        38 => .home_r, // KEY_L
        39 => .home_r, // KEY_SEMICOLON
        40 => .home_r, // KEY_APOSTROPHE

        // Lower row (ZXCV)
        44 => .lower_l, // KEY_Z
        45 => .lower_l, // KEY_X
        46 => .lower_l, // KEY_C
        47 => .lower_l, // KEY_V
        48 => .lower_l, // KEY_B
        49 => .lower_r, // KEY_N
        50 => .lower_r, // KEY_M
        51 => .lower_r, // KEY_COMMA
        52 => .lower_r, // KEY_DOT
        53 => .lower_r, // KEY_SLASH

        // Spacebar
        57 => .space, // KEY_SPACE

        // Left modifiers
        29 => .mod_l, // KEY_LEFTCTRL
        42 => .mod_l, // KEY_LEFTSHIFT
        56 => .mod_l, // KEY_LEFTALT
        125 => .mod_l, // KEY_LEFTMETA

        // Right modifiers
        54 => .mod_r, // KEY_RIGHTSHIFT
        97 => .mod_r, // KEY_RIGHTCTRL
        100 => .mod_r, // KEY_RIGHTALT
        126 => .mod_r, // KEY_RIGHTMETA

        // Punctuation
        12 => .punct, // KEY_MINUS
        13 => .punct, // KEY_EQUAL
        26 => .punct, // KEY_LEFTBRACE
        27 => .punct, // KEY_RIGHTBRACE
        43 => .punct, // KEY_BACKSLASH
        41 => .punct, // KEY_GRAVE

        // Navigation
        1 => .nav, // KEY_ESC (also nav — immediate action key)
        14 => .nav, // KEY_BACKSPACE
        15 => .nav, // KEY_TAB
        28 => .nav, // KEY_ENTER
        102 => .nav, // KEY_HOME
        103 => .nav, // KEY_UP
        104 => .nav, // KEY_PAGEUP
        105 => .nav, // KEY_LEFT
        106 => .nav, // KEY_RIGHT
        107 => .nav, // KEY_END
        108 => .nav, // KEY_DOWN
        109 => .nav, // KEY_PAGEDOWN
        110 => .nav, // KEY_INSERT
        111 => .nav, // KEY_DELETE

        // Function keys
        59...68 => .func, // KEY_F1 through KEY_F10
        87 => .func, // KEY_F11
        88 => .func, // KEY_F12

        // Numpad
        69 => .numpad, // KEY_NUMLOCK
        71...73 => .numpad, // KEY_KP7, KP8, KP9
        75...77 => .numpad, // KEY_KP4, KP5, KP6
        79...82 => .numpad, // KEY_KP1, KP2, KP3, KP0
        55 => .numpad, // KEY_KPASTERISK
        74 => .numpad, // KEY_KPMINUS
        78 => .numpad, // KEY_KPPLUS
        83 => .numpad, // KEY_KPDOT
        96 => .numpad, // KEY_KPENTER
        98 => .numpad, // KEY_KPSLASH

        // Capslock — treat as left modifier
        58 => .mod_l, // KEY_CAPSLOCK

        // Everything else (multimedia, power, etc.) — ignore
        else => null,
    };
}

test "home row left keys map correctly" {
    const testing = @import("std").testing;
    // A=30, S=31, D=32, F=33, G=34
    try testing.expectEqual(KeyClass.home_l, evdevToClass(30).?);
    try testing.expectEqual(KeyClass.home_l, evdevToClass(31).?);
    try testing.expectEqual(KeyClass.home_l, evdevToClass(32).?);
    try testing.expectEqual(KeyClass.home_l, evdevToClass(33).?);
    try testing.expectEqual(KeyClass.home_l, evdevToClass(34).?);
}

test "home row right keys map correctly" {
    const testing = @import("std").testing;
    // H=35, J=36, K=37, L=38, ;=39, '=40
    try testing.expectEqual(KeyClass.home_r, evdevToClass(35).?);
    try testing.expectEqual(KeyClass.home_r, evdevToClass(36).?);
    try testing.expectEqual(KeyClass.home_r, evdevToClass(37).?);
    try testing.expectEqual(KeyClass.home_r, evdevToClass(38).?);
    try testing.expectEqual(KeyClass.home_r, evdevToClass(39).?);
    try testing.expectEqual(KeyClass.home_r, evdevToClass(40).?);
}

test "navigation keys include backspace and enter" {
    const testing = @import("std").testing;
    try testing.expectEqual(KeyClass.nav, evdevToClass(14).?); // Backspace
    try testing.expectEqual(KeyClass.nav, evdevToClass(28).?); // Enter
    try testing.expectEqual(KeyClass.nav, evdevToClass(111).?); // Delete
}

test "unknown keycodes return null" {
    const testing = @import("std").testing;
    try testing.expectEqual(@as(?KeyClass, null), evdevToClass(200));
    try testing.expectEqual(@as(?KeyClass, null), evdevToClass(500));
}

test "spacebar maps to space" {
    const testing = @import("std").testing;
    try testing.expectEqual(KeyClass.space, evdevToClass(57).?);
}

test "modifiers map to correct side" {
    const testing = @import("std").testing;
    try testing.expectEqual(KeyClass.mod_l, evdevToClass(42).?); // LShift
    try testing.expectEqual(KeyClass.mod_l, evdevToClass(29).?); // LCtrl
    try testing.expectEqual(KeyClass.mod_r, evdevToClass(54).?); // RShift
    try testing.expectEqual(KeyClass.mod_r, evdevToClass(97).?); // RCtrl
}
