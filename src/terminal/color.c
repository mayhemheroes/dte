#include "color.h"
#include "util/debug.h"
#include "util/strtonum.h"

static unsigned int rgb_to_rrggbb(unsigned int c)
{
    unsigned int r = c & 0xF;
    unsigned int g = c & 0xF0;
    unsigned int b = c & 0xF00;
    return r | (r|g) << 4 | (g|b) << 8 | b << 12;
}

int32_t parse_rgb(const char *str, size_t len)
{
    unsigned int val = 0;
    size_t n = buf_parse_hex_uint(str, len, &val);
    switch (n) {
    case 3:
        val = rgb_to_rrggbb(val);
        // Fallthrough
    case 6:
        if (likely(n == len)) {
            return COLOR_RGB(val);
        }
    }
    return COLOR_INVALID;
}

// Calculate squared Euclidean distance between 2 RGB colors
static int color_distance (
    uint8_t R, uint8_t G, uint8_t B,
    uint8_t r, uint8_t g, uint8_t b
) {
    static_assert(INT_MAX >= 3 * 255 * 255);
    return (R - r) * (R - r) + (G - g) * (G - g) + (B - b) * (B - b);
}

UNITTEST {
    BUG_ON(color_distance(1,1,1, 1,0,1) != 1);
    BUG_ON(color_distance(100,0,0, 80,0,0) != 400);
    BUG_ON(color_distance(0,5,10, 5,0,2) != 25 + 25 + 64);
    BUG_ON(color_distance(0,0,0, 255,0,0) != 255 * 255);
    BUG_ON(color_distance(255,255,255, 0,0,0) != 255 * 255 * 3);
}

// Convert RGB color component (0-255) to nearest xterm color cube index (0-5)
static uint8_t nearest_cube_index(uint8_t c)
{
    if (c < 75) {
        c += 28;
    }
    return (c - 35) / 40;
}

UNITTEST {
    BUG_ON(nearest_cube_index(0) != 0);
    BUG_ON(nearest_cube_index(46) != 0);
    BUG_ON(nearest_cube_index(47) != 1);
    BUG_ON(nearest_cube_index(0x72) != 1);
    BUG_ON(nearest_cube_index(0x73) != 2);
    BUG_ON(nearest_cube_index(0xaa) != 3);
    BUG_ON(nearest_cube_index(0xff) != 5);
}

static uint8_t color_rgb_to_256(uint32_t color, bool *exact)
{
    if (!(color & COLOR_FLAG_RGB)) {
        BUG_ON(color > 255);
        *exact = true;
        return color;
    }

    uint8_t r, g, b;
    color_split_rgb(color, &r, &g, &b);

    // Calculate closest 6x6x6 RGB cube color
    static const uint8_t color_stops[6] = {0x00, 0x5f, 0x87, 0xaf, 0xd7, 0xff};
    uint8_t r_idx = nearest_cube_index(r);
    uint8_t g_idx = nearest_cube_index(g);
    uint8_t b_idx = nearest_cube_index(b);
    uint8_t r_stop = color_stops[r_idx];
    uint8_t g_stop = color_stops[g_idx];
    uint8_t b_stop = color_stops[b_idx];

    // Calculate closest gray
    int gray_avg = (r + g + b) / 3;
    int gray_idx = (gray_avg > 238) ? 23 : ((gray_avg - 3) / 10);
    int gray = 8 + (10 * gray_idx);

    // Calculate differences
    int rgb_distance = color_distance(r_stop, g_stop, b_stop, r, g, b);
    int gray_distance = color_distance(gray, gray, gray, r, g, b);

    if (gray_distance < rgb_distance) {
        // Gray is closest match
        *exact = (gray_distance == 0);
        return 232 + gray_idx;
    } else {
        // RGB cube color is closest match
        *exact = (rgb_distance == 0);
        return 16 + (36 * r_idx) + (6 * g_idx) + b_idx;
    }
}

// Convert a 24-bit RGB color to an xterm palette color if one matches
// exactly, or otherwise return the original color unchanged. This is
// useful for reducing the size of SGR sequences sent to the terminal.
static int32_t color_rgb_optimize(int32_t color)
{
    bool exact;
    int32_t new_color = color_rgb_to_256(color, &exact);
    return exact ? new_color : color;
}

static uint8_t color_256_to_16(uint8_t color)
{
    enum {
        k = COLOR_BLACK,
        r = COLOR_RED,
        g = COLOR_GREEN,
        y = COLOR_YELLOW,
        b = COLOR_BLUE,
        m = COLOR_MAGENTA,
        c = COLOR_CYAN,
        a = COLOR_GRAY,
        A = COLOR_DARKGRAY,
        R = COLOR_LIGHTRED,
        G = COLOR_LIGHTGREEN,
        Y = COLOR_LIGHTYELLOW,
        B = COLOR_LIGHTBLUE,
        M = COLOR_LIGHTMAGENTA,
        C = COLOR_LIGHTCYAN,
        W = COLOR_WHITE
    };

    static const uint8_t table[256] = {
        k, r, g, y, b, m, c, a, A, R, G, Y, B, M, C, W, //   0...15
        k, b, b, b, B, B, g, c, b, b, B, B, g, g, c, b, //  16...31
        B, B, g, g, g, c, B, B, G, G, G, C, C, B, G, G, //  32...47
        G, G, C, C, r, m, m, m, m, B, y, A, b, b, B, B, //  48...63
        g, g, c, b, B, B, g, g, g, c, B, B, G, G, G, G, //  64...79
        C, B, G, G, G, G, G, C, r, m, m, m, m, m, y, r, //  80...95
        m, m, m, m, y, y, A, b, B, B, g, g, g, c, B, B, //  96..111
        G, G, G, G, C, B, G, G, G, G, G, C, r, r, m, m, // 112..127
        m, m, r, r, r, m, M, M, y, y, r, m, M, M, y, y, // 128..143
        y, a, B, B, G, G, G, G, C, B, G, G, G, G, G, C, // 144..159
        R, R, R, m, M, M, R, R, M, M, M, M, R, R, R, R, // 160..175
        M, M, y, y, y, M, M, M, Y, Y, Y, Y, a, B, Y, G, // 176..191
        G, G, G, C, R, R, R, M, M, M, R, R, R, R, R, M, // 192..207
        R, R, R, M, M, M, y, y, y, R, M, M, y, y, Y, Y, // 208..223
        R, M, Y, Y, Y, Y, Y, W, k, k, k, k, k, k, A, A, // 224..239
        A, A, A, A, a, a, a, a, a, a, W, W, W, W, W, W  // 240..255
    };

    return table[color];
}

static uint8_t color_any_to_256(int32_t color)
{
    BUG_ON(color < 0);
    bool exact;
    return color_rgb_to_256(color, &exact);
}

static uint8_t color_any_to_16(int32_t color)
{
    return color_256_to_16(color_any_to_256(color));
}

static uint8_t color_any_to_8(int32_t color)
{
    return color_any_to_16(color) & 7;
}

int32_t color_to_nearest(int32_t color, TermColorCapabilityType type, bool optimize)
{
    if (color < 0) {
        return color;
    }
    switch (type) {
    case TERM_0_COLOR: return COLOR_DEFAULT;
    case TERM_8_COLOR: return color_any_to_8(color);
    case TERM_16_COLOR: return color_any_to_16(color);
    case TERM_256_COLOR: return color_any_to_256(color);
    case TERM_TRUE_COLOR: return optimize ? color_rgb_optimize(color) : color;
    }
    BUG("unexpected TermColorCapabilityType value");
    // This should never be reached, but it silences compiler warnings
    // when DEBUG == 0 and __builtin_unreachable() isn't supported
    // (i.e. BUG() expands to nothing)
    return COLOR_DEFAULT;
}
