#include "lightbox.h"

#include <lightc/memory.h>

/*
 * JSON, as RFC 8259 has it (ROADMAP I.4): what an image's index, its manifest
 * and its configuration are written in.
 *
 * A text is checked whole before any value of it is used, and strictly. What
 * the RFC leaves open, readers settle each their own way; such a text is
 * refused, so that lightbox never reads another manifest out of it than the
 * registry or the tool that carried it did:
 *
 *   - a name that is there twice in one object, of which some readers take
 *     the first and most the last;
 *   - bytes that are no UTF-8 and half a surrogate pair written \uXXXX,
 *     which some readers replace and some keep;
 *   - \u0000, which ends a string for whoever keeps it the way C does;
 *   - anything after the value, a byte order mark before it, and what is
 *     longer or deeper than is read.
 *
 * And where a member is looked up by its name, one whose name is that name
 * but for the case of its letters makes the lookup fail (json_at): Go's
 * reader, which registries and their tools are written with, takes such a
 * member for the field.
 *
 * Nothing is built from a text. A value is its bytes in the text, and the
 * values inside it are found by reading it again, which a text of this size
 * allows; one function reads a string's characters for the check, for the
 * comparing of names and for what a caller is given, so that the three never
 * differ.
 */

enum refusal {
    TEXT_OK,
    TEXT_LONG,
    TEXT_MEMORY,
    TEXT_EMPTY,
    TEXT_ENDS,
    TEXT_NO_VALUE,
    TEXT_NUMBER,
    TEXT_STRING_OPEN,
    TEXT_CONTROL,
    TEXT_ESCAPE,
    TEXT_UTF8,
    TEXT_SURROGATE,
    TEXT_NUL,
    TEXT_NAME,
    TEXT_COLON,
    TEXT_IN_OBJECT,
    TEXT_IN_ARRAY,
    TEXT_DEEP,
    TEXT_TWICE,
    TEXT_MORE,
    TEXT_REFUSALS
};

static const char *const refusals[TEXT_REFUSALS] = {
    [TEXT_OK]          = "",
    [TEXT_LONG]        = "the text is longer than is read",
    [TEXT_MEMORY]      = "there is no memory to check the text with",
    [TEXT_EMPTY]       = "there is no value",
    [TEXT_ENDS]        = "the text ends before its value does",
    [TEXT_NO_VALUE]    = "what is here is no value",
    [TEXT_NUMBER]      = "a number that is not written the way JSON has them",
    [TEXT_STRING_OPEN] = "a string that does not end",
    [TEXT_CONTROL]     = "a control character in a string, where only an escape may say one",
    [TEXT_ESCAPE]      = "an escape that JSON does not have",
    [TEXT_UTF8]        = "bytes that are no UTF-8",
    [TEXT_SURROGATE]   = "half of a surrogate pair",
    [TEXT_NUL]         = "the character U+0000, which is not read",
    [TEXT_NAME]        = "a member's name has to be a string",
    [TEXT_COLON]       = "there is no colon after a member's name",
    [TEXT_IN_OBJECT]   = "there is no comma and no closing brace after a member",
    [TEXT_IN_ARRAY]    = "there is no comma and no closing bracket after an element",
    [TEXT_DEEP]        = "arrays and objects are deeper inside one another than is read",
    [TEXT_TWICE]       = "a name that is there twice in one object",
    [TEXT_MORE]        = "there is more after the value",
};

/* ─── Characters ────────────────────────────────────────────────────────── */

static bool is_digit(uint8_t c) {
    return c >= '0' && c <= '9';
}

static const uint8_t *after_blank(const uint8_t *p, const uint8_t *end) {
    while (p < end && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r'))
        p++;
    return p;
}

/* One character written as UTF-8 at p, which is before end: its code point
 * and how many bytes it has, or -1 for bytes that are none. RFC 3629: no
 * form longer than the shortest, no surrogate, nothing above U+10FFFF. */
static int32_t utf8(const uint8_t *p, const uint8_t *end, size_t *bytes) {
    uint8_t c = p[0];
    if (c < 0x80) {
        *bytes = 1;
        return c;
    }
    size_t n;
    uint32_t point, least;
    if (c >= 0xC2 && c <= 0xDF) {
        n = 2;
        point = c & 0x1Fu;
        least = 0x80;
    } else if (c >= 0xE0 && c <= 0xEF) {
        n = 3;
        point = c & 0x0Fu;
        least = 0x800;
    } else if (c >= 0xF0 && c <= 0xF4) {
        n = 4;
        point = c & 0x07u;
        least = 0x10000;
    } else {
        return -1;
    }
    if ((size_t)(end - p) < n)
        return -1;
    for (size_t i = 1; i < n; i++) {
        if ((p[i] & 0xC0) != 0x80)
            return -1;
        point = point << 6 | (p[i] & 0x3Fu);
    }
    if (point < least || point > 0x10FFFF || (point >= 0xD800 && point <= 0xDFFF))
        return -1;
    *bytes = n;
    return (int32_t)point;
}

/* A code point as UTF-8: how many bytes */
static size_t utf8_write(uint32_t point, uint8_t out[4]) {
    if (point < 0x80) {
        out[0] = (uint8_t)point;
        return 1;
    }
    if (point < 0x800) {
        out[0] = (uint8_t)(0xC0 | point >> 6);
        out[1] = (uint8_t)(0x80 | (point & 0x3F));
        return 2;
    }
    if (point < 0x10000) {
        out[0] = (uint8_t)(0xE0 | point >> 12);
        out[1] = (uint8_t)(0x80 | (point >> 6 & 0x3F));
        out[2] = (uint8_t)(0x80 | (point & 0x3F));
        return 3;
    }
    out[0] = (uint8_t)(0xF0 | point >> 18);
    out[1] = (uint8_t)(0x80 | (point >> 12 & 0x3F));
    out[2] = (uint8_t)(0x80 | (point >> 6 & 0x3F));
    out[3] = (uint8_t)(0x80 | (point & 0x3F));
    return 4;
}

/* Four hex digits at p: their number, or -1 */
static int32_t hex4(const uint8_t *p, const uint8_t *end) {
    if (end - p < 4)
        return -1;
    int32_t number = 0;
    for (int i = 0; i < 4; i++) {
        uint8_t c = p[i];
        int32_t digit;
        if (is_digit(c))
            digit = c - '0';
        else if (c >= 'a' && c <= 'f')
            digit = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F')
            digit = c - 'A' + 10;
        else
            return -1;
        number = number << 4 | digit;
    }
    return number;
}

/*
 * One character of what a string has between its quotes, at p, which is
 * before end and is not the closing quote: its code point and how many bytes
 * of the text say it; or less than 0, minus what is wrong with it. An escape
 * is resolved, and the two halves of a surrogate pair are one character.
 */
static int32_t character(const uint8_t *p, const uint8_t *end, size_t *bytes) {
    uint8_t c = p[0];
    if (c < 0x20)
        return -(int32_t)TEXT_CONTROL;
    if (c != '\\') {
        int32_t point = utf8(p, end, bytes);
        return point < 0 ? -(int32_t)TEXT_UTF8 : point;
    }
    if (end - p < 2)
        return -(int32_t)TEXT_STRING_OPEN;
    *bytes = 2;
    switch (p[1]) {
    case '"':
        return '"';
    case '\\':
        return '\\';
    case '/':
        return '/';
    case 'b':
        return '\b';
    case 'f':
        return '\f';
    case 'n':
        return '\n';
    case 'r':
        return '\r';
    case 't':
        return '\t';
    case 'u':
        break;
    default:
        return -(int32_t)TEXT_ESCAPE;
    }
    int32_t unit = hex4(p + 2, end);
    if (unit < 0)
        return -(int32_t)TEXT_ESCAPE;
    *bytes = 6;
    if (unit == 0)
        return -(int32_t)TEXT_NUL;
    if (unit >= 0xDC00 && unit <= 0xDFFF)
        return -(int32_t)TEXT_SURROGATE;
    if (unit < 0xD800 || unit > 0xDBFF)
        return unit;
    /* the first half of a pair: the second has to follow at once */
    if (end - p < 12 || p[6] != '\\' || p[7] != 'u')
        return -(int32_t)TEXT_SURROGATE;
    int32_t low = hex4(p + 8, end);
    if (low < 0xDC00 || low > 0xDFFF)
        return -(int32_t)TEXT_SURROGATE;
    *bytes = 12;
    return 0x10000 + ((unit - 0xD800) << 10) + (low - 0xDC00);
}

/* ─── The check ─────────────────────────────────────────────────────────── */

struct text {
    const uint8_t *bytes, *end;
    const uint8_t *at;          /* how far it is read */
    /* Where the names of the objects that are open begin in the text, an
     * object's after those of the one it is in. */
    uint32_t      *names;
    size_t         names_used, names_size;
    enum refusal   refusal;
    size_t         refused_at;
};

static bool refuse(struct text *t, enum refusal why, const uint8_t *at) {
    t->refusal = why;
    t->refused_at = (size_t)(at - t->bytes);
    return false;
}

/* A string, at its opening quote: read to after its closing one */
static bool string(struct text *t) {
    const uint8_t *p = t->at + 1;
    for (;;) {
        if (p >= t->end)
            return refuse(t, TEXT_STRING_OPEN, t->at);
        if (*p == '"')
            break;
        size_t bytes = 0;
        int32_t c = character(p, t->end, &bytes);
        if (c < 0)
            return refuse(t, (enum refusal)-c, p);
        p += bytes;
    }
    t->at = p + 1;
    return true;
}

static bool digits(struct text *t) {
    const uint8_t *from = t->at;
    while (t->at < t->end && is_digit(*t->at))
        t->at++;
    return t->at > from;
}

static bool at_byte(const struct text *t, uint8_t c) {
    return t->at < t->end && *t->at == c;
}

/* A number, at its sign or its first digit */
static bool number(struct text *t) {
    const uint8_t *from = t->at;
    if (at_byte(t, '-'))
        t->at++;
    if (at_byte(t, '0')) {
        t->at++;
        if (t->at < t->end && is_digit(*t->at))
            return refuse(t, TEXT_NUMBER, from);
    } else if (!digits(t)) {
        return refuse(t, TEXT_NUMBER, from);
    }
    if (at_byte(t, '.')) {
        t->at++;
        if (!digits(t))
            return refuse(t, TEXT_NUMBER, from);
    }
    if (at_byte(t, 'e') || at_byte(t, 'E')) {
        t->at++;
        if (at_byte(t, '+') || at_byte(t, '-'))
            t->at++;
        if (!digits(t))
            return refuse(t, TEXT_NUMBER, from);
    }
    return true;
}

static bool word(struct text *t, const char *letters, size_t len) {
    if ((size_t)(t->end - t->at) < len || lc_bytes_compare(t->at, letters, len) != 0)
        return refuse(t, TEXT_NO_VALUE, t->at);
    t->at += len;
    return true;
}

/* The order of two names by what they say, their escapes resolved: less than
 * 0, 0 for one name written twice, or more. Both are strings that string()
 * took. */
static int name_order(const struct text *t, uint32_t a, uint32_t b) {
    const uint8_t *p = t->bytes + a + 1, *q = t->bytes + b + 1;
    for (;;) {
        bool p_ends = p >= t->end || *p == '"', q_ends = q >= t->end || *q == '"';
        if (p_ends || q_ends)
            return (int)q_ends - (int)p_ends;
        size_t p_bytes = 0, q_bytes = 0;
        int32_t c = character(p, t->end, &p_bytes), d = character(q, t->end, &q_bytes);
        if (c != d)
            return c < d ? -1 : 1;
        if (c < 0)
            return 0;
        p += p_bytes;
        q += q_bytes;
    }
}

static bool name_before(const struct text *t, uint32_t a, uint32_t b) {
    int order = name_order(t, a, b);
    return order < 0 || (order == 0 && a < b);
}

static void sift(const struct text *t, uint32_t *names, size_t root, size_t count) {
    for (;;) {
        size_t child = 2 * root + 1;
        if (child >= count)
            return;
        if (child + 1 < count && name_before(t, names[child], names[child + 1]))
            child++;
        if (!name_before(t, names[root], names[child]))
            return;
        uint32_t held = names[root];
        names[root] = names[child];
        names[child] = held;
        root = child;
    }
}

/*
 * Whether an object's names are each there once. They are put in order, a
 * heap sort, as that takes no more than its count times the count's
 * logarithm of comparisons whatever the names are, and then one written
 * twice is beside itself. The place given is where the first name of the
 * text that was there before is written the second time.
 */
static bool names_once(struct text *t, size_t first) {
    uint32_t *names = t->names + first;
    size_t count = t->names_used - first;
    t->names_used = first;
    for (size_t i = count / 2; i-- > 0;)
        sift(t, names, i, count);
    for (size_t left = count; left-- > 1;) {
        uint32_t held = names[0];
        names[0] = names[left];
        names[left] = held;
        sift(t, names, 0, left);
    }
    bool twice = false;
    uint32_t where = 0;
    for (size_t i = 1; i < count; i++)
        if (name_order(t, names[i - 1], names[i]) == 0 && (!twice || names[i] < where)) {
            twice = true;
            where = names[i];
        }
    return twice ? refuse(t, TEXT_TWICE, t->bytes + where) : true;
}

static bool value(struct text *t, unsigned depth);

/* An array, after its opening bracket */
static bool array(struct text *t, unsigned depth) {
    t->at = after_blank(t->at, t->end);
    if (at_byte(t, ']')) {
        t->at++;
        return true;
    }
    for (;;) {
        if (!value(t, depth))
            return false;
        t->at = after_blank(t->at, t->end);
        if (t->at >= t->end)
            return refuse(t, TEXT_ENDS, t->at);
        if (*t->at == ']')
            break;
        if (*t->at != ',')
            return refuse(t, TEXT_IN_ARRAY, t->at);
        t->at++;
    }
    t->at++;
    return true;
}

/* An object, after its opening brace */
static bool object(struct text *t, unsigned depth) {
    size_t first = t->names_used;
    t->at = after_blank(t->at, t->end);
    if (at_byte(t, '}')) {
        t->at++;
        return true;
    }
    for (;;) {
        t->at = after_blank(t->at, t->end);
        if (t->at >= t->end)
            return refuse(t, TEXT_ENDS, t->at);
        if (*t->at != '"')
            return refuse(t, TEXT_NAME, t->at);
        if (t->names_used >= t->names_size)
            return refuse(t, TEXT_MEMORY, t->at);
        t->names[t->names_used++] = (uint32_t)(t->at - t->bytes);
        if (!string(t))
            return false;
        t->at = after_blank(t->at, t->end);
        if (t->at >= t->end)
            return refuse(t, TEXT_ENDS, t->at);
        if (*t->at != ':')
            return refuse(t, TEXT_COLON, t->at);
        t->at++;
        if (!value(t, depth))
            return false;
        t->at = after_blank(t->at, t->end);
        if (t->at >= t->end)
            return refuse(t, TEXT_ENDS, t->at);
        if (*t->at == '}')
            break;
        if (*t->at != ',')
            return refuse(t, TEXT_IN_OBJECT, t->at);
        t->at++;
    }
    t->at++;
    return names_once(t, first);
}

/* A value, with blanks before it or none; depth is how many arrays and
 * objects it is in. */
static bool value(struct text *t, unsigned depth) {
    t->at = after_blank(t->at, t->end);
    if (t->at >= t->end)
        return refuse(t, TEXT_ENDS, t->at);
    uint8_t c = *t->at;
    if (c == '[' || c == '{') {
        if (depth == JSON_DEPTH_MAX)
            return refuse(t, TEXT_DEEP, t->at);
        t->at++;
        return c == '[' ? array(t, depth + 1) : object(t, depth + 1);
    }
    if (c == '"')
        return string(t);
    if (c == '-' || is_digit(c))
        return number(t);
    if (c == 't')
        return word(t, "true", 4);
    if (c == 'f')
        return word(t, "false", 5);
    if (c == 'n')
        return word(t, "null", 4);
    return refuse(t, TEXT_NO_VALUE, t->at);
}

int json_check(const char *text, size_t len, json_value *root, json_refusal *why) {
    struct text t = { .bytes = (const uint8_t *)text, .end = (const uint8_t *)text + len };
    t.at = t.bytes;
    *root = (json_value){ 0 };
    *why = (json_refusal){ 0 };

    if (len > JSON_TEXT_MAX) {
        (void)refuse(&t, TEXT_LONG, t.bytes + JSON_TEXT_MAX);
    } else {
        /* A member is four bytes at the least, "":0, so that a text has no
         * more names than a quarter of its bytes. */
        size_t names = len / 4 + 1;
        size_t pages = (names * sizeof(uint32_t) + LC_PAGE_SIZE - 1) / LC_PAGE_SIZE;
        lc_result_ptr got = lc_allocate_pages(pages);
        if (lc_ptr_is_err(got)) {
            (void)refuse(&t, TEXT_MEMORY, t.bytes);
        } else {
            t.names = got.value;
            t.names_size = names;
            const uint8_t *from = after_blank(t.bytes, t.end);
            if (from >= t.end) {
                (void)refuse(&t, TEXT_EMPTY, from);
            } else if (value(&t, 0)) {
                const uint8_t *to = t.at;
                t.at = after_blank(t.at, t.end);
                if (t.at < t.end)
                    (void)refuse(&t, TEXT_MORE, t.at);
                else
                    *root = (json_value){ .text = text + (from - t.bytes), .len = (size_t)(to - from) };
            }
            lc_free_pages(got.value, pages);
        }
    }
    if (t.refusal == TEXT_OK)
        return 0;

    why->why = refusals[t.refusal];
    why->offset = t.refused_at;
    why->line = 1;
    size_t line_from = 0;
    for (size_t i = 0; i < t.refused_at && i < len; i++)
        if (text[i] == '\n') {
            why->line++;
            line_from = i + 1;
        }
    why->column = t.refused_at - line_from + 1;
    return -1;
}

/* ─── The values of a text that was checked ─────────────────────────────── */

/*
 * These read a value's bytes again, and take them for what json_check
 * passed. Given other bytes they still stay inside them, and say that
 * nothing is there.
 */

static const uint8_t *bytes_of(json_value v) {
    return (const uint8_t *)v.text;
}

static json_value span(const uint8_t *from, const uint8_t *to) {
    return (json_value){ .text = (const char *)from, .len = (size_t)(to - from) };
}

json_kind json_kind_of(json_value v) {
    if (v.len == 0)
        return JSON_NULL;
    switch (v.text[0]) {
    case '{':
        return JSON_OBJECT;
    case '[':
        return JSON_ARRAY;
    case '"':
        return JSON_STRING;
    case 't':
        return JSON_TRUE;
    case 'f':
        return JSON_FALSE;
    case 'n':
        return JSON_NULL;
    default:
        return JSON_NUMBER;
    }
}

/* After the string that begins at p, or NULL */
static const uint8_t *string_end(const uint8_t *p, const uint8_t *end) {
    if (p >= end || *p != '"')
        return NULL;
    p++;
    while (p < end) {
        if (*p == '"')
            return p + 1;
        p += *p == '\\' ? 2 : 1;
    }
    return NULL;
}

/* After the value that begins at p, or NULL */
static const uint8_t *value_end(const uint8_t *p, const uint8_t *end) {
    size_t depth = 0;
    do {
        if (p >= end)
            return NULL;
        uint8_t c = *p;
        if (c == '"') {
            p = string_end(p, end);
            if (!p)
                return NULL;
        } else if (c == '{' || c == '[') {
            depth++;
            p++;
        } else if (c == '}' || c == ']') {
            if (depth == 0)
                return NULL;
            depth--;
            p++;
        } else if (depth > 0) {
            p++;
        } else {
            /* a number or a word, to what ends it */
            while (p < end && *p != ',' && *p != ']' && *p != '}' && *p != ' ' && *p != '\t' && *p != '\n' &&
                   *p != '\r')
                p++;
        }
    } while (depth > 0);
    return p;
}

/* The member or the element that begins at p, with blanks before it or none */
static bool item_at(const uint8_t *p, const uint8_t *end, bool named, json_item *item) {
    item->named = named;
    item->name = (json_value){ 0 };
    p = after_blank(p, end);
    if (p >= end || *p == ']' || *p == '}')
        return false;
    if (named) {
        const uint8_t *name_end = string_end(p, end);
        if (!name_end)
            return false;
        item->name = span(p, name_end);
        p = after_blank(name_end, end);
        if (p >= end || *p != ':')
            return false;
        p = after_blank(p + 1, end);
    }
    const uint8_t *to = value_end(p, end);
    if (!to)
        return false;
    item->value = span(p, to);
    item->rest = span(to, end);
    return true;
}

bool json_first(json_value in, json_item *item) {
    json_kind kind = json_kind_of(in);
    *item = (json_item){ 0 };
    if (kind != JSON_ARRAY && kind != JSON_OBJECT)
        return false;
    return item_at(bytes_of(in) + 1, bytes_of(in) + in.len, kind == JSON_OBJECT, item);
}

bool json_next(json_item *item) {
    if (item->rest.len == 0)
        return false;
    const uint8_t *end = bytes_of(item->rest) + item->rest.len;
    const uint8_t *p = after_blank(bytes_of(item->rest), end);
    if (p >= end || *p != ',')
        return false;
    return item_at(p + 1, end, item->named, item);
}

size_t json_count(json_value v) {
    size_t count = 0;
    json_item item;
    for (bool more = json_first(v, &item); more; more = json_next(&item))
        count++;
    return count;
}

/* Letters of one case, as Go's reader of JSON takes them for one another:
 * ASCII's, and the two characters beyond it that Unicode folds to an ASCII
 * letter, the long s and the Kelvin sign. */
static int32_t folded(int32_t c) {
    if (c >= 'A' && c <= 'Z')
        return c + ('a' - 'A');
    if (c == 0x17F)
        return 's';
    if (c == 0x212A)
        return 'k';
    return c;
}

enum same { OTHER, SAME, SAME_BUT_CASE };

/* A string of a text against other text, which is a token of a path when
 * its ~0 stands for ~ and its ~1 for /. */
static enum same same_text(json_value string, const char *text, size_t len, bool token) {
    if (json_kind_of(string) != JSON_STRING || string.len < 2)
        return OTHER;
    const uint8_t *p = bytes_of(string) + 1, *end = bytes_of(string) + string.len - 1;
    const uint8_t *q = (const uint8_t *)text, *q_end = (const uint8_t *)text + len;
    enum same same = SAME;
    for (;;) {
        if (p >= end || q >= q_end)
            return p >= end && q >= q_end ? same : OTHER;
        size_t p_bytes = 0, q_bytes = 0;
        int32_t c = character(p, end, &p_bytes), d;
        if (token && q_end - q >= 2 && q[0] == '~' && (q[1] == '0' || q[1] == '1')) {
            d = q[1] == '0' ? '~' : '/';
            q_bytes = 2;
        } else {
            d = utf8(q, q_end, &q_bytes);
        }
        if (c < 0 || d < 0)
            return OTHER;
        if (c != d) {
            if (folded(c) != folded(d))
                return OTHER;
            same = SAME_BUT_CASE;
        }
        p += p_bytes;
        q += q_bytes;
    }
}

bool json_text_is(json_value v, const char *text) {
    return same_text(v, text, lc_string_length(text), false) == SAME;
}

/* A token of a path as an array's index: 0, or digits that do not begin
 * with one (RFC 6901, 4) */
static bool token_index(const char *token, size_t len, uint64_t *index) {
    if (len == 0 || len > 19 || (len > 1 && token[0] == '0'))
        return false;
    *index = 0;
    for (size_t i = 0; i < len; i++) {
        if (!is_digit((uint8_t)token[i]))
            return false;
        *index = *index * 10 + (uint64_t)(token[i] - '0');
    }
    return true;
}

int json_at(json_value v, const char *path, json_value *out) {
    *out = (json_value){ 0 };
    while (*path) {
        if (*path != '/')
            return 0;
        const char *token = ++path;
        while (*path && *path != '/')
            path++;
        size_t len = (size_t)(path - token);

        json_kind kind = json_kind_of(v);
        json_value found = { 0 };
        bool there = false;
        json_item item;
        if (kind == JSON_ARRAY) {
            uint64_t index, i = 0;
            if (!token_index(token, len, &index))
                return 0;
            for (bool more = json_first(v, &item); more && !there; more = json_next(&item), i++)
                if (i == index) {
                    found = item.value;
                    there = true;
                }
        } else if (kind == JSON_OBJECT) {
            /* to the object's end, whatever was found: the name may be there
             * once more in another case */
            for (bool more = json_first(v, &item); more; more = json_next(&item)) {
                enum same same = same_text(item.name, token, len, true);
                if (same == SAME_BUT_CASE)
                    return -1;
                if (same == SAME) {
                    found = item.value;
                    there = true;
                }
            }
        }
        if (!there)
            return 0;
        v = found;
    }
    *out = v;
    return 1;
}

int64_t json_text(json_value v, char *out, size_t size) {
    if (size == 0)
        return -1;
    out[0] = '\0';
    if (json_kind_of(v) != JSON_STRING || v.len < 2 || v.text[v.len - 1] != '"')
        return -1;
    const uint8_t *p = bytes_of(v) + 1, *end = bytes_of(v) + v.len - 1;
    size_t used = 0;
    while (p < end) {
        size_t bytes = 0;
        int32_t c = character(p, end, &bytes);
        uint8_t written[4];
        size_t more = c > 0 ? utf8_write((uint32_t)c, written) : 0;
        /* all of it or none: a text cut short is another text */
        if (c <= 0 || more >= size - used) {
            out[0] = '\0';
            return -1;
        }
        lc_bytes_copy(out + used, written, more);
        used += more;
        p += bytes;
    }
    out[used] = '\0';
    return (int64_t)used;
}

bool json_whole(json_value v, uint64_t *number) {
    *number = 0;
    if (v.len == 0 || v.len > 20 || (v.len > 1 && v.text[0] == '0'))
        return false;
    uint64_t n = 0;
    for (size_t i = 0; i < v.len; i++) {
        if (!is_digit((uint8_t)v.text[i]))
            return false;
        uint64_t digit = (uint64_t)(v.text[i] - '0');
        if (n > (UINT64_MAX - digit) / 10)
            return false;
        n = n * 10 + digit;
    }
    *number = n;
    return true;
}
