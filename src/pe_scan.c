#include "pe_scan.h"

#include <limits.h>
#include <string.h>

/*
 * The semantic locator is inspired by the structural-scan idea in UWD3:
 * https://github.com/jcnnik/uwd3 (Jannik, MIT License).  This is an
 * independent C implementation with stricter PE validation and no fallback
 * to guessed function prologues.
 */

#define UWD_DOS_HEADER_SIZE 64u
#define UWD_PE_SIGNATURE_SIZE 4u
#define UWD_COFF_HEADER_SIZE 20u
#define UWD_PE32_PLUS_MIN_OPTIONAL_SIZE 240u
#define UWD_SECTION_HEADER_SIZE 40u
#define UWD_MAX_SECTIONS 96u
#define UWD_IMAGE_FILE_MACHINE_AMD64 0x8664u
#define UWD_IMAGE_FILE_MACHINE_ARM64 0xaa64u
#define UWD_IMAGE_FILE_DLL 0x2000u
#define UWD_PE32_PLUS_MAGIC 0x020bu
#define UWD_IMAGE_SCN_MEM_EXECUTE 0x20000000u
#define UWD_IMPORT_DIRECTORY 1u
#define UWD_EXCEPTION_DIRECTORY 3u
#define UWD_DEBUG_DIRECTORY 6u
#define UWD_IMPORT_DESCRIPTOR_SIZE 20u
#define UWD_RUNTIME_FUNCTION_SIZE 12u
#define UWD_DEBUG_DIRECTORY_ENTRY_SIZE 28u
#define UWD_IMAGE_DEBUG_TYPE_CODEVIEW 2u
#define UWD_RSDS_HEADER_SIZE 24u
#define UWD_ORDINAL_FLAG64 UINT64_C(0x8000000000000000)
#define UWD_WHITE_LOOKBACK 40u

typedef struct UwdPeSection {
    uint32_t virtual_size;
    uint32_t virtual_address;
    uint32_t raw_size;
    uint32_t raw_offset;
    uint32_t characteristics;
} UwdPeSection;

typedef struct UwdParsedPe {
    const unsigned char *data;
    size_t size;
    uint16_t machine;
    uint32_t timestamp;
    uint32_t size_of_image;
    uint32_t size_of_headers;
    uint32_t directory_count;
    uint32_t directory_rva[7];
    uint32_t directory_size[7];
    uint16_t section_count;
    UwdPeSection sections[UWD_MAX_SECTIONS];
} UwdParsedPe;

typedef struct UwdPdata {
    size_t file_offset;
    size_t entry_count;
} UwdPdata;

typedef struct UwdScanState {
    int saw_set_text_color_import;
    int saw_iat_call;
    int saw_white_call;
    int saw_pdata_match;
    int has_candidate;
    int ambiguous;
    uint32_t candidate_rva;
} UwdScanState;

static int uwd_range_ok(size_t total, size_t offset, size_t length)
{
    return offset <= total && length <= total - offset;
}

static uint16_t uwd_read_u16(const unsigned char *p)
{
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t uwd_read_u32(const unsigned char *p)
{
    return (uint32_t)p[0]
        | ((uint32_t)p[1] << 8)
        | ((uint32_t)p[2] << 16)
        | ((uint32_t)p[3] << 24);
}

static uint64_t uwd_read_u64(const unsigned char *p)
{
    return (uint64_t)uwd_read_u32(p)
        | ((uint64_t)uwd_read_u32(p + 4) << 32);
}

static void uwd_set_error(char *error, size_t capacity, const char *message)
{
    size_t i;

    if (error == NULL || capacity == 0u) {
        return;
    }
    if (message == NULL) {
        error[0] = '\0';
        return;
    }
    i = 0u;
    while (i + 1u < capacity && message[i] != '\0') {
        error[i] = message[i];
        ++i;
    }
    error[i] = '\0';
}

static int uwd_fail(char *error, size_t capacity, const char *message)
{
    uwd_set_error(error, capacity, message);
    return -1;
}

static uint32_t uwd_section_span(const UwdPeSection *section)
{
    return section->virtual_size > section->raw_size
        ? section->virtual_size
        : section->raw_size;
}

static int uwd_intervals_overlap_u32(uint32_t a_start,
                                     uint32_t a_size,
                                     uint32_t b_start,
                                     uint32_t b_size)
{
    uint64_t a_end = (uint64_t)a_start + (uint64_t)a_size;
    uint64_t b_end = (uint64_t)b_start + (uint64_t)b_size;

    return a_size != 0u && b_size != 0u
        && (uint64_t)a_start < b_end
        && (uint64_t)b_start < a_end;
}

static int uwd_parse_pe(const void *input,
                        size_t size,
                        UwdParsedPe *pe,
                        char *error,
                        size_t error_capacity)
{
    const unsigned char *data = (const unsigned char *)input;
    uint32_t nt_value;
    size_t nt_offset;
    size_t coff_offset;
    size_t optional_offset;
    size_t section_table_offset;
    uint16_t optional_size;
    uint16_t characteristics;
    uint32_t directory_count;
    size_t available_directories;
    size_t section_bytes;
    size_t i;
    size_t j;

    if (pe == NULL || data == NULL) {
        return uwd_fail(error, error_capacity, "invalid argument");
    }
    memset(pe, 0, sizeof(*pe));
    if (!uwd_range_ok(size, 0u, UWD_DOS_HEADER_SIZE)) {
        return uwd_fail(error, error_capacity, "truncated DOS header");
    }
    if (data[0] != 'M' || data[1] != 'Z') {
        return uwd_fail(error, error_capacity, "invalid DOS signature");
    }

    nt_value = uwd_read_u32(data + 0x3cu);
    nt_offset = (size_t)nt_value;
    if (!uwd_range_ok(size,
                      nt_offset,
                      UWD_PE_SIGNATURE_SIZE + UWD_COFF_HEADER_SIZE)) {
        return uwd_fail(error, error_capacity, "truncated PE header");
    }
    if (data[nt_offset] != 'P'
        || data[nt_offset + 1u] != 'E'
        || data[nt_offset + 2u] != 0u
        || data[nt_offset + 3u] != 0u) {
        return uwd_fail(error, error_capacity, "invalid PE signature");
    }

    coff_offset = nt_offset + UWD_PE_SIGNATURE_SIZE;
    pe->machine = uwd_read_u16(data + coff_offset);
    pe->section_count = uwd_read_u16(data + coff_offset + 2u);
    pe->timestamp = uwd_read_u32(data + coff_offset + 4u);
    optional_size = uwd_read_u16(data + coff_offset + 16u);
    characteristics = uwd_read_u16(data + coff_offset + 18u);

    if (pe->machine != UWD_IMAGE_FILE_MACHINE_AMD64
        && pe->machine != UWD_IMAGE_FILE_MACHINE_ARM64) {
        return uwd_fail(error, error_capacity, "PE is not AMD64 or ARM64");
    }
    if ((characteristics & UWD_IMAGE_FILE_DLL) == 0u) {
        return uwd_fail(error, error_capacity, "PE is not a DLL");
    }
    if (pe->section_count == 0u || pe->section_count > UWD_MAX_SECTIONS) {
        return uwd_fail(error, error_capacity, "invalid section count");
    }
    if (optional_size < UWD_PE32_PLUS_MIN_OPTIONAL_SIZE) {
        return uwd_fail(error, error_capacity, "truncated PE32+ optional header");
    }

    optional_offset = coff_offset + UWD_COFF_HEADER_SIZE;
    if (!uwd_range_ok(size, optional_offset, (size_t)optional_size)) {
        return uwd_fail(error, error_capacity, "truncated optional header");
    }
    if (uwd_read_u16(data + optional_offset) != UWD_PE32_PLUS_MAGIC) {
        return uwd_fail(error, error_capacity, "PE is not PE32+");
    }

    pe->size_of_image = uwd_read_u32(data + optional_offset + 56u);
    pe->size_of_headers = uwd_read_u32(data + optional_offset + 60u);
    directory_count = uwd_read_u32(data + optional_offset + 108u);
    available_directories = ((size_t)optional_size - 112u) / 8u;
    if ((uint64_t)directory_count > (uint64_t)available_directories) {
        return uwd_fail(error, error_capacity, "data directories exceed optional header");
    }
    pe->directory_count = directory_count;

    if (pe->size_of_image == 0u) {
        return uwd_fail(error, error_capacity, "invalid SizeOfImage");
    }
    if (pe->size_of_headers == 0u
        || pe->size_of_headers > pe->size_of_image
        || (uint64_t)pe->size_of_headers > (uint64_t)size) {
        return uwd_fail(error, error_capacity, "invalid SizeOfHeaders");
    }

    for (i = 0u; i < 7u; ++i) {
        if (i < (size_t)directory_count) {
            pe->directory_rva[i] =
                uwd_read_u32(data + optional_offset + 112u + i * 8u);
            pe->directory_size[i] =
                uwd_read_u32(data + optional_offset + 116u + i * 8u);
        }
    }

    section_table_offset = optional_offset + (size_t)optional_size;
    section_bytes = (size_t)pe->section_count * UWD_SECTION_HEADER_SIZE;
    if (!uwd_range_ok(size, section_table_offset, section_bytes)
        || section_table_offset > (size_t)pe->size_of_headers
        || section_bytes > (size_t)pe->size_of_headers - section_table_offset) {
        return uwd_fail(error, error_capacity, "truncated section table");
    }

    for (i = 0u; i < (size_t)pe->section_count; ++i) {
        const unsigned char *header =
            data + section_table_offset + i * UWD_SECTION_HEADER_SIZE;
        UwdPeSection *section = &pe->sections[i];
        uint32_t span;

        section->virtual_size = uwd_read_u32(header + 8u);
        section->virtual_address = uwd_read_u32(header + 12u);
        section->raw_size = uwd_read_u32(header + 16u);
        section->raw_offset = uwd_read_u32(header + 20u);
        section->characteristics = uwd_read_u32(header + 36u);

        if (section->raw_size != 0u) {
            if (section->raw_offset < pe->size_of_headers
                || (uint64_t)section->raw_offset
                       + (uint64_t)section->raw_size
                       > (uint64_t)size) {
                return uwd_fail(error, error_capacity, "section raw range is invalid");
            }
        }

        span = uwd_section_span(section);
        if (span != 0u) {
            if (section->virtual_address < pe->size_of_headers
                || section->virtual_address >= pe->size_of_image
                || span > pe->size_of_image - section->virtual_address) {
                return uwd_fail(error, error_capacity, "section RVA range is invalid");
            }
        }
    }

    for (i = 0u; i < (size_t)pe->section_count; ++i) {
        const UwdPeSection *a = &pe->sections[i];
        for (j = i + 1u; j < (size_t)pe->section_count; ++j) {
            const UwdPeSection *b = &pe->sections[j];
            if (uwd_intervals_overlap_u32(a->virtual_address,
                                          uwd_section_span(a),
                                          b->virtual_address,
                                          uwd_section_span(b))) {
                return uwd_fail(error, error_capacity, "overlapping section RVA ranges");
            }
            if (uwd_intervals_overlap_u32(a->raw_offset,
                                          a->raw_size,
                                          b->raw_offset,
                                          b->raw_size)) {
                return uwd_fail(error, error_capacity, "overlapping section raw ranges");
            }
        }
    }

    pe->data = data;
    pe->size = size;
    uwd_set_error(error, error_capacity, NULL);
    return 0;
}

static int uwd_map_rva_span(const UwdParsedPe *pe,
                            uint32_t rva,
                            size_t length,
                            size_t *file_offset,
                            size_t *available)
{
    size_t i;

    if (pe == NULL || file_offset == NULL || length == 0u) {
        return -1;
    }
    if (rva >= pe->size_of_image) {
        return -1;
    }

    if (rva < pe->size_of_headers) {
        size_t remain = (size_t)pe->size_of_headers - (size_t)rva;
        if (length > remain || !uwd_range_ok(pe->size, (size_t)rva, length)) {
            return -1;
        }
        *file_offset = (size_t)rva;
        if (available != NULL) {
            *available = remain;
        }
        return 0;
    }

    for (i = 0u; i < (size_t)pe->section_count; ++i) {
        const UwdPeSection *section = &pe->sections[i];
        uint32_t delta;
        size_t raw_available;
        size_t offset;

        if (rva < section->virtual_address) {
            continue;
        }
        delta = rva - section->virtual_address;
        if (delta >= section->raw_size) {
            continue;
        }
        raw_available = (size_t)(section->raw_size - delta);
        if (length > raw_available) {
            return -1;
        }
        offset = (size_t)section->raw_offset + (size_t)delta;
        if (!uwd_range_ok(pe->size, offset, length)) {
            return -1;
        }
        *file_offset = offset;
        if (available != NULL) {
            *available = raw_available;
        }
        return 0;
    }
    return -1;
}

static int uwd_ascii_equal(const unsigned char *text,
                           size_t text_length,
                           const char *expected,
                           int ignore_case)
{
    size_t i;

    for (i = 0u; i < text_length; ++i) {
        unsigned char a = text[i];
        unsigned char b = (unsigned char)expected[i];
        if (b == 0u) {
            return 0;
        }
        if (ignore_case) {
            if (a >= 'A' && a <= 'Z') {
                a = (unsigned char)(a + ('a' - 'A'));
            }
            if (b >= 'A' && b <= 'Z') {
                b = (unsigned char)(b + ('a' - 'A'));
            }
        }
        if (a != b) {
            return 0;
        }
    }
    return expected[text_length] == '\0';
}

/* Returns 1 for equal, 0 for unequal, and -1 for an invalid PE string. */
static int uwd_rva_string_equal(const UwdParsedPe *pe,
                                uint32_t rva,
                                const char *expected,
                                int ignore_case)
{
    size_t offset;
    size_t available;
    size_t length;

    if (expected == NULL
        || uwd_map_rva_span(pe, rva, 1u, &offset, &available) != 0) {
        return -1;
    }
    for (length = 0u; length < available; ++length) {
        if (pe->data[offset + length] == 0u) {
            return uwd_ascii_equal(pe->data + offset,
                                   length,
                                   expected,
                                   ignore_case);
        }
    }
    return -1;
}

static int uwd_debug_payload_offset(const UwdParsedPe *pe,
                                    uint32_t data_rva,
                                    uint32_t raw_pointer,
                                    uint32_t data_size,
                                    size_t *payload_offset,
                                    char *error,
                                    size_t error_capacity)
{
    size_t rva_offset = 0u;
    size_t raw_offset = 0u;
    int has_rva = 0;
    int has_raw = 0;

    if (data_size == 0u) {
        return uwd_fail(error, error_capacity, "empty CodeView record");
    }
    if (data_rva != 0u) {
        if (uwd_map_rva_span(pe,
                             data_rva,
                             (size_t)data_size,
                             &rva_offset,
                             NULL) != 0) {
            return uwd_fail(error,
                            error_capacity,
                            "CodeView RVA is out of bounds");
        }
        has_rva = 1;
    }
    if (raw_pointer != 0u) {
        raw_offset = (size_t)raw_pointer;
        if (!uwd_range_ok(pe->size, raw_offset, (size_t)data_size)) {
            return uwd_fail(error,
                            error_capacity,
                            "CodeView file range is out of bounds");
        }
        has_raw = 1;
    }
    if (!has_rva && !has_raw) {
        return uwd_fail(error,
                        error_capacity,
                        "CodeView record has no data location");
    }
    if (has_rva && has_raw && rva_offset != raw_offset) {
        return uwd_fail(error,
                        error_capacity,
                        "CodeView RVA and file offset disagree");
    }
    *payload_offset = has_raw ? raw_offset : rva_offset;
    return 0;
}

static int uwd_parse_rsds(const UwdParsedPe *pe,
                          size_t offset,
                          uint32_t data_size,
                          UwdPdbIdentity *identity,
                          char *error,
                          size_t error_capacity)
{
    const unsigned char *record;
    size_t path_capacity;
    size_t path_length;
    size_t basename_start = 0u;
    size_t basename_length;
    size_t i;

    if (data_size <= UWD_RSDS_HEADER_SIZE
        || !uwd_range_ok(pe->size, offset, (size_t)data_size)) {
        return uwd_fail(error, error_capacity, "truncated RSDS record");
    }
    record = pe->data + offset;
    if (memcmp(record, "RSDS", 4u) != 0) {
        return uwd_fail(error, error_capacity, "invalid RSDS signature");
    }

    path_capacity = (size_t)data_size - UWD_RSDS_HEADER_SIZE;
    path_length = path_capacity;
    for (i = 0u; i < path_capacity; ++i) {
        unsigned char value = record[UWD_RSDS_HEADER_SIZE + i];
        if (value == 0u) {
            path_length = i;
            break;
        }
        if (value < 0x20u || value == 0x7fu) {
            return uwd_fail(error,
                            error_capacity,
                            "invalid character in RSDS PDB path");
        }
        if (value == '\\' || value == '/') {
            basename_start = i + 1u;
        }
    }
    if (path_length == path_capacity) {
        return uwd_fail(error,
                        error_capacity,
                        "unterminated RSDS PDB path");
    }
    if (basename_start >= path_length) {
        return uwd_fail(error, error_capacity, "empty RSDS PDB basename");
    }
    basename_length = path_length - basename_start;
    if (basename_length >= UWD_PDB_NAME_CAPACITY) {
        return uwd_fail(error, error_capacity, "RSDS PDB basename is too long");
    }

    memset(identity, 0, sizeof(*identity));
    memcpy(identity->guid, record + 4u, sizeof(identity->guid));
    identity->age = uwd_read_u32(record + 20u);
    memcpy(identity->pdb_name,
           record + UWD_RSDS_HEADER_SIZE + basename_start,
           basename_length);
    identity->pdb_name[basename_length] = '\0';
    return 0;
}

static int uwd_exec_section_contains(const UwdParsedPe *pe,
                                     uint32_t begin,
                                     uint32_t end)
{
    size_t i;

    if (begin >= end) {
        return 0;
    }
    for (i = 0u; i < (size_t)pe->section_count; ++i) {
        const UwdPeSection *section = &pe->sections[i];
        uint32_t span = uwd_section_span(section);
        uint64_t section_end =
            (uint64_t)section->virtual_address + (uint64_t)span;

        if ((section->characteristics & UWD_IMAGE_SCN_MEM_EXECUTE) != 0u
            && begin >= section->virtual_address
            && (uint64_t)end <= section_end) {
            return 1;
        }
    }
    return 0;
}

static int uwd_load_pdata(const UwdParsedPe *pe,
                          UwdPdata *pdata,
                          char *error,
                          size_t error_capacity)
{
    uint32_t rva;
    uint32_t size;
    size_t offset;
    size_t count;
    size_t i;
    uint32_t previous_end = 0u;

    if (pe->directory_count <= UWD_EXCEPTION_DIRECTORY) {
        return uwd_fail(error, error_capacity, "PE has no exception directory");
    }
    rva = pe->directory_rva[UWD_EXCEPTION_DIRECTORY];
    size = pe->directory_size[UWD_EXCEPTION_DIRECTORY];
    if (rva == 0u && size == 0u) {
        return uwd_fail(error, error_capacity, "PE has no exception directory");
    }
    if (rva == 0u || size == 0u
        || size % UWD_RUNTIME_FUNCTION_SIZE != 0u) {
        return uwd_fail(error, error_capacity, "invalid exception directory");
    }
    if (uwd_map_rva_span(pe, rva, (size_t)size, &offset, NULL) != 0) {
        return uwd_fail(error, error_capacity, "exception directory is out of bounds");
    }

    count = (size_t)(size / UWD_RUNTIME_FUNCTION_SIZE);
    if (count == 0u) {
        return uwd_fail(error, error_capacity, "empty exception directory");
    }
    for (i = 0u; i < count; ++i) {
        const unsigned char *entry =
            pe->data + offset + i * UWD_RUNTIME_FUNCTION_SIZE;
        uint32_t begin = uwd_read_u32(entry);
        uint32_t end = uwd_read_u32(entry + 4u);

        if (begin >= end || end > pe->size_of_image) {
            return uwd_fail(error, error_capacity, "invalid RUNTIME_FUNCTION range");
        }
        if (i != 0u && begin < previous_end) {
            return uwd_fail(error, error_capacity, "overlapping or unsorted .pdata");
        }
        if (!uwd_exec_section_contains(pe, begin, end)) {
            return uwd_fail(error, error_capacity, ".pdata points outside executable code");
        }
        previous_end = end;
    }

    pdata->file_offset = offset;
    pdata->entry_count = count;
    return 0;
}

static int uwd_find_runtime_function(const UwdParsedPe *pe,
                                     const UwdPdata *pdata,
                                     uint32_t instruction_rva,
                                     uint32_t *begin_rva)
{
    size_t low = 0u;
    size_t high = pdata->entry_count;

    while (low < high) {
        size_t middle = low + (high - low) / 2u;
        const unsigned char *entry = pe->data + pdata->file_offset
            + middle * UWD_RUNTIME_FUNCTION_SIZE;
        uint32_t begin = uwd_read_u32(entry);
        uint32_t end = uwd_read_u32(entry + 4u);

        if (instruction_rva < begin) {
            high = middle;
        } else if (instruction_rva >= end) {
            low = middle + 1u;
        } else {
            *begin_rva = begin;
            return 0;
        }
    }
    return -1;
}

static int uwd_has_white_argument(const UwdParsedPe *pe,
                                  const UwdPeSection *section,
                                  size_t call_index,
                                  uint32_t function_begin)
{
    static const unsigned char mov_edx[] = {
        0xba, 0xff, 0xff, 0xff, 0x00
    };
    static const unsigned char mov_edx_modrm[] = {
        0xc7, 0xc2, 0xff, 0xff, 0xff, 0x00
    };
    size_t function_index;
    size_t start;
    size_t i;

    if (function_begin < section->virtual_address) {
        return 0;
    }
    function_index = (size_t)(function_begin - section->virtual_address);
    if (function_index > call_index) {
        return 0;
    }
    start = call_index > UWD_WHITE_LOOKBACK
        ? call_index - UWD_WHITE_LOOKBACK
        : 0u;
    if (start < function_index) {
        start = function_index;
    }

    for (i = start; i < call_index; ++i) {
        size_t remaining = call_index - i;
        const unsigned char *p = pe->data + section->raw_offset + i;

        if (remaining >= sizeof(mov_edx)
            && memcmp(p, mov_edx, sizeof(mov_edx)) == 0) {
            return 1;
        }
        if (remaining >= sizeof(mov_edx_modrm)
            && memcmp(p, mov_edx_modrm, sizeof(mov_edx_modrm)) == 0) {
            return 1;
        }
    }
    return 0;
}

static void uwd_record_candidate(UwdScanState *state, uint32_t candidate)
{
    if (!state->has_candidate) {
        state->has_candidate = 1;
        state->candidate_rva = candidate;
    } else if (state->candidate_rva != candidate) {
        state->ambiguous = 1;
    }
}

static void uwd_scan_calls_to_slot(const UwdParsedPe *pe,
                                   const UwdPdata *pdata,
                                   uint32_t iat_rva,
                                   UwdScanState *state)
{
    size_t section_index;

    for (section_index = 0u;
         section_index < (size_t)pe->section_count;
         ++section_index) {
        const UwdPeSection *section = &pe->sections[section_index];
        size_t raw_size;
        size_t i;

        if ((section->characteristics & UWD_IMAGE_SCN_MEM_EXECUTE) == 0u
            || section->raw_size < 6u) {
            continue;
        }
        raw_size = (size_t)section->raw_size;
        for (i = 0u; i + 6u <= raw_size; ++i) {
            const unsigned char *instruction =
                pe->data + (size_t)section->raw_offset + i;
            uint32_t call_rva;
            uint32_t displacement_bits;
            int64_t displacement;
            int64_t target;
            uint32_t function_begin;

            if (instruction[0] != 0xffu || instruction[1] != 0x15u) {
                continue;
            }
            if (i > (size_t)(UINT32_MAX - section->virtual_address)) {
                continue;
            }
            call_rva = section->virtual_address + (uint32_t)i;
            if (call_rva > UINT32_MAX - 6u) {
                continue;
            }
            displacement_bits = uwd_read_u32(instruction + 2u);
            displacement = (displacement_bits & 0x80000000u) != 0u
                ? (int64_t)displacement_bits - INT64_C(0x100000000)
                : (int64_t)displacement_bits;
            target = (int64_t)(uint64_t)(call_rva + 6u) + displacement;
            if (target < 0 || target > (int64_t)UINT32_MAX
                || (uint32_t)target != iat_rva) {
                continue;
            }

            state->saw_iat_call = 1;
            if (uwd_find_runtime_function(pe,
                                          pdata,
                                          call_rva,
                                          &function_begin) != 0) {
                continue;
            }
            state->saw_pdata_match = 1;
            if (!uwd_has_white_argument(pe,
                                        section,
                                        i,
                                        function_begin)) {
                continue;
            }
            state->saw_white_call = 1;
            uwd_record_candidate(state, function_begin);
        }
    }
}

static int uwd_scan_import_thunks(const UwdParsedPe *pe,
                                  const UwdPdata *pdata,
                                  uint32_t name_thunk_rva,
                                  uint32_t first_thunk_rva,
                                  UwdScanState *state,
                                  char *error,
                                  size_t error_capacity)
{
    size_t thunk_offset;
    size_t thunk_available;
    size_t thunk_count;
    size_t index;

    if (name_thunk_rva == 0u || first_thunk_rva == 0u
        || uwd_map_rva_span(pe,
                            name_thunk_rva,
                            8u,
                            &thunk_offset,
                            &thunk_available) != 0) {
        return uwd_fail(error, error_capacity, "invalid GDI32 import thunk");
    }
    thunk_count = thunk_available / 8u;
    for (index = 0u; index < thunk_count; ++index) {
        uint64_t thunk = uwd_read_u64(pe->data + thunk_offset + index * 8u);

        if (thunk == 0u) {
            return 0;
        }
        if ((thunk & UWD_ORDINAL_FLAG64) == 0u) {
            uint32_t name_rva;
            uint32_t function_name_rva;
            int name_match;

            if (thunk > UINT32_MAX) {
                return uwd_fail(error,
                                error_capacity,
                                "invalid import-by-name RVA");
            }
            name_rva = (uint32_t)thunk;
            if (name_rva > UINT32_MAX - 2u) {
                return uwd_fail(error,
                                error_capacity,
                                "import name RVA overflow");
            }
            function_name_rva = name_rva + 2u;
            name_match = uwd_rva_string_equal(pe,
                                              function_name_rva,
                                              "SetTextColor",
                                              0);
            if (name_match < 0) {
                return uwd_fail(error,
                                error_capacity,
                                "invalid import function name");
            }
            if (name_match != 0) {
                uint64_t slot64 = (uint64_t)first_thunk_rva
                    + (uint64_t)index * 8u;
                size_t ignored_offset;

                if (slot64 > UINT32_MAX
                    || uwd_map_rva_span(pe,
                                        (uint32_t)slot64,
                                        8u,
                                        &ignored_offset,
                                        NULL) != 0) {
                    return uwd_fail(error,
                                    error_capacity,
                                    "SetTextColor IAT slot is out of bounds");
                }
                state->saw_set_text_color_import = 1;
                uwd_scan_calls_to_slot(pe,
                                       pdata,
                                       (uint32_t)slot64,
                                       state);
            }
        }
    }
    return uwd_fail(error, error_capacity, "unterminated GDI32 import thunk");
}

static int uwd_scan_imports(const UwdParsedPe *pe,
                            const UwdPdata *pdata,
                            UwdScanState *state,
                            char *error,
                            size_t error_capacity)
{
    uint32_t directory_rva;
    uint32_t directory_size;
    size_t directory_offset;
    size_t descriptor_count;
    size_t index;
    int terminated = 0;

    if (pe->directory_count <= UWD_IMPORT_DIRECTORY) {
        return uwd_fail(error, error_capacity, "PE has no import directory");
    }
    directory_rva = pe->directory_rva[UWD_IMPORT_DIRECTORY];
    directory_size = pe->directory_size[UWD_IMPORT_DIRECTORY];
    if (directory_rva == 0u && directory_size == 0u) {
        return uwd_fail(error, error_capacity, "PE has no import directory");
    }
    if (directory_rva == 0u
        || directory_size < UWD_IMPORT_DESCRIPTOR_SIZE
        || uwd_map_rva_span(pe,
                            directory_rva,
                            (size_t)directory_size,
                            &directory_offset,
                            NULL) != 0) {
        return uwd_fail(error, error_capacity, "invalid import directory");
    }

    descriptor_count =
        (size_t)(directory_size / UWD_IMPORT_DESCRIPTOR_SIZE);
    for (index = 0u; index < descriptor_count; ++index) {
        const unsigned char *descriptor = pe->data + directory_offset
            + index * UWD_IMPORT_DESCRIPTOR_SIZE;
        uint32_t original_first_thunk = uwd_read_u32(descriptor);
        uint32_t timestamp = uwd_read_u32(descriptor + 4u);
        uint32_t forwarder_chain = uwd_read_u32(descriptor + 8u);
        uint32_t name_rva = uwd_read_u32(descriptor + 12u);
        uint32_t first_thunk = uwd_read_u32(descriptor + 16u);
        int module_match;

        if (original_first_thunk == 0u
            && timestamp == 0u
            && forwarder_chain == 0u
            && name_rva == 0u
            && first_thunk == 0u) {
            terminated = 1;
            break;
        }
        if (name_rva == 0u || first_thunk == 0u) {
            return uwd_fail(error,
                            error_capacity,
                            "invalid import descriptor");
        }
        module_match = uwd_rva_string_equal(pe,
                                            name_rva,
                                            "GDI32.dll",
                                            1);
        if (module_match < 0) {
            return uwd_fail(error, error_capacity, "invalid import DLL name");
        }
        if (module_match != 0) {
            uint32_t names_rva = original_first_thunk != 0u
                ? original_first_thunk
                : first_thunk;
            if (uwd_scan_import_thunks(pe,
                                       pdata,
                                       names_rva,
                                       first_thunk,
                                       state,
                                       error,
                                       error_capacity) != 0) {
                return -1;
            }
        }
    }
    if (!terminated) {
        return uwd_fail(error,
                        error_capacity,
                        "unterminated import descriptor table");
    }
    return 0;
}

int uwd_pe_identity(const void *data,
                    size_t size,
                    UwdPeIdentity *identity,
                    char *error,
                    size_t error_capacity)
{
    UwdParsedPe pe;

    if (identity == NULL) {
        return uwd_fail(error, error_capacity, "invalid argument");
    }
    memset(identity, 0, sizeof(*identity));
    if (uwd_parse_pe(data, size, &pe, error, error_capacity) != 0) {
        return -1;
    }
    identity->machine = pe.machine;
    identity->timestamp = pe.timestamp;
    identity->size_of_image = pe.size_of_image;
    uwd_set_error(error, error_capacity, NULL);
    return 0;
}

int uwd_pe_pdb_identity(const void *data,
                        size_t size,
                        UwdPdbIdentity *identity,
                        char *error,
                        size_t error_capacity)
{
    UwdParsedPe pe;
    uint32_t directory_rva;
    uint32_t directory_size;
    size_t directory_offset;
    size_t entry_count;
    size_t index;
    int found = 0;
    UwdPdbIdentity candidate;
    UwdPdbIdentity selected;

    if (identity == NULL) {
        return uwd_fail(error, error_capacity, "invalid argument");
    }
    memset(identity, 0, sizeof(*identity));
    if (uwd_parse_pe(data, size, &pe, error, error_capacity) != 0) {
        return -1;
    }
    if (pe.directory_count <= UWD_DEBUG_DIRECTORY) {
        return uwd_fail(error, error_capacity, "PE has no debug directory");
    }
    directory_rva = pe.directory_rva[UWD_DEBUG_DIRECTORY];
    directory_size = pe.directory_size[UWD_DEBUG_DIRECTORY];
    if (directory_rva == 0u && directory_size == 0u) {
        return uwd_fail(error, error_capacity, "PE has no debug directory");
    }
    if (directory_rva == 0u
        || directory_size == 0u
        || directory_size % UWD_DEBUG_DIRECTORY_ENTRY_SIZE != 0u
        || uwd_map_rva_span(&pe,
                            directory_rva,
                            (size_t)directory_size,
                            &directory_offset,
                            NULL) != 0) {
        return uwd_fail(error, error_capacity, "invalid debug directory");
    }

    entry_count = (size_t)(directory_size / UWD_DEBUG_DIRECTORY_ENTRY_SIZE);
    for (index = 0u; index < entry_count; ++index) {
        const unsigned char *entry = pe.data + directory_offset
            + index * UWD_DEBUG_DIRECTORY_ENTRY_SIZE;
        uint32_t type = uwd_read_u32(entry + 12u);
        uint32_t payload_size;
        uint32_t payload_rva;
        uint32_t payload_pointer;
        size_t payload_offset;

        if (type != UWD_IMAGE_DEBUG_TYPE_CODEVIEW) {
            continue;
        }
        payload_size = uwd_read_u32(entry + 16u);
        payload_rva = uwd_read_u32(entry + 20u);
        payload_pointer = uwd_read_u32(entry + 24u);
        if (uwd_debug_payload_offset(&pe,
                                     payload_rva,
                                     payload_pointer,
                                     payload_size,
                                     &payload_offset,
                                     error,
                                     error_capacity) != 0) {
            return -1;
        }
        if (payload_size < 4u) {
            return uwd_fail(error, error_capacity, "truncated CodeView record");
        }
        if (memcmp(pe.data + payload_offset, "RSDS", 4u) != 0) {
            continue;
        }
        if (uwd_parse_rsds(&pe,
                           payload_offset,
                           payload_size,
                           &candidate,
                           error,
                           error_capacity) != 0) {
            return -1;
        }
        if (!found) {
            selected = candidate;
            found = 1;
        } else if (memcmp(selected.guid,
                          candidate.guid,
                          sizeof(selected.guid)) != 0
                   || selected.age != candidate.age
                   || strcmp(selected.pdb_name, candidate.pdb_name) != 0) {
            return uwd_fail(error,
                            error_capacity,
                            "CodeView RSDS identity is ambiguous");
        }
    }
    if (!found) {
        return uwd_fail(error,
                        error_capacity,
                        "CodeView RSDS record was not found");
    }
    *identity = selected;
    uwd_set_error(error, error_capacity, NULL);
    return 0;
}

int uwd_pe_find_watermark_rva(const void *data,
                              size_t size,
                              uint32_t *function_rva,
                              char *error,
                              size_t error_capacity)
{
    UwdParsedPe pe;
    UwdPdata pdata;
    UwdScanState state;

    if (function_rva == NULL) {
        return uwd_fail(error, error_capacity, "invalid argument");
    }
    *function_rva = 0u;
    memset(&state, 0, sizeof(state));
    if (uwd_parse_pe(data, size, &pe, error, error_capacity) != 0) {
        return -1;
    }
    if (pe.machine != UWD_IMAGE_FILE_MACHINE_AMD64) {
        return uwd_fail(error,
                        error_capacity,
                        "structural watermark scan requires AMD64");
    }
    if (uwd_load_pdata(&pe, &pdata, error, error_capacity) != 0) {
        return -1;
    }
    if (uwd_scan_imports(&pe,
                         &pdata,
                         &state,
                         error,
                         error_capacity) != 0) {
        return -1;
    }
    if (!state.saw_set_text_color_import) {
        return uwd_fail(error,
                        error_capacity,
                        "GDI32.dll!SetTextColor import was not found");
    }
    if (!state.saw_iat_call) {
        return uwd_fail(error,
                        error_capacity,
                        "no call to the SetTextColor IAT slot was found");
    }
    if (!state.saw_pdata_match) {
        return uwd_fail(error,
                        error_capacity,
                        "SetTextColor call is not covered by .pdata");
    }
    if (!state.saw_white_call || !state.has_candidate) {
        return uwd_fail(error,
                        error_capacity,
                        "no SetTextColor white-color call was found");
    }
    if (state.ambiguous) {
        return uwd_fail(error,
                        error_capacity,
                        "watermark function candidate is ambiguous");
    }

    *function_rva = state.candidate_rva;
    uwd_set_error(error, error_capacity, NULL);
    return 0;
}

int uwd_pe_rva_to_offset(const void *data,
                         size_t size,
                         uint32_t rva,
                         size_t *offset)
{
    UwdParsedPe pe;
    size_t mapped;

    if (offset == NULL) {
        return -1;
    }
    *offset = 0u;
    if (uwd_parse_pe(data, size, &pe, NULL, 0u) != 0
        || uwd_map_rva_span(&pe, rva, 1u, &mapped, NULL) != 0) {
        return -1;
    }
    *offset = mapped;
    return 0;
}

int uwd_pe_rva_is_executable(const void *data,
                             size_t size,
                             uint32_t rva,
                             size_t length)
{
    UwdParsedPe pe;
    size_t index;

    if (length == 0u
        || uwd_parse_pe(data, size, &pe, NULL, 0u) != 0
        || rva >= pe.size_of_image) {
        return 0;
    }
    for (index = 0u; index < (size_t)pe.section_count; ++index) {
        const UwdPeSection *section = &pe.sections[index];
        uint32_t delta;
        size_t available;

        if ((section->characteristics & UWD_IMAGE_SCN_MEM_EXECUTE) == 0u
            || rva < section->virtual_address) {
            continue;
        }
        delta = rva - section->virtual_address;
        if (delta >= section->raw_size) {
            continue;
        }
        available = (size_t)(section->raw_size - delta);
        if (length <= available) {
            return 1;
        }
    }
    return 0;
}
