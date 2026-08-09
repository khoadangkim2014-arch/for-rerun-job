#include "../src/pe_scan.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TEST_IMAGE_SIZE 0x800u
#define TEST_NT_OFFSET 0x80u
#define TEST_OPTIONAL_OFFSET 0x98u
#define TEST_SECTION_TABLE_OFFSET 0x188u
#define TEST_MACHINE_AMD64 0x8664u

static int g_failures;

#define CHECK(expression)                                                     \
    do {                                                                      \
        if (!(expression)) {                                                  \
            fprintf(stderr, "FAIL %s:%d: %s\n",                            \
                    __FILE__, __LINE__, #expression);                         \
            ++g_failures;                                                     \
        }                                                                     \
    } while (0)

static void put_u16(unsigned char *p, uint16_t value)
{
    p[0] = (unsigned char)value;
    p[1] = (unsigned char)(value >> 8);
}

static void put_u32(unsigned char *p, uint32_t value)
{
    p[0] = (unsigned char)value;
    p[1] = (unsigned char)(value >> 8);
    p[2] = (unsigned char)(value >> 16);
    p[3] = (unsigned char)(value >> 24);
}

static void put_u64(unsigned char *p, uint64_t value)
{
    put_u32(p, (uint32_t)value);
    put_u32(p + 4, (uint32_t)(value >> 32));
}

static void put_section(unsigned char *image,
                        size_t index,
                        const char *name,
                        uint32_t virtual_size,
                        uint32_t virtual_address,
                        uint32_t raw_size,
                        uint32_t raw_offset,
                        uint32_t characteristics)
{
    unsigned char *section = image + TEST_SECTION_TABLE_OFFSET + index * 40u;
    size_t name_length = strlen(name);

    if (name_length > 8u) {
        name_length = 8u;
    }
    memcpy(section, name, name_length);
    put_u32(section + 8u, virtual_size);
    put_u32(section + 12u, virtual_address);
    put_u32(section + 16u, raw_size);
    put_u32(section + 20u, raw_offset);
    put_u32(section + 36u, characteristics);
}

static void put_call(unsigned char *image,
                     uint32_t call_rva,
                     uint32_t target_rva)
{
    size_t offset = 0x200u + (size_t)(call_rva - 0x1000u);
    int64_t displacement =
        (int64_t)(uint64_t)target_rva - (int64_t)(uint64_t)(call_rva + 6u);

    image[offset] = 0xffu;
    image[offset + 1u] = 0x15u;
    put_u32(image + offset + 2u, (uint32_t)displacement);
}

static void put_white_edx(unsigned char *image, uint32_t instruction_rva)
{
    static const unsigned char instruction[] = {
        0xba, 0xff, 0xff, 0xff, 0x00
    };
    size_t offset = 0x200u + (size_t)(instruction_rva - 0x1000u);

    memcpy(image + offset, instruction, sizeof(instruction));
}

static void put_runtime_function(unsigned char *image,
                                 size_t index,
                                 uint32_t begin,
                                 uint32_t end)
{
    unsigned char *entry = image + 0x600u + index * 12u;

    put_u32(entry, begin);
    put_u32(entry + 4u, end);
    put_u32(entry + 8u, 0x3050u);
}

static uint32_t put_rsds(unsigned char *image,
                         size_t file_offset,
                         unsigned int guid_seed,
                         uint32_t age,
                         const char *pdb_path)
{
    size_t i;
    size_t path_size = strlen(pdb_path) + 1u;

    memcpy(image + file_offset, "RSDS", 4u);
    for (i = 0u; i < 16u; ++i) {
        image[file_offset + 4u + i] =
            (unsigned char)(guid_seed + (unsigned int)i);
    }
    put_u32(image + file_offset + 20u, age);
    memcpy(image + file_offset + 24u, pdb_path, path_size);
    return (uint32_t)(24u + path_size);
}

static void put_debug_entry(unsigned char *image,
                            size_t index,
                            uint32_t payload_size,
                            uint32_t payload_rva,
                            uint32_t payload_offset)
{
    unsigned char *entry = image + 0x500u + index * 28u;

    put_u32(entry + 12u, 2u);            /* IMAGE_DEBUG_TYPE_CODEVIEW */
    put_u32(entry + 16u, payload_size);
    put_u32(entry + 20u, payload_rva);
    put_u32(entry + 24u, payload_offset);
}

static void make_valid_image(unsigned char image[TEST_IMAGE_SIZE])
{
    unsigned char *coff;
    unsigned char *optional;
    unsigned char *descriptor;

    memset(image, 0, TEST_IMAGE_SIZE);
    image[0] = 'M';
    image[1] = 'Z';
    put_u32(image + 0x3cu, TEST_NT_OFFSET);

    image[TEST_NT_OFFSET] = 'P';
    image[TEST_NT_OFFSET + 1u] = 'E';
    coff = image + TEST_NT_OFFSET + 4u;
    put_u16(coff, 0x8664u);              /* AMD64 */
    put_u16(coff + 2u, 3u);
    put_u32(coff + 4u, 0x12345678u);
    put_u16(coff + 16u, 0x00f0u);
    put_u16(coff + 18u, 0x2022u);        /* executable, large-address, DLL */

    optional = image + TEST_OPTIONAL_OFFSET;
    put_u16(optional, 0x020bu);          /* PE32+ */
    put_u32(optional + 56u, 0x4000u);    /* SizeOfImage */
    put_u32(optional + 60u, 0x0200u);    /* SizeOfHeaders */
    put_u32(optional + 108u, 16u);       /* NumberOfRvaAndSizes */
    put_u32(optional + 120u, 0x2000u);   /* import RVA */
    put_u32(optional + 124u, 40u);       /* descriptor plus terminator */
    put_u32(optional + 136u, 0x3000u);   /* exception RVA */
    put_u32(optional + 140u, 12u);       /* one RUNTIME_FUNCTION */
    put_u32(optional + 160u, 0x2100u);   /* debug-directory RVA */
    put_u32(optional + 164u, 28u);       /* one debug-directory entry */

    put_section(image, 0u, ".text", 0x200u, 0x1000u,
                0x200u, 0x200u, 0x60000020u);
    put_section(image, 1u, ".rdata", 0x200u, 0x2000u,
                0x200u, 0x400u, 0x40000040u);
    put_section(image, 2u, ".pdata", 0x200u, 0x3000u,
                0x200u, 0x600u, 0x40000040u);

    descriptor = image + 0x400u;
    put_u32(descriptor, 0x2080u);        /* OriginalFirstThunk */
    put_u32(descriptor + 12u, 0x2040u);  /* DLL name */
    put_u32(descriptor + 16u, 0x20c0u);  /* FirstThunk */
    memcpy(image + 0x440u, "GDI32.dll", sizeof("GDI32.dll"));
    put_u64(image + 0x480u, 0x20a0u);
    put_u64(image + 0x488u, 0u);
    put_u16(image + 0x4a0u, 0u);         /* IMAGE_IMPORT_BY_NAME.Hint */
    memcpy(image + 0x4a2u, "SetTextColor", sizeof("SetTextColor"));
    put_u64(image + 0x4c0u, 0x20a0u);
    put_u64(image + 0x4c8u, 0u);
    put_debug_entry(image,
                    0u,
                    put_rsds(image,
                             0x540u,
                             1u,
                             5u,
                             "C:\\symbols\\shell32.pdb"),
                    0x2140u,
                    0x540u);

    put_white_edx(image, 0x1030u);
    put_call(image, 0x1040u, 0x20c0u);
    put_runtime_function(image, 0u, 0x1010u, 0x1070u);
}

static void test_valid_image(void)
{
    unsigned char image[TEST_IMAGE_SIZE];
    UwdPeIdentity identity;
    UwdPdbIdentity pdb_identity;
    uint32_t function_rva = 0u;
    size_t offset = 0u;
    char error[128];

    make_valid_image(image);
    memset(error, 0x55, sizeof(error));
    CHECK(uwd_pe_identity(image, sizeof(image), &identity,
                          error, sizeof(error)) == 0);
    CHECK(identity.machine == 0x8664u);
    CHECK(identity.timestamp == 0x12345678u);
    CHECK(identity.size_of_image == 0x4000u);
    CHECK(error[0] == '\0');

    CHECK(uwd_pe_pdb_identity(image, sizeof(image), &pdb_identity,
                              error, sizeof(error)) == 0);
    CHECK(pdb_identity.guid[0] == 1u);
    CHECK(pdb_identity.guid[15] == 16u);
    CHECK(pdb_identity.age == 5u);
    CHECK(strcmp(pdb_identity.pdb_name, "shell32.pdb") == 0);
    CHECK(error[0] == '\0');

    CHECK(uwd_pe_rva_to_offset(image, sizeof(image), 0x1040u, &offset) == 0);
    CHECK(offset == 0x240u);
    CHECK(uwd_pe_rva_to_offset(image, sizeof(image), 0x80u, &offset) == 0);
    CHECK(offset == 0x80u);
    CHECK(uwd_pe_rva_to_offset(image, sizeof(image), 0x3fffu, &offset) == -1);
    CHECK(offset == 0u);
    CHECK(uwd_pe_rva_is_executable(image, sizeof(image), 0x1040u, 16u) == 1);
    CHECK(uwd_pe_rva_is_executable(image, sizeof(image), 0x1040u, 0u) == 0);
    CHECK(uwd_pe_rva_is_executable(image, sizeof(image), 0x2000u, 1u) == 0);
    CHECK(uwd_pe_rva_is_executable(image, sizeof(image), 0x11f8u, 16u) == 0);
    CHECK(uwd_pe_rva_is_executable(image, sizeof(image), 0x1040u, SIZE_MAX) == 0);

    CHECK(uwd_pe_find_watermark_rva(image, sizeof(image), &function_rva,
                                    error, sizeof(error)) == 0);
    CHECK(function_rva == 0x1010u);
    CHECK(error[0] == '\0');
}

static void test_arm64_identity_only(void)
{
    unsigned char image[TEST_IMAGE_SIZE];
    UwdPeIdentity identity;
    UwdPdbIdentity pdb_identity;
    uint32_t function_rva = 99u;
    char error[64];

    make_valid_image(image);
    put_u16(image + TEST_NT_OFFSET + 4u, 0xaa64u);
    CHECK(uwd_pe_identity(image, sizeof(image), &identity,
                          error, sizeof(error)) == 0);
    CHECK(identity.machine == 0xaa64u);
    CHECK(uwd_pe_pdb_identity(image, sizeof(image), &pdb_identity,
                              error, sizeof(error)) == 0);
    CHECK(strcmp(pdb_identity.pdb_name, "shell32.pdb") == 0);
    CHECK(uwd_pe_find_watermark_rva(image, sizeof(image), &function_rva,
                                    error, sizeof(error)) == -1);
    CHECK(function_rva == 0u);
    CHECK(strstr(error, "AMD64") != NULL);
}

static void test_bad_rsds_records_fail(void)
{
    unsigned char image[TEST_IMAGE_SIZE];
    UwdPdbIdentity identity;
    char error[128];

    make_valid_image(image);
    put_u32(image + 0x510u, 24u);
    CHECK(uwd_pe_pdb_identity(image, sizeof(image), &identity,
                              error, sizeof(error)) == -1);

    make_valid_image(image);
    memset(image + 0x558u, 'A', 23u);
    CHECK(uwd_pe_pdb_identity(image, sizeof(image), &identity,
                              error, sizeof(error)) == -1);
    CHECK(strstr(error, "unterminated") != NULL);

    make_valid_image(image);
    put_u32(image + 0x518u, 0x7f0u);
    CHECK(uwd_pe_pdb_identity(image, sizeof(image), &identity,
                              error, sizeof(error)) == -1);

    make_valid_image(image);
    put_u32(image + TEST_OPTIONAL_OFFSET + 164u, 27u);
    CHECK(uwd_pe_pdb_identity(image, sizeof(image), &identity,
                              error, sizeof(error)) == -1);

    make_valid_image(image);
    put_u32(image + TEST_OPTIONAL_OFFSET + 164u, 56u);
    put_debug_entry(image,
                    1u,
                    put_rsds(image, 0x580u, 33u, 8u, "other.pdb"),
                    0x2180u,
                    0x580u);
    memset(&identity, 0xa5, sizeof(identity));
    CHECK(uwd_pe_pdb_identity(image, sizeof(image), &identity,
                              error, sizeof(error)) == -1);
    CHECK(strstr(error, "ambiguous") != NULL);
    CHECK(identity.guid[0] == 0u);
    CHECK(identity.age == 0u);
    CHECK(identity.pdb_name[0] == '\0');

    /* A valid first record must not leak through when a later record is bad. */
    make_valid_image(image);
    put_u32(image + TEST_OPTIONAL_OFFSET + 164u, 56u);
    (void)put_rsds(image, 0x580u, 33u, 8u, "broken.pdb");
    put_debug_entry(image, 1u, 25u, 0x2180u, 0x580u);
    memset(&identity, 0xa5, sizeof(identity));
    CHECK(uwd_pe_pdb_identity(image, sizeof(image), &identity,
                              error, sizeof(error)) == -1);
    CHECK(strstr(error, "unterminated") != NULL);
    CHECK(identity.guid[0] == 0u);
    CHECK(identity.age == 0u);
    CHECK(identity.pdb_name[0] == '\0');
}

static void test_same_function_is_not_ambiguous(void)
{
    unsigned char image[TEST_IMAGE_SIZE];
    uint32_t function_rva = 0u;
    char error[128];

    make_valid_image(image);
    put_white_edx(image, 0x1050u);
    put_call(image, 0x1060u, 0x20c0u);
    CHECK(uwd_pe_find_watermark_rva(image, sizeof(image), &function_rva,
                                    error, sizeof(error)) == 0);
    CHECK(function_rva == 0x1010u);
}

static void test_ambiguous_functions_fail(void)
{
    unsigned char image[TEST_IMAGE_SIZE];
    uint32_t function_rva = 99u;
    char error[128];

    make_valid_image(image);
    put_u32(image + TEST_OPTIONAL_OFFSET + 140u, 24u);
    put_runtime_function(image, 1u, 0x1080u, 0x10c0u);
    put_white_edx(image, 0x1088u);
    put_call(image, 0x1098u, 0x20c0u);
    CHECK(uwd_pe_find_watermark_rva(image, sizeof(image), &function_rva,
                                    error, sizeof(error)) == -1);
    CHECK(function_rva == 0u);
    CHECK(strstr(error, "ambiguous") != NULL);
}

static void test_wrong_color_fails(void)
{
    unsigned char image[TEST_IMAGE_SIZE];
    uint32_t function_rva = 99u;
    char error[128];

    make_valid_image(image);
    image[0x230u] = 0x90u;
    CHECK(uwd_pe_find_watermark_rva(image, sizeof(image), &function_rva,
                                    error, sizeof(error)) == -1);
    CHECK(function_rva == 0u);
}

static void test_every_truncation_is_safe(void)
{
    unsigned char image[TEST_IMAGE_SIZE];
    size_t length;

    make_valid_image(image);
    for (length = 0u; length < sizeof(image); ++length) {
        UwdPeIdentity identity;
        UwdPdbIdentity pdb_identity;
        uint32_t function_rva = 0xaaaaaaaau;
        size_t offset = 123u;
        char error[8];

        CHECK(uwd_pe_identity(image, length, &identity,
                              error, sizeof(error)) == -1);
        CHECK(uwd_pe_find_watermark_rva(image, length, &function_rva,
                                        error, sizeof(error)) == -1);
        CHECK(uwd_pe_pdb_identity(image, length, &pdb_identity,
                                  error, sizeof(error)) == -1);
        CHECK(function_rva == 0u);
        CHECK(uwd_pe_rva_to_offset(image, length, 0x1000u, &offset) == -1);
        CHECK(offset == 0u);
        CHECK(uwd_pe_rva_is_executable(image, length, 0x1000u, 1u) == 0);
        CHECK(error[sizeof(error) - 1u] == '\0'
              || memchr(error, '\0', sizeof(error)) != NULL);
    }
}

static void test_hostile_fields_are_safe(void)
{
    unsigned char image[TEST_IMAGE_SIZE];
    UwdPeIdentity identity;
    uint32_t function_rva;
    size_t offset;
    char error[1];

    CHECK(uwd_pe_identity(NULL, 0u, &identity, error, sizeof(error)) == -1);
    CHECK(error[0] == '\0');
    CHECK(uwd_pe_identity(image, sizeof(image), NULL,
                          error, sizeof(error)) == -1);
    CHECK(uwd_pe_pdb_identity(image, sizeof(image), NULL,
                              error, sizeof(error)) == -1);
    CHECK(uwd_pe_find_watermark_rva(image, sizeof(image), NULL,
                                    error, sizeof(error)) == -1);
    CHECK(uwd_pe_rva_to_offset(image, sizeof(image), 0u, NULL) == -1);

    make_valid_image(image);
    put_u32(image + 0x3cu, 0xfffffff0u);
    CHECK(uwd_pe_identity(image, sizeof(image), &identity,
                          error, sizeof(error)) == -1);

    make_valid_image(image);
    put_u16(image + TEST_NT_OFFSET + 6u, 0xffffu);
    CHECK(uwd_pe_identity(image, sizeof(image), &identity,
                          error, sizeof(error)) == -1);

    make_valid_image(image);
    put_u32(image + TEST_SECTION_TABLE_OFFSET + 20u, 0xfffffff0u);
    CHECK(uwd_pe_identity(image, sizeof(image), &identity,
                          error, sizeof(error)) == -1);

    make_valid_image(image);
    put_u32(image + TEST_OPTIONAL_OFFSET + 120u, 0xfffffff0u);
    function_rva = 1u;
    CHECK(uwd_pe_find_watermark_rva(image, sizeof(image), &function_rva,
                                    error, sizeof(error)) == -1);
    CHECK(function_rva == 0u);

    make_valid_image(image);
    put_u32(image + TEST_OPTIONAL_OFFSET + 140u, 0xfffffff8u);
    CHECK(uwd_pe_find_watermark_rva(image, sizeof(image), &function_rva,
                                    error, sizeof(error)) == -1);

    make_valid_image(image);
    put_u32(image + 0x414u, 1u); /* corrupt the null import descriptor */
    CHECK(uwd_pe_find_watermark_rva(image, sizeof(image), &function_rva,
                                    error, sizeof(error)) == -1);

    make_valid_image(image);
    put_u32(image + 0x60cu, 0x1020u);
    put_u32(image + 0x610u, 0x1050u);
    put_u32(image + TEST_OPTIONAL_OFFSET + 140u, 24u);
    CHECK(uwd_pe_find_watermark_rva(image, sizeof(image), &function_rva,
                                    error, sizeof(error)) == -1);

    make_valid_image(image);
    CHECK(uwd_pe_rva_to_offset(image, sizeof(image), UINT32_MAX, &offset) == -1);
}

static void test_garbage_inputs_are_safe(void)
{
    unsigned char garbage[512];
    size_t length;

    memset(garbage, 0xa5, sizeof(garbage));
    for (length = 0u; length <= sizeof(garbage); ++length) {
        UwdPeIdentity identity;
        UwdPdbIdentity pdb_identity;
        uint32_t function_rva;
        size_t offset;

        (void)uwd_pe_identity(garbage, length, &identity, NULL, 0u);
        (void)uwd_pe_find_watermark_rva(garbage, length, &function_rva,
                                        NULL, 0u);
        (void)uwd_pe_pdb_identity(garbage, length, &pdb_identity, NULL, 0u);
        (void)uwd_pe_rva_to_offset(garbage, length, 0xfffffff0u, &offset);
        CHECK(uwd_pe_rva_is_executable(garbage,
                                       length,
                                       0xfffffff0u,
                                       SIZE_MAX) == 0);
    }
}

static int run_shell32_smoke_test(const char *path)
{
    FILE *file;
    long file_length;
    unsigned char *data;
    size_t bytes_read;
    UwdPeIdentity identity;
    UwdPdbIdentity pdb_identity;
    uint32_t function_rva;
    char error[256];

    file = fopen(path, "rb");
    if (file == NULL) {
        fprintf(stderr, "cannot open shell32 image: %s\n", path);
        return -1;
    }
    if (fseek(file, 0L, SEEK_END) != 0
        || (file_length = ftell(file)) <= 0L
        || fseek(file, 0L, SEEK_SET) != 0) {
        fprintf(stderr, "cannot determine shell32 image size: %s\n", path);
        fclose(file);
        return -1;
    }
    data = (unsigned char *)malloc((size_t)file_length);
    if (data == NULL) {
        fprintf(stderr, "cannot allocate %ld bytes for shell32 image\n",
                file_length);
        fclose(file);
        return -1;
    }
    bytes_read = fread(data, 1u, (size_t)file_length, file);
    fclose(file);
    if (bytes_read != (size_t)file_length) {
        fprintf(stderr, "cannot read complete shell32 image: %s\n", path);
        free(data);
        return -1;
    }
    if (uwd_pe_identity(data, bytes_read, &identity,
                        error, sizeof(error)) != 0) {
        fprintf(stderr, "shell32 identity failed: %s\n", error);
        free(data);
        return -1;
    }
    if (uwd_pe_pdb_identity(data, bytes_read, &pdb_identity,
                            error, sizeof(error)) != 0) {
        fprintf(stderr, "shell32 PDB identity failed: %s\n", error);
        free(data);
        return -1;
    }
    printf("shell32 machine=%04x timestamp=%08x size=%08x "
           "pdb=%s age=%u",
           (unsigned int)identity.machine,
           (unsigned int)identity.timestamp,
           (unsigned int)identity.size_of_image,
           pdb_identity.pdb_name,
           (unsigned int)pdb_identity.age);
    if (identity.machine == TEST_MACHINE_AMD64 &&
        uwd_pe_find_watermark_rva(data, bytes_read, &function_rva,
                                  error, sizeof(error)) == 0 &&
        uwd_pe_rva_is_executable(data, bytes_read, function_rva, 16u)) {
        printf(" structural_candidate=%08x (diagnostics-only)",
               (unsigned int)function_rva);
    } else {
        printf(" structural_candidate=unavailable");
    }
    putchar('\n');
    free(data);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc > 2) {
        fprintf(stderr, "usage: %s [shell32.dll]\n", argv[0]);
        return 2;
    }
    test_valid_image();
    test_arm64_identity_only();
    test_bad_rsds_records_fail();
    test_same_function_is_not_ambiguous();
    test_ambiguous_functions_fail();
    test_wrong_color_fails();
    test_every_truncation_is_safe();
    test_hostile_fields_are_safe();
    test_garbage_inputs_are_safe();

    if (g_failures != 0) {
        fprintf(stderr, "%d pe_scan test(s) failed\n", g_failures);
        return 1;
    }
    if (argc == 2 && run_shell32_smoke_test(argv[1]) != 0) {
        return 1;
    }
    puts("pe_scan tests passed");
    return 0;
}
