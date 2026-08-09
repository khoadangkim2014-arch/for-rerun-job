#ifndef UWD_PE_SCAN_H
#define UWD_PE_SCAN_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct UwdPeIdentity {
    uint16_t machine;
    uint32_t timestamp;
    uint32_t size_of_image;
} UwdPeIdentity;

#define UWD_PDB_NAME_CAPACITY 260u

typedef struct UwdPdbIdentity {
    uint8_t guid[16];
    uint32_t age;
    char pdb_name[UWD_PDB_NAME_CAPACITY];
} UwdPdbIdentity;

/*
 * Status functions return 0 on success and -1 on failure.  On failure,
 * output values are reset to zero.  The error buffer is optional; when
 * supplied it is always NUL terminated (provided error_capacity is nonzero).
 */
int uwd_pe_identity(const void *data,
                    size_t size,
                    UwdPeIdentity *identity,
                    char *error,
                    size_t error_capacity);

/* Reads a unique CodeView RSDS record and returns only the PDB basename. */
int uwd_pe_pdb_identity(const void *data,
                        size_t size,
                        UwdPdbIdentity *identity,
                        char *error,
                        size_t error_capacity);

/*
 * Finds the unique x64 shell32 function that calls GDI32!SetTextColor through
 * its IAT after loading white (COLORREF 0x00FFFFFF).  The returned value is the
 * enclosing RUNTIME_FUNCTION BeginAddress from the exception directory.
 * Missing and ambiguous candidates are both failures.
 */
int uwd_pe_find_watermark_rva(const void *data,
                              size_t size,
                              uint32_t *function_rva,
                              char *error,
                              size_t error_capacity);

/* Maps one file-backed byte at rva to its raw-file offset. */
int uwd_pe_rva_to_offset(const void *data,
                         size_t size,
                         uint32_t rva,
                         size_t *offset);

/*
 * Predicate: returns 1 only when the complete, nonempty range is file-backed
 * by one executable section.  Invalid PE input and all other cases return 0.
 */
int uwd_pe_rva_is_executable(const void *data,
                             size_t size,
                             uint32_t rva,
                             size_t length);

#ifdef __cplusplus
}
#endif

#endif /* UWD_PE_SCAN_H */
