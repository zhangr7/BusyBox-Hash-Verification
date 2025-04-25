//config:config VERIFYHASH
//config:   bool "verifyhash"
//config:   default n
//config:   help
//config:       Say yes to enable the verifyhash applet for 
//config:       checking hash of /proc/self/exe


//kbuild:lib-$(CONFIG_VERIFYHASH) += verifyhash.o
//applet:IF_VERIFYHASH(APPLET(verifyhash, BB_DIR_USR_BIN, BB_SUID_DROP))

//usage:#define verifyhash_trivial_usage "[--output-hash]"
//usage:#define verifyhash_full_usage "\n\nVerify /proc/self/exe hash against a known hash value."

#include "libbb.h" // For sha512_* functions
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <elf.h>
#include <sys/mman.h>
#include <sys/stat.h>

#define OUTPUT_HASH_FLAG "--output-hash"  // Define the flag for outputting the hash

// Define a section in the binary called .hashsig to store the known good hash.
// This section is excluded from the hash computation at runtime.
__attribute__((section(".hashsig")))
const unsigned char known_good_hash[64] = { 0 };

// This function performs hash verification of the current binary, excluding the .hashsig section.
static int verify_self_hash(int output_hash_flag)
{
    const char *self_path = "/proc/self/exe"; // Path to the current executable.
    int fd = open(self_path, O_RDONLY); // Open the binary for reading.
    if (fd < 0) {
        bb_perror_msg("open");
        return -1;
    }

    struct stat st;
    if (fstat(fd, &st) < 0) { // Get file metadata.
        bb_perror_msg("fstat");
        close(fd);
        return -1;
    }

    // Map the binary into memory for direct access.
    void *data = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (data == MAP_FAILED) {
        bb_perror_msg("mmap");
        close(fd);
        return -1;
    }

    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)data;
    Elf64_Shdr *shdrs = (Elf64_Shdr *)((char *)data + ehdr->e_shoff);
    const char *shstrtab = (const char *)data + shdrs[ehdr->e_shstrndx].sh_offset;

    // Locate .hashsig section offset and size
    off_t skip_offset = 0;
    size_t skip_size = 0;
    for (int i = 0; i < ehdr->e_shnum; i++) {
        const char *name = shstrtab + shdrs[i].sh_name;
        if (strcmp(name, ".hashsig") == 0) {
            skip_offset = shdrs[i].sh_offset;
            skip_size = shdrs[i].sh_size;
            break;
        }
    }

    sha512_ctx_t ctx;
    sha512_begin(&ctx);

    // Hash the entire file, skipping the .hashsig range
    const uint8_t *p = data;
    for (off_t i = 0; i < st.st_size; ) {
        if (i == skip_offset) {
            i += skip_size;
            continue;
        }
        size_t chunk = 1024;
        if (i + chunk > st.st_size) chunk = st.st_size - i;
        if (i < skip_offset && i + chunk > skip_offset) chunk = skip_offset - i;
        if (i > skip_offset && i < skip_offset + skip_size) {
            i = skip_offset + skip_size;
            continue;
        }
        sha512_hash(&ctx, p + i, chunk);
        i += chunk;
    }

    unsigned char computed_hash[64];
    sha512_end(&ctx, computed_hash); // Finalize the SHA-512 hash.

    munmap(data, st.st_size); // Unmap the memory-mapped binary.
    close(fd); // Close the file descriptor.

    if (output_hash_flag) {
        // If --output-hash flag is set, only output the computed hash
        char hash_hex[129] = {0};
        for (int i = 0; i < 64; ++i)
            sprintf(&hash_hex[i * 2], "%02x", computed_hash[i]);

        // Print the computed hash
        printf("%s\n", hash_hex);
        return 0;
    }

    // Compare the computed hash to the known good hash.
    if (memcmp(computed_hash, known_good_hash, 64) == 0) {
        puts("Hash match: binary integrity verified.");
        return 0;
    } else {
        puts("Hash mismatch: binary may have been tampered with!");
        return 1;
    }
}

// Main entry point of the verifyhash applet.
int verifyhash_main(int argc, char **argv) MAIN_EXTERNALLY_VISIBLE;
int verifyhash_main(int argc UNUSED_PARAM, char **argv UNUSED_PARAM)
{
    int output_hash_flag = 0;

    // Parse command-line arguments.
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], OUTPUT_HASH_FLAG) == 0) {
            output_hash_flag = 1;  // Set flag if --output-hash is found.
            break;
        }
    }

    // Invoke the hash verification function.
    return verify_self_hash(output_hash_flag);
}