#include <stdint.h>
#include <stdlib.h>
#include <assert.h>       
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <string.h>
#include <stdbool.h>
#include <signal.h>

#include <stdio.h>

#include <elf.h>

#define ELF_MAGIC 0x464c457f    // 0x7f + "ELF"
#define ELF_PHOFF_32 0x34
#define ELF_PHOFF_64 0x40
#define INT3 ((uint8_t)0xcc)

struct elf
{
    size_t map_length;
    void *map;
    void *base;
    void *vaddr_start;
    size_t file_length;
    union
    {   
        void *file;
        Elf32_Ehdr *e_hdr32;
        Elf64_Ehdr *e_hdr64;
    };
    size_t phnum;
    union
    {   
        void *e_pht;
        Elf32_Phdr *e_pht32;
        Elf64_Phdr *e_pht64;
    };
    size_t shnum;
    union
    {   
        void *e_sht;
        Elf32_Shdr *e_sht32;
        Elf64_Shdr *e_sht64;
    };
    uint8_t class;
};

void int3(int signo)
{
    assert(false);
}

void validate_elf_header64(struct elf elf)
{
    assert(elf.file_length >= sizeof(Elf64_Ehdr) + sizeof(Elf64_Phdr));

    assert(elf.e_hdr64->e_entry); // should check if entry is in code
    assert(elf.e_hdr64->e_phoff == ELF_PHOFF_64); // should follow elf header
    assert(elf.e_hdr64->e_shoff < elf.file_length - sizeof(Elf64_Shdr));
    assert(elf.e_hdr64->e_ehsize == sizeof(Elf64_Ehdr));
    assert(elf.e_hdr64->e_phentsize == sizeof(Elf64_Phdr));
    assert(elf.e_hdr64->e_phnum > 0);
    assert(elf.e_hdr64->e_shentsize == sizeof(Elf64_Shdr));
    assert(elf.e_hdr64->e_shstrndx < elf.e_hdr64->e_shnum);

    assert(elf.file_length >= 
        sizeof(Elf64_Ehdr) 
        + elf.e_hdr64->e_phnum * sizeof(Elf64_Phdr)
        + elf.e_hdr64->e_shnum * sizeof(Elf64_Shdr));
}

void validate_elf_header32(struct elf elf)
{
    assert(elf.e_hdr32->e_entry);
    assert(elf.e_hdr32->e_phoff == ELF_PHOFF_32); // should follow elf header
    assert(elf.e_hdr32->e_shoff < elf.file_length - sizeof(Elf32_Shdr));
    assert(elf.e_hdr32->e_ehsize == sizeof(Elf32_Ehdr));
    assert(elf.e_hdr32->e_phentsize == sizeof(Elf32_Phdr));
    assert(elf.e_hdr32->e_phnum > 0);
    assert(elf.e_hdr32->e_shentsize == sizeof(Elf32_Shdr));
    assert(elf.e_hdr32->e_shstrndx < elf.e_hdr32->e_shnum);

    assert(elf.file_length >= 
        sizeof(Elf32_Ehdr) 
        + elf.e_hdr32->e_phnum * sizeof(Elf32_Phdr)
        + elf.e_hdr32->e_shnum * sizeof(Elf32_Shdr));
}

void validate_elf_header(struct elf elf)
{
    assert(elf.file);
    assert(elf.file_length >= sizeof(Elf32_Ehdr) + sizeof(Elf32_Phdr));

    char *ident = (char *)elf.e_hdr32->e_ident;
    
    uint32_t magic = (uint32_t)*(uint32_t *)ident;
    assert(magic == ELF_MAGIC);

    uint8_t class = ident[EI_CLASS];
    assert(class == ELFCLASS32 || class == ELFCLASS64);

    assert(ident[EI_DATA] == ELFDATA2LSB); // only lsb
    assert(ident[EI_VERSION] == EV_CURRENT);

    assert(elf.e_hdr32->e_type == ET_EXEC 
        || elf.e_hdr32->e_type == ET_DYN); // only execs or libs
    assert(elf.e_hdr32->e_machine == EM_386 
        || (elf.e_hdr32->e_machine == EM_X86_64 
            && class == ELFCLASS64)); // only intel (non-itanium)
    assert(elf.e_hdr32->e_version == EV_CURRENT);

    class == ELFCLASS32 
        ? validate_elf_header32(elf)
        : validate_elf_header64(elf);
}

struct elf validate_elf_pht64(struct elf elf)
{
    bool found_pt_phdr= false;
    bool found_pt_interp = false;
    bool found_pt_load = false;
    Elf64_Addr last_load_vaddr = 0;
    for (size_t i = 0; i < elf.phnum; ++i)
    {
        Elf64_Phdr phdr = elf.e_pht64[i];
        assert(phdr.p_offset + phdr.p_filesz < elf.file_length);
        // not totally sure about this end calculation ...
        size_t end = phdr.p_vaddr + phdr.p_memsz;
        if (end > elf.map_length)
        {
            elf.map_length = end;
        }                
        if (phdr.p_vaddr < (uint64_t)elf.vaddr_start)
        {
            elf.vaddr_start = (void *)phdr.p_vaddr;
        }
        switch (phdr.p_type)
        {
            case PT_NULL:
            case PT_GNU_STACK:
            case PT_GNU_EH_FRAME:
            case PT_GNU_RELRO:
                continue;
            case PT_LOAD:
                found_pt_load = true;
                assert(phdr.p_filesz <= phdr.p_memsz);
                assert(phdr.p_vaddr >= last_load_vaddr);
                last_load_vaddr = phdr.p_vaddr;
                continue;
            case PT_DYNAMIC:
                assert(phdr.p_memsz >= sizeof(Elf64_Dyn));
                continue;
            case PT_INTERP:
                assert(!found_pt_interp);
                assert(!found_pt_load);
                assert(phdr.p_filesz > 0);
                assert(((char *)elf.file)[phdr.p_filesz - 1] == '\0');
                continue;
            case PT_NOTE:
                assert(phdr.p_memsz >= sizeof(Elf64_Nhdr));
                continue;
            case PT_PHDR:
                // doesn't check if phdr is part of the memory image
                // because it forward references load entries ...
                assert(!found_pt_phdr);
                assert(!found_pt_load);
                continue;
            default:
                assert(false);
        }
    }
    assert(elf.vaddr_start != NULL - 1);
    return elf;
}

struct elf validate_elf_pht32(struct elf elf)
{    
    bool found_pt_phdr= false;
    bool found_pt_interp = false;
    bool found_pt_load = false;
    Elf32_Addr last_load_vaddr = 0;
    for (size_t i = 0; i < elf.phnum; ++i)
    {
        Elf32_Phdr phdr = elf.e_pht32[i];
        assert(phdr.p_offset + phdr.p_filesz < elf.file_length);
        // not totally sure about this end calculation ...
        size_t end = phdr.p_vaddr + phdr.p_memsz;
        if (end > elf.map_length)
        {
            elf.map_length = end;
        }                
        if (phdr.p_vaddr < (uint64_t)elf.vaddr_start)
        {
            elf.vaddr_start = (void *)(uint64_t)phdr.p_vaddr;
        }
        switch (phdr.p_type)
        {
            case PT_NULL:
                continue;
            case PT_LOAD:
                found_pt_load = true;
                assert(phdr.p_filesz <= phdr.p_memsz);
                assert(phdr.p_vaddr >= last_load_vaddr);
                last_load_vaddr = phdr.p_vaddr;
                continue;
            case PT_DYNAMIC:
                assert(phdr.p_memsz >= sizeof(Elf32_Dyn));
                continue;
            case PT_INTERP:
                assert(!found_pt_interp);
                assert(!found_pt_load);
                assert(phdr.p_filesz > 0);
                assert(((char *)elf.file)[phdr.p_filesz - 1] == '\0');
                continue;
            case PT_NOTE:
                assert(phdr.p_memsz >= sizeof(Elf32_Nhdr));
                continue;
            case PT_PHDR:
                // doesn't check if phdr is part of the memory image
                // because it forward references load entries ...
                assert(!found_pt_phdr);
                assert(!found_pt_load);
                continue;
            default:
                assert(false);
        }
    }
    assert(elf.vaddr_start != NULL - 1);
    return elf;
}

struct elf validate_elf_pht(struct elf elf)
{
    switch (elf.class)
    {
        case ELFCLASS32:
            return validate_elf_pht32(elf);
        case ELFCLASS64:
            return validate_elf_pht64(elf);
        default:
            assert(false);
    }
}

struct elf map_phdr64(struct elf elf, Elf64_Phdr phdr)
{
    Elf64_Off offset = phdr.p_offset;
    // void *target = (void *)(phdr.p_vaddr - (uint64_t)elf.vaddr_start);
    void *target = (void *)(elf.base + (uint64_t)phdr.p_vaddr);
    size_t file_size = phdr.p_filesz;
    size_t mem_size = phdr.p_memsz;
    size_t bss_size = mem_size - file_size;
    // flags are not implemented ...
    // assume reachable code is executable
    // alignment is also not checked ...
    memcpy(target, elf.file + offset, file_size);
    memset(target + file_size, 0, bss_size);
    return elf;
}

struct elf map_phdr32(struct elf elf, Elf32_Phdr phdr)
{
    Elf32_Off offset = phdr.p_offset;
    // void *target = (void *)(phdr.p_vaddr - (uint64_t)elf.vaddr_start);
    void *target = (void *)(elf.base + (uint64_t)phdr.p_vaddr);
    size_t file_size = phdr.p_filesz;
    size_t mem_size = phdr.p_memsz;
    size_t bss_size = mem_size - file_size;
    // flags are not implemented ...
    // assume reachable code is executable
    // proper alignment is also not checked ...
    memcpy(target, elf.file + offset, file_size);
    memset(target + file_size, 0, bss_size);
    return elf;
}

struct elf parse_elf_pht(struct elf elf)
{
    assert(elf.map_length);
    // portable anonymous mapping
    int zero_fd = open("/dev/zero", O_RDWR);
    assert(zero_fd > -1);
    elf.map = mmap(
        NULL, 
        elf.map_length, 
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE,
        zero_fd,
        0);
    close(zero_fd);
    assert(elf.map && elf.map != MAP_FAILED);
    memset(elf.map, INT3, elf.map_length);
    // not quite the spec ...
    // elf.base = elf.map - (uint64_t)elf.vaddr_start;
    elf.base = elf.map;
    assert(elf.base >= elf.map);
    // this switch has no method of closing the maps on assertion failure
    // hopefully my computer is smart enough, or I should replace assert
    for (size_t i = 0; i < elf.phnum; ++i)
    {
        switch (elf.class)
        {
            case ELFCLASS32:
                elf = map_phdr32(elf, elf.e_pht32[i]);
                continue;
            case ELFCLASS64:
                elf = map_phdr64(elf, elf.e_pht64[i]);
                continue;
            default:
                assert(false);
        }
    }
    assert(false);
    return elf;
}

struct elf parse_elf(struct elf elf)
{
    assert(elf.file);
    assert(elf.file_length);
    validate_elf_header(elf);
    switch (elf.class)
    {
        case ELFCLASS32:
            elf.phnum = elf.e_hdr32->e_phnum;
            elf.e_pht = elf.file + ELF_PHOFF_32;
            elf.shnum = elf.e_hdr32->e_shnum;
            elf.e_sht = elf.file + elf.e_hdr32->e_shoff;
            break;
        case ELFCLASS64:
            elf.phnum = elf.e_hdr64->e_phnum;
            elf.e_pht = elf.file + ELF_PHOFF_64;
            elf.shnum = elf.e_hdr64->e_shnum;
            elf.e_sht = elf.file + elf.e_hdr64->e_shoff;
            break;
        default:
            assert(false);
    }
    elf = validate_elf_pht(elf);
    elf = parse_elf_pht(elf);
    return elf;
}

struct elf read_elf(char *pathname)
{
    assert(pathname);
    int fd = open(pathname, O_RDONLY);
    assert(fd >= 0);
    struct elf elf;
    memset(&elf, 0, sizeof(elf));
    elf.vaddr_start = NULL - 1;

    // basic sanity checks
    uint32_t magic = 0;
    if (read(fd, &magic, sizeof(magic)) != sizeof(magic)
        || magic != ELF_MAGIC)
    {
        goto read_elf_error;
    }
    
    uint8_t class = 0;
    if (read(fd, &class, sizeof(class)) != sizeof(class)
        || (class != ELFCLASS32 && class != ELFCLASS64))
    {
        goto read_elf_error;
    }
    elf.class = class;
    
    uint8_t data = 0;
    if (read(fd, &data, sizeof(data)) != sizeof(data)
        || data != ELFDATA2LSB)
    {
        goto read_elf_error;
    }

    struct stat st;
    if (fstat(fd, &st) < 0)
    {
        goto read_elf_error;
    }
    off_t size = st.st_size;
    if (class == ELFCLASS32 
        ? size < sizeof(Elf32_Ehdr)
        : size < sizeof(Elf64_Ehdr))
    {
        goto read_elf_error;
    }
    elf.file_length = (size_t)size;

    elf.file = mmap(NULL, elf.file_length, PROT_READ, MAP_PRIVATE, fd, 0);
    if (!elf.file || elf.file == MAP_FAILED)
    {
        goto read_elf_error;
    }
    
    close(fd);
    return elf;

read_elf_error:
    if (fd >= 0)
    {
        close(fd);
    }
    if (elf.file && elf.file != MAP_FAILED)
    {
        assert(!munmap(elf.file, elf.file_length));
    }
    elf.file = MAP_FAILED;
    assert(false);
    return elf;
}

struct elf load_elf(char *pathname)
{
    assert(pathname);
    struct elf elf = read_elf(pathname);
    parse_elf(elf);
    return elf;
}

int main(int argc, char **argv, char **env)
{
    assert(argc == 2);
    signal(SIGTRAP, int3); // higher-lever (gdb) debugger overrides this
    struct elf elf = load_elf(argv[1]);
    return 0;
}
