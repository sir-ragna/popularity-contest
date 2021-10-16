#define NMD_ASSEMBLY_IMPLEMENTATION
#include "nmd/nmd_assembly.h" // from https://github.com/Nomade040/nmd

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

/* The first 16 bytes. This will tell use bit-Arch, endianness, ... */
typedef struct 
{
    uint8_t magic[4];   /* 0x7F, 'E', 'L', 'F' */
    uint8_t elfclass;   /* 1 = 32-bit
                         * 2 = 64-bit */
    uint8_t data;       /* 1 = little-endian 
                         * 2 = big-endian    */
    uint8_t version;    /* ELF version (always 1) */
    uint8_t osabi;      /* Target OS
                         * 0 = System V
                         * 2 = Netbsd
                         * 3 = Linux
                         * 4 = GNU/Hurd
                         * 6 = Solaris
                         * 9 = Freebsd
                         * 12 = Openbsd */
    uint8_t abiversion; /* ?? */
    uint8_t pad[7];     /* 7 bytes of padding, not used */
} Ident;

typedef struct
{
    Ident    ident;
    uint16_t e_type;    /* Object file type 
                         * 1 = Relocatable file
                         * 2 = Executable file 
                         * 3 = Shared object file
                         * (Not interested in the rest ATM */
    uint16_t e_machine; /* Machine
                         * 62 = AMD x86-64
                         * 3 = Intel 80386
                         */
    uint32_t e_version; /* ELF Version (again) set to 1 */
    uint32_t e_entry;   /* Entry point virtual address */
    uint32_t e_phoff;   /* Program header table file offset */
    uint32_t e_shoff;   /* Section header table file offset */
    uint32_t e_flags;   /* Processor-specific flags */
    uint16_t e_ehsize;  /* ELF header size in bytes. 
                         * 52 Bytes for 32-bit    */
    uint16_t e_phentsize;/* Program header table entry size */
    uint16_t e_phnum;    /* Program header table entry count */
    uint16_t e_shentsize;/* Section header table entry size */
    uint16_t e_shnum;    /* Section header table entry count */
    uint16_t e_shstrndx; /* Section header string table index */
} Elf32_header;

typedef struct
{
    Ident    ident;
    uint16_t e_type;    
    uint16_t e_machine;
    uint32_t e_version;    /* Object file version */
    uint64_t e_entry;      /* Entry point virtual address */
    uint64_t e_phoff;      /* Program header table file offset */
    uint64_t e_shoff;      /* Section header table file offset */
    uint32_t e_flags;      /* Processor-specific flags */
    uint16_t e_ehsize;     /* ELF header size in bytes 
                            * 64 Bytes for 64-bit */
    uint16_t e_phentsize;  /* Program header table entry size */
    uint16_t e_phnum;      /* Program header table entry count */
    uint16_t e_shentsize;  /* Section header table entry size */
    uint16_t e_shnum;      /* Section header table entry count */
    uint16_t e_shstrndx;   /* Section header string table index */
} Elf64_header;

typedef struct
{
    uint32_t sh_name;       /* Section name (string tbl index) */
    uint32_t sh_type;       /* Section type */
    uint32_t sh_flags;      /* Section flags */
    uint32_t sh_addr;       /* Section virtual addr at execution */
    uint32_t sh_offset;     /* Section file offset */
    uint32_t sh_size;       /* Section size in bytes */
    uint32_t sh_link;       /* Link to another section */
    uint32_t sh_info;       /* Additional section information */
    uint32_t sh_addralign;  /* Section alignment */
    uint32_t sh_entsize;    /* Entry size if section holds table */
} Elf32_sectionheader;

typedef struct
{
    uint32_t sh_name;       /* Section name (string tbl index) */
    uint32_t sh_type;       /* Section type */
    uint64_t sh_flags;      /* Section flags */
    uint64_t sh_addr;       /* Section virtual addr at execution */
    uint64_t sh_offset;     /* Section file offset */
    uint64_t sh_size;       /* Section size in bytes */
    uint32_t sh_link;       /* Link to another section */
    uint32_t sh_info;       /* Additional section information */
    uint64_t sh_addralign;  /* Section alignment */
    uint64_t sh_entsize;    /* Entry size if section holds table */
} Elf64_sectionheader;

typedef struct {
    uint8_t * data;
    size_t datalen;
} Section_data;

typedef struct {
    unsigned int counter; // count occurences
    char instr_str[32];   // store mnemonic
} Instruction_counter;

typedef struct {
    Instruction_counter counters[1508];
    /* The 1508 comes from nmd_assembly.h, I took the last enum 
     * NMD_X86_INSTRUCTION and took the last value and added one.
     * printf("highest instruction enum: %d\n", NMD_X86_INSTRUCTION_ENDBR64);
     * See nmd_assembly.h */
} Counter_container;

Counter_container* count_instructions_64bit(Section_data text) {
    /* Allocate counters and zero initialize */
    Counter_container *ics = NULL;
    ics = (Counter_container *)malloc(sizeof(Counter_container));
    memset(ics, 0, sizeof(Counter_container));

    nmd_x86_instruction instruction;
    memset(&instruction, 0, sizeof(instruction)); /* zero initialize */
    char formatted_instruction[128];

    uint8_t* data_end = text.data + text.datalen;
    for (size_t i = 0; i < text.datalen; i += instruction.length) {
        /* Consider changing NMD_X86_DECODER_FLAGS_ALL
         * maybe we can speed things up by not decoding everything. */
        if (!nmd_x86_decode(
                text.data + i, /* point to start instr */
                (size_t)data_end - (text.datalen + i), /* remaining size of the buffer */
                &instruction, /* Output */
                NMD_X86_MODE_64, 
                NMD_X86_DECODER_FLAGS_ALL)) 
        {
            break; /* failed to decode */
            /* TODO error stuff? Clean up and return NULL?  */
            free(ics);
            fprintf(stderr, "Failed to decode instruction the %ldth" 
                "instruction (addr: %#016lx)\n", i, (uint64_t)text.data + i);
        }
        /* might have to switch back to: NMD_X86_FORMAT_FLAGS_DEFAULT */
        nmd_x86_format(&instruction, formatted_instruction, NMD_X86_INVALID_RUNTIME_ADDRESS, NMD_X86_FORMAT_FLAGS_HEX);
        
        //printf("%s\n", formatted_instruction); // print as test

        /* copy the first 32 (or till the first space) bytes into instr_str */
        for (unsigned char k = 0; k < 32        /* max of 32 bytes */
            && formatted_instruction[k] != ' '  /* stop at the first space */
            && formatted_instruction[k] != '\0' /* end of str */
            ; k++) 
        {
            ics->counters[instruction.id].instr_str[k] = formatted_instruction[k];
        }
        /* increment the counter for this instruction */
        ics->counters[instruction.id].counter++;
    }

    return ics;
}

/* returns Section_data.data == NULL on failure */
Section_data get_text_section(FILE *fp) {
    Elf64_header elfheader;
    
    /* Zero initialize, the alternative is memset() */
    Section_data text_data = { .data = NULL, .datalen = 0 }; 
    
    if (fseek(fp, 0, SEEK_SET) != 0) {
        perror("fseek");
        return text_data;
    }

    if (fread(&elfheader, sizeof(elfheader), 1, fp) != 1) {
        perror("fread");
        return text_data;
    }

    if (elfheader.e_ehsize != 64) {
        fprintf(stderr, "64-bit ELF file reports an abnormal header "
            "size (%d)\n", elfheader.e_ehsize);
        return text_data;
    }

    if (elfheader.e_shentsize != sizeof(Elf64_sectionheader)) {
        fprintf(stderr, "Reported ELF section header size is wrong "
            "(%d)\n", elfheader.e_shentsize);
        return text_data;
    }

    if (-1 == fseek(fp, elfheader.e_shoff, SEEK_SET)) {
        fprintf(stderr, "fseek failed (eof=%d)\n", feof(fp));
        return text_data;
    }

    Elf64_sectionheader *section_headers;
    section_headers = (Elf64_sectionheader *)malloc(sizeof(Elf64_sectionheader) * elfheader.e_shnum);

    /* Read out the section headers */
    for (int i = 0; i < elfheader.e_shnum; i++) {
        int ret = fread(section_headers + i, sizeof(Elf64_sectionheader), 1, fp);
        if (ret != 1) {
            fprintf(stderr, "eof value: %d\n", feof(fp));
            fprintf(stderr, "ferror value: %d\n", ferror(fp));
            perror("fread");

            free(section_headers); /* cleanup */
            return text_data;
        }
    }

    /* Look up the [section header string table]-section */
    uint64_t sh_str_tbl_size = section_headers[elfheader.e_shstrndx].sh_size;
    uint64_t sh_str_tbl_offset = section_headers[elfheader.e_shstrndx].sh_offset;
    char *sh_string_table; // Hold the names of all the sections
    sh_string_table = (char *) malloc(sh_str_tbl_size);
    if (fseek(fp, sh_str_tbl_offset, SEEK_SET) == -1) { /* set cursor at offset */
        perror("fseek");
        free(section_headers);
        free(sh_string_table);
        return text_data;
    }
    /* actual read of section header    */
    if (fread(sh_string_table, sh_str_tbl_size, 1, fp) != 1) { 
        perror("fread");
        free(section_headers);
        free(sh_string_table);
        return text_data;
    }

    /* find the .text section header */
    for (int i = 0; i < elfheader.e_shnum; i++)
    {
        Elf64_sectionheader current_sh = section_headers[i];
        if (current_sh.sh_type == 1 && /* Check if Program Info bits */
            strcmp(".text", (sh_string_table + current_sh.sh_name)) == 0) {
            /* Check if the section name is '.text' */
            // printf("\tSection file offset: %ld\n", current_sh.sh_offset);
            // printf("\tSection size: %ld\n", current_sh.sh_size);
            if (fseek(fp, current_sh.sh_offset, SEEK_SET) == -1) { /* set cursor at offset */
                perror("fseek");
                free(section_headers);
                free(sh_string_table);
                return text_data;
            }

            /* Allocate required memory for .text section */
            unsigned char* text_section = (unsigned char *)malloc(current_sh.sh_size);

            /* reading in the .text section */
            if (fread(text_section, current_sh.sh_size, 1, fp) != 1) { 
                perror("fread");
                free(section_headers);
                free(sh_string_table);
                free(text_section);
                return text_data;
            }

            text_data.data = text_section;
            text_data.datalen = current_sh.sh_size;

            free(section_headers);
            free(sh_string_table);
            return text_data; /* SUCCESS */
        }
    }
    
    fprintf(stderr, ".text section not found in section headers\n");
    free(section_headers);
    free(sh_string_table);
    return text_data;
}

/* Returns a non-zero value on failure */
Counter_container* count_instructions_in_file(const char *filename) {
    
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        perror("fopen");
        return NULL;
    }
    
    Ident ident;
    if (fread(&ident, sizeof(Ident), 1, fp) != 1) {
        perror("fread");
        return NULL;
    }

    /* Check magic bytes */
    if (ident.magic[0] != 0x7f || 
        ident.magic[1] != 0x45 || // E
        ident.magic[2] != 0x4c || // L
        ident.magic[3] != 0x46)   // F
    {
        fprintf(stderr, "Not an elf file\n");
        return NULL;
    }

    if (ident.data != 1) {
        fprintf(stderr, "Only little endian is supported (reported=%d)\n", ident.data);
        return NULL;
    }

    if (ident.elfclass == 2) { /* 64-bit */

        Section_data text_section = get_text_section(fp);
        if (text_section.data == NULL) {
            /* FAILED, what now? */
            fclose(fp);
            return NULL;
        }

        Counter_container* ics = count_instructions_64bit(text_section);
        // result = count_instructions_64bit()
        // aggregate the results (maybe not here but in main func)
        //    \-->write output somewhere
        
        free(text_section.data);
        fclose(fp);
        
        if (ics == NULL) {
            fprintf(stderr, "failed to retrieve instructions from .text section\n");
            return NULL;
        }

        return ics;     

    } else if (ident.elfclass == 1) {
        // 32-bit
        // TODO
    } else {
        // WTF?
        fprintf(stderr, "Unknown elfclass bits: %d\n", ident.elfclass);
    }

    fclose(fp);
    return NULL;
}

/* Returns a non-zero value on failure */
int parse_64_bit_header(FILE *fp) {
    Elf64_header elfheader;
    
    if (fseek(fp, 0, SEEK_SET) != 0) {
        /* Could use rewind(), but that doesn't have 
         * error handling. So it is worse? */
        perror("fseek");
        return 1;
    }

    if (fread(&elfheader, sizeof(elfheader), 1, fp) != 1) {
        perror("fread");
        return 2;
    }

    switch (elfheader.e_type)
    {
    case 1:
        puts("Type: Relocatable file");
        break;
    case 2:
        puts("Type: Executable file");
        break;
    case 3:
        puts("Type: Shared object file");
        break;
    default:
        puts("Unsupported object file type");
        exit(1);
        break;
    }

    if (elfheader.e_machine != 62) {
        puts("Only AMD x86-64 machine is supported (for 64-bit systems)");
        exit(1);    
    } else {
        puts("Machine: AMD x86-64");
    }

    if (elfheader.e_version != 1) {
        puts("Can only handle ELF version 1");
        exit(1);
    }

    printf("Entrypoint: %#016lx\n", elfheader.e_entry);
    printf("Program header table offset: %ld\n", elfheader.e_phoff);
    printf("Section header table offset: %ld\n", elfheader.e_shoff);
    printf("Flags: %#08x\n", elfheader.e_flags);
    printf("ELF Header size: %#04x (%i bytes)\n", elfheader.e_ehsize, elfheader.e_ehsize);

    if (elfheader.e_ehsize != 64) {
        // I don't know in which situation this isn't 64.
        puts("Abnormal ELF Header size for 64-bit");
        exit(2); /* Exit because I don't know how I'm going to handle this */
    }

    printf("Section header table entry count: %i\n", elfheader.e_shnum);
    printf("Section header string table index: %i\n", elfheader.e_shstrndx);
    
    /* This should be a fixed size, so maybe don't print it? */
    // printf("Section header size: %d(fixed)\n", elfheader.e_shentsize);

    if (elfheader.e_shentsize != sizeof(Elf64_sectionheader)) {
        /* This might be a header issue or my the code */
        puts("Section header size doesn't match Elf64_sectionheader struct");
        exit(3);
    }

    /* Set the cursor ready for reading out for the section headers */
    if (-1 == fseek(fp, elfheader.e_shoff, SEEK_SET)) {
            fprintf(stderr, "fseek failed (eof=%d)\n", feof(fp));
            return 1;
    }

    /* Allocate the required memory */
    Elf64_sectionheader *section_headers;
    section_headers = (Elf64_sectionheader *)malloc(sizeof(Elf64_sectionheader) * elfheader.e_shnum);

    /* Read out the section headers */
    for (int i = 0; i < elfheader.e_shnum; i++) {
        int ret = fread(section_headers + i, sizeof(Elf64_sectionheader), 1, fp);
        if (ret != 1) {
            fprintf(stderr, "eof value: %d\n", feof(fp));
            fprintf(stderr, "ferror value: %d\n", ferror(fp));
            perror("fread");

            free(section_headers);
            return 1;
        }
    }

    /* Look up the [section header string table]-section */
    uint64_t sh_str_tbl_size = section_headers[elfheader.e_shstrndx].sh_size;
    uint64_t sh_str_tbl_offset = section_headers[elfheader.e_shstrndx].sh_offset;
    char *sh_string_table; // Hold the names of all the sections
    sh_string_table = (char *) malloc(sh_str_tbl_size);
    if (fseek(fp, sh_str_tbl_offset, SEEK_SET) == -1) { /* set cursor at offset */
        perror("fseek");
        free(section_headers);
        free(sh_string_table);
        return 1;
    }
    if (fread(sh_string_table, sh_str_tbl_size, 1, fp) != 1) {
        perror("fread");
        free(section_headers);
        free(sh_string_table);
        return 1;
    }

    /* Print ouf the section headers one by one */
    for (int i = 0; i < elfheader.e_shnum; i++) {
        Elf64_sectionheader sh = section_headers[i];

        /* Look up the section name in the string table */
        char *section_name = sh_string_table + section_headers[i].sh_name;
        printf("%d --- Section: %s (index: %d)\n", i, section_name, sh.sh_name);
        printf("\tType code: %d\n", sh.sh_type);
        switch (sh.sh_type)
        {
        case 0:
            puts("\tType: NULL section");
            break;
        case 1:
            puts("\tType: Program information");
            break;
        case 2:
            puts("\tType: Symbol table");
            break;
        case 3:
            puts("\tType: String table");
            break;
        case 4:
            puts("\tType: Relocation (no addend)");
            break;
        case 5:
            puts("\tType: Symbol hash table");
            break;
        case 6:
            puts("\tType: Dynamic linking information");
            break;
        case 7:
            puts("\tType: Notes");
            break;
        case 8:
            puts("\tType: Not present in file");
            break;
        case 9:
            puts("\tType: Relocation (with addend)");
            break;
        case 10:
            puts("\tType: Reserved");
            break;
        case 11:
            puts("\tType: Dynamic linker symbol table");
            break;
        case 14:
            puts("\tType: Array of constructors");
            break;
        case 15:
            puts("\tType: Array of destructors");
            break;
        case 16:
            puts("\tType: Array of pre-constructors");
            break;
        case 17:
            puts("\tType: Section group");
            break;
        case 18:
            puts("\tType: Extended section indices");
            break;
        case 19:
            puts("\tType: Number of defined types");
            break;
        case 0x60000000:
            puts("\tType: Start OS-specific");
            break;
        case 0x6ffffff5:
            puts("\tType: Object attributes");
            break;    
        case 0x6ffffff6:
            puts("\tType: GNU-style Hash table");
            break;
        case 0x6ffffff7:
            puts("\tType: Prelink libary list");
            break;    
        case 0x6ffffff8:
            puts("\tType: Checksum for DSO content");
            break;
        case 0x6ffffffa:
            puts("\tType: Sun-specific low bound");
            break;
        case 0x6ffffffd:
            puts("\tType: Version definition section");
            break;
        case 0x6ffffffe:
            puts("\tType: Version needs section");
            break;
        case 0x6fffffff:
            puts("\tType: Version symbol table(GNU symver)");
            break;
        default:
            puts("\tType is UNKNOWN");
            break;
        }
        printf("\tFlags: %ld\n", sh.sh_flags);
        if (sh.sh_flags & 0x1) {
            puts("\t\tWriteable section");
        }
        if (sh.sh_flags & 0x2) {
            puts("\t\tAllocate in memory");
        }
        if (sh.sh_flags & 0x4) {
            puts("\t\tExecutable");
        }
        if (sh.sh_flags & 0x8) {
            puts("\t\tMerge");
        }
        if (sh.sh_flags & 0x16) {
            puts("\t\tContains nul-terminated strings");
        }
        printf("\tVirtual Address: %#016lx\n", sh.sh_addr);
        printf("\tSection file offset: %ld\n", sh.sh_offset);
        printf("\tSection size: %ld\n", sh.sh_size);
        printf("\tLink: %#08x\n", sh.sh_link); /* What is Link? */
        printf("\tInfo: %#08x\n", sh.sh_info);
        printf("\tSection alignment: %#016lx\n", sh.sh_addralign);
        printf("\tEntry size: %ld\n", sh.sh_entsize);
        puts("******************************");
    }

    if (sh_string_table) {
        free(sh_string_table);
    }
    if (section_headers) {
        free(section_headers);
    }
    return 0;
}

void sort_instruction_counters(Counter_container *ics) {
    bool swapped_any_value = false;

    unsigned short possible_instructions = sizeof(Counter_container) / sizeof(Instruction_counter);
    assert(possible_instructions == 1508);
    for (unsigned short i = 0; i < possible_instructions; i++)
    {
        for (unsigned short j = 1; j < possible_instructions; j++)
        {
            int k = j - 1; /* k is previous element */
            if (ics->counters[j].counter > ics->counters[k].counter) {
                Instruction_counter swap = ics->counters[j];
                ics->counters[j] = ics->counters[k];
                ics->counters[k] = swap;
                swapped_any_value = true;
            }
        }
        if (!swapped_any_value) {
            break; 
            /* All values are sorted, avoid more iterations than necessary
             * Best case scenario, we only need one iteration because
             * the data is already sorted. */
        }        
    }
}

void print_instruction_counters(Counter_container *ics) {
    for (unsigned short i = 0; i < 1508; i++) {
        if (ics->counters[i].counter != 0) {
            printf("%s\t%d\n", ics->counters[i].instr_str, ics->counters[i].counter);
        }
    }
}

char *join_str(const char sep, char **strlst, size_t strc)
{
    char * joined = NULL;
    size_t joined_len = 512; /* Initial len */
    size_t joined_index = 0;
    joined = (char *)malloc(joined_len);
    // memset(joined, 0, joined_len); /* always initialize */
    
    for (size_t i = 1; i < strc; i++)
    {
        char * str = strlst[i];
        if (str == NULL) 
        {
            continue;
        }
        size_t len = strlen(str);

        while (joined_index + len + 1 > joined_len) 
        {
            /* If our current string len is insufficient to hold to the
             * total length of what we want to add, allocate more memory
             * in increments of 512 bytes */
            joined_len += 512;
            joined = (char *)realloc(joined, joined_len);
            // memset(joined + joined_len - 512, 0, 512);
        }
        strcpy(joined + joined_index, strlst[i]);

        if (i+1 != strc) 
        { /* We want to skip the last iteration */
            joined[joined_index + len] = sep;
        }
        joined_index += len + 1;
    }

    /* guarantee that our string ends with a NULL-byte
     * This makes the memsets unnecessary */
    joined[joined_index] = '\0';

    return joined;
}

void print_csv_table(const Counter_container *cc)
{
    unsigned int columns = 0;
    /* Print headers */
    char **col_values = NULL;
    col_values = (char **)malloc(sizeof(void*) * 1508);
    for (unsigned short i = 0; i < 1508; i++)
    {
        if (cc->counters[i].counter != 0) 
        {
            col_values[columns] = (char *)cc->counters[i].instr_str;
            columns++;
        }
    }

    char *header_str = join_str(',', col_values, columns);
    puts(header_str);
    free(header_str);

    /* print values */
    columns = 0;
    for (unsigned short i = 0; i < 1508; i++)
    {
        if (cc->counters[i].counter != 0) 
        {
            /* Convert integer to ASCII 
             * I don't like any of these: https://stackoverflow.com/questions/4629050/convert-an-int-to-ascii-character/4629161
             */
            char *ascii = (char *)malloc(14); 
            /* 13 characters is enough to print hold the value
             * 4,294,967,295 (max uint)*/
            sprintf(ascii, "%d", cc->counters[i].counter);
            col_values[columns] = ascii;
            columns++;
        }
    }
    char *values_str = join_str(',', col_values, columns);
    puts(values_str);
    free(values_str);

    /* We need to free ptrs we created to store the ascii strings of the
     * numbers. */
    for (size_t i = 0; i < columns; i++)
    {
        free(col_values[i]);
    }
    free(col_values);    
}

/* Returns a non-zero value on failure */
int parse_elf_header(const char *filename) {
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        perror("fopen");
        return 1;
    }
    Ident ident;
    size_t ret = fread(&ident, sizeof(Ident), 1, fp);
    if (ret != 1) {
        perror("fread");
        return 2;
    }

    if (ident.elfclass == 1) {
        puts("elfclass: 32-bit");
    } else if (ident.elfclass == 2) {
        puts("elfclass: 64-bit");
    } else {
        puts("Unsupported architecture");
        return 3;
    }

    if (ident.data == 1) {
        puts("Data: little endian");
    } else if (ident.data == 2) {
        puts("Data: big endian");
    } else {
        puts("Unsupported data byte");
        return 4;
    }

    if (ident.version != 1) {
        puts("Unsupported ELF version");
        return 5;
    }

    switch (ident.osabi)
    {
    case 0:
        puts("OS ABI: UNIX - System V");
        /* This is the default for most compilers.
         * This means that no OS specific extensions are used. */
        break;
    case 2:
        puts("OS ABI: NetBSD");
        break;
    case 3:
        puts("OS ABI: Linux");
        break;
    case 4:
        puts("OS ABI: GNU/Hurd");
        break;
    case 6:
        puts("OS ABI: Solaris");
        break;
    case 9:
        puts("OS ABI: FreeBSD");
        break;
    case 12:
        puts("OS ABI: OpenBSD");
        break;
    default:
        puts("OS ABI: Unknown");
        return 6;
        break;
    }

    if (ident.osabi != 0) {
        puts("non-System V ELF binaries are not implemented");
        exit(1);
    }

    // Depending on 32-bit or 64-bit
    // read out the rest of the header
    if (ident.elfclass == 1) {
        // TODO 32-bit header
    } else if (ident.elfclass == 2) {
        parse_64_bit_header(fp);
    }

    if (fp) {
        fclose(fp);
    }
    return 0;
}

int main(int argc, char *argv[]) 
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s [options] [64ELFbinary]...\n", argv[0]);
        fprintf(stderr, "\t-p Only parse the ELF header\n");
        return 1;
    }

    bool parse_elf_only = false;

    for (int i = 1; i < argc; i++) {
        if (argv[i][0] == '-' && argv[i][1] == 'p') {
            parse_elf_only = true;
        }
    }

    if (parse_elf_only) {
        for (int i = 1; i < argc; i++) {
            if (strcmp("-p", argv[i]) == 0) {
                continue;
            }
            printf("File name: %s\n", argv[i]);
            parse_elf_header(argv[i]);
        }
        return 0;
    }

    for (int i = 1; i < argc; i++) {
        fprintf(stderr, "Running popularity contest for: %s\n", argv[i]);
        Counter_container *ics = count_instructions_in_file(argv[i]);
        if (ics != NULL) {
            sort_instruction_counters(ics);
            //print_instruction_counters(ics);
            print_csv_table(ics);

            free(ics);
        }
        fflush(stdout);
        fprintf(stderr, "End of popularity contest: %s\n", argv[i]);
        fprintf(stderr, "%s\n", "--------------------------------------------------------------------------------");
    }


    return 0;
}