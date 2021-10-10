#define NMD_ASSEMBLY_IMPLEMENTATION
#include "nmd_assembly.h" // from https://github.com/Nomade040/nmd
#include "elf.h" // copy from /usr/include/elf.h from my own machine
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

/* The ELF header */
typedef struct
{
  uint8_t magic[4]; /* 0x7F, 'E', 'L', 'F' */
  uint8_t class;    /* 1 = 32-bit
                     * 2 = 64-bit */
  uint8_t data;     /* 1 = little-endian 
                     * 2 = big-endian  */
  uint8_t version;  /* ELF version (always 1) */
  uint8_t osabi;    /* Target OS
                     * 0 = System V
                     * 2 = Netbsd
                     * 3 = Linux
                     * 4 = GNU/Hurd
                     * 6 = Solaris
                     * 9 = Freebsd
                     * 12 = Openbsd */
  uint8_t abiversion; /* ?? */
  uint8_t pad;      /* unused, should be zero */
} Ident;

typedef struct
{
  Ident	ident;
  uint32_t e_type;		  /* Object file type 
                         * 1 = Relocatable file
                         * 2 = Executable file 
                         * 3 = Shared object file
                         * (Not interested in the rest ATM */
  uint32_t	e_machine;  /* Machine
                         * 62 = AMD x86-64
                         * 3 = Intel 80386
                         */
  uint32_t	e_version;	/* ELF Version (again) set to 1 */
  uint32_t	e_entry;		/* Entry point virtual address */
  uint32_t	e_phoff;		/* Program header table file offset */
  uint32_t	e_shoff;		/* Section header table file offset */
  uint32_t	e_flags;		/* Processor-specific flags */
  uint32_t	e_ehsize;		/* ELF header size in bytes */
  uint32_t	e_phentsize;		/* Program header table entry size */
  uint32_t	e_phnum;		/* Program header table entry count */
  uint32_t	e_shentsize;		/* Section header table entry size */
  uint32_t	e_shnum;		/* Section header table entry count */
  uint32_t	e_shstrndx;		/* Section header string table index */
} Elf32_header;

typedef struct
{
  Ident	ident;
  uint32_t e_type;		  
  uint32_t	e_machine;		
  uint32_t	e_version;		/* Object file version */
  uint64_t	e_entry;		/* Entry point virtual address */
  uint64_t	e_phoff;		/* Program header table file offset */
  uint64_t	e_shoff;		/* Section header table file offset */
  uint32_t	e_flags;		/* Processor-specific flags */
  uint32_t	e_ehsize;		/* ELF header size in bytes */
  uint32_t	e_phentsize;		/* Program header table entry size */
  uint32_t	e_phnum;		/* Program header table entry count */
  uint32_t	e_shentsize;		/* Section header table entry size */
  uint32_t	e_shnum;		/* Section header table entry count */
  uint32_t	e_shstrndx;		/* Section header string table index */
} Elf64_header;

typedef struct {
    unsigned int counter; // count occurences
    char instr_str[32]; // store mnemonic
} InstructionCounter;

/* Returns a non-zero value on failure */
int popularity_contest(const char *filename) {
  
  FILE *fp = fopen(filename, "r");
  if (!fp) {
    perror("fopen");
    return 1;
  }

  Elf64_Ehdr elfHeader;
  size_t ret = fread(&elfHeader, sizeof(elfHeader), 1, fp);
  if (ret != 1) {
    fprintf(stderr, "Line:%d fread() failed: %zu\n", __LINE__, ret);
    return 1;
  } 

  // Specification
  if (elfHeader.e_ident[0] != 0x7f || 
      elfHeader.e_ident[1] != 0x45 || // E
      elfHeader.e_ident[2] != 0x4c || // L
      elfHeader.e_ident[3] != 0x46)   // F
  {
    puts("This is not an ELF file\n");
    return 4;
  }

  printf("e_type: %d\n", elfHeader.e_type);
  return 0;
  //if (elfHeader.e_type)

  // printf("Entrypoint %08x %lu\n", (unsigned int)elfHeader.e_entry, elfHeader.e_entry);
  // printf("Program header offset %08x %lu\n", (unsigned int)elfHeader.e_phoff, elfHeader.e_phoff);
  // printf("Section header offset %08x %lu\n", (unsigned int)elfHeader.e_shoff, elfHeader.e_shoff);

  // Seeking through a file: https://stackoverflow.com/questions/238603/how-can-i-get-a-files-size-in-c

  // Recover file size:
  fseek(fp, 0L, SEEK_END); // set cursor on the last byte
  int amount_bytes = ftell(fp); // tell which byte we are
  rewind(fp); // next read instruction, start from the beginning
  clearerr(fp); // clear feof()

  assert(elfHeader.e_shentsize == sizeof(Elf64_Shdr));

  // e_shoff header offset
  // e_shnum aantal headers
  // find the section headers and load them into Elf64_Shdr structs
  Elf64_Shdr *section_headers;
  section_headers = malloc(sizeof(Elf64_Shdr) * elfHeader.e_shnum); 
  
  // printf("Total file size: %d\n", amount_bytes);
  // printf("Section Header Offset: %zu\n", elfHeader.e_shoff);
  // printf("Section header size: %d\n", elfHeader.e_shentsize);
  // printf("Section header struct size: %zu\n", sizeof(Elf64_Shdr));
  ret = fseek(fp, elfHeader.e_shoff, SEEK_SET); 
  if (ret == -1) {
    fprintf(stderr, "Line:%d fseek() failed: %zu\n", __LINE__, ret);
    return 1;
  }

  char *section_string_table;

  for (int i = 0; i < elfHeader.e_shnum; i++) {
    
    // Read out Section Header from file
    ret = fread(section_headers + i, elfHeader.e_shentsize, 1, fp);
    if (ret != 1) {
      fprintf(stderr, "Line:%d fread() failed: %zu\n", __LINE__, ret);
      fprintf(stderr, "eof value: %d\n", feof(fp));
      fprintf(stderr, "ferror value: %d\n", ferror(fp));
      return 1;
    }
    
    // Print the properties of the Section Header
    printf("%i Str offset: %i, Type: %i, offset: %lu (%#lx), Size: %lu (%#lx)\n",
      i, section_headers[i].sh_name, section_headers[i].sh_type,
      section_headers[i].sh_offset, section_headers[i].sh_offset,
      section_headers[i].sh_size, section_headers[i].sh_size);

    if (i == elfHeader.e_shstrndx) { // This is the _Section Header String Table_
      ret = fseek(fp, section_headers[i].sh_offset, SEEK_SET); // set cursor
      if (ret == -1) {
        fprintf(stderr, "Line:%d fseek() failed: %zu\n", __LINE__, ret);
        return 1;
      }
      section_string_table = malloc(section_headers[i].sh_size); // allocate memory
      ret = fread(section_string_table, section_headers[i].sh_size, 1, fp); 
      if (ret != 1) {
        fprintf(stderr, "Line:%d fread() failed: %zu\n", __LINE__, ret);
        fprintf(stderr, "eof value: %d\n", feof(fp));
        fprintf(stderr, "ferror value: %d\n", ferror(fp));
        return 1;
      }
    }
  }

  unsigned char *buffer;
  uint8_t* buffer_end; //= buffer + sizeof(buffer);
  size_t buffer_size = 0;

  for (int i = 0; i < elfHeader.e_shnum; i++) {
    if (section_headers[i].sh_size == 0 // Not interested in pieces that are zero-size
     || section_headers[i].sh_type != SHT_PROGBITS) // issues with /bin/go
    {
      continue;
    }
    // section_headers[i].sh_name // index in section header str table
    printf("%p + section_headers.name(%d)\n", section_string_table, section_headers[i].sh_name);
    char* str = section_string_table + section_headers[i].sh_name;
    puts(str); // print section name
    fflush(stdout);
    if (*str == '.' &&
        *(str+1) == 't' &&
        str[2] == 'e' &&
        str[3] == 'x' &&
        str[4] == 't') {
      // This is the piece we want to disassemble
      
      // set cursor
      ret = fseek(fp, section_headers[i].sh_offset, SEEK_SET); 
      if (ret == -1) {
        fprintf(stderr, "Line:%d fseek() failed: %zu\n", __LINE__, ret);
        return 1;
      }

      // allocate necessary memory
      buffer_size = section_headers[i].sh_size;
      buffer = malloc(buffer_size);
      buffer_end = buffer + buffer_size;

      // read section into memory
      ret = fread(buffer, section_headers[i].sh_size, 1, fp); 
      if (ret != 1) {
        fprintf(stderr, "Line:%d fread() failed: %zu\n", __LINE__, ret);
        fprintf(stderr, "eof value: %d\n", feof(fp));
        fprintf(stderr, "ferror value: %d\n", ferror(fp));
        return 1;
      }
    }
  }

 	nmd_x86_instruction instruction;
	char formatted_instruction[128];

  // Check the amount of instructions by printing the highest enum value
  //printf("highest instruction enum: %d\n", NMD_X86_INSTRUCTION_ENDBR64);
  InstructionCounter instruction_counters[1508];
  // We are going to read from this before writing things into it
  // therefore we need to memset to avoid garbage values.
  memset(instruction_counters, 0, sizeof(instruction_counters));

	for (size_t i = 0; i < buffer_size; i += instruction.length)
	{
		if (!nmd_x86_decode(buffer + i, buffer_end - (buffer + i), &instruction, NMD_X86_MODE_64, NMD_X86_DECODER_FLAGS_ALL))
			break;

		nmd_x86_format(&instruction, formatted_instruction, NMD_X86_INVALID_RUNTIME_ADDRESS, NMD_X86_FORMAT_FLAGS_DEFAULT | NMD_X86_FORMAT_FLAGS_COMMA_SPACES);

	  // printf("%s\n", formatted_instruction);

    // copy the first 32 (or till the first space) bytes into instr_str
    for (unsigned char k = 0; k < 32  // max of 32 bytes
      && formatted_instruction[k] != ' ' // don't do spaces
      && formatted_instruction[k] != '\0' // stop at end of str
      ; k++) 
    {
      instruction_counters[instruction.id].instr_str[k] = formatted_instruction[k];
    }
    instruction_counters[instruction.id].counter++; // increment counter 
	}

  // sort the results
  bool swapped_value = false; // check if a value was swapped in the last run
  for (unsigned short k = 0; k < 1508; k++) { // iterate the maximum amount of needed iterations
    for (unsigned short i = 1; i < 1508; i++) {
      /* Check each neighbouring value and swap them if needed */
      int j = i - 1;
      if (instruction_counters[i].counter > instruction_counters[j].counter) {
        InstructionCounter swapval = instruction_counters[i];
        instruction_counters[i] = instruction_counters[j];
        instruction_counters[j] = swapval;
        swapped_value = true;
      }
    }
    if (!swapped_value) { 
      /* In order to avoid having to perform more iterations than necessary
      * in case that the data is already somewhat sorted, break out as soon as we have
      * one iteration that doesn't require us to swap any values. */

      //printf("Breaking the loop earlier at itteration %d\n", k);
      break; // quit loop earlier if the data is sorted
    }
    swapped_value = false;
  }

  // print off all the results.
  for (unsigned short i = 0; i < 1508; i++) {
    if (instruction_counters[i].counter != 0) {
      printf("%s\t%d\n", instruction_counters[i].instr_str, instruction_counters[i].counter);
    }
  }

  // perform all clean-up  
  fclose(fp);
  free(section_headers);
  if (section_string_table != NULL) {
    free(section_string_table);
  }
  if (buffer != NULL) {
    free(buffer);
  }

  return 0;
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


  return 0;
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

  if (ident.class == 1) {
    puts("Class: 32-bit");
  } else if (ident.class == 2) {
    puts("Class: 64-bit");
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


  if (fp) {
    fclose(fp);
  }
}

int main(int argc, char *argv[]) {
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
      printf("Parsing file: %s\n", argv[i]);
      parse_elf_header(argv[i]);
    }
    return 0;
  }

  for (int i = 1; i < argc; i++) {
    fprintf(stderr, "Running popularity contest for: %s\n", argv[i]);
    popularity_contest(argv[i]);
    fflush(stdout);
    fprintf(stderr, "End of popularity contest: %s\n", argv[i]);
    fprintf(stderr, "%s\n", "--------------------------------------------------------------------------------");
  }


  return 0;
}