#define NMD_ASSEMBLY_IMPLEMENTATION
#include "nmd_assembly.h" // from https://github.com/Nomade040/nmd
#include "elf.h" // copy from /usr/include/elf.h from my own machine
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    // unsigned short NMD_X86_INSTRUCTION;
    unsigned int counter; // count occurences
    char instr_str[32]; // store mnemonic
} InstructionCounter;

void popularity_contest(const char *filename) {
    FILE *fp = fopen(filename, "r");
  if (!fp) {
    perror("fopen");
    exit(1);
  }

  Elf64_Ehdr elfHeader;
  size_t ret = fread(&elfHeader, sizeof(elfHeader), 1, fp);
  if (ret != 1) {
    fprintf(stderr, "Line:%d fread() failed: %zu\n", __LINE__, ret);
    exit(1);
  } 

  // Specification
  if (elfHeader.e_ident[0] == 0x7f && 
      elfHeader.e_ident[1] == 0x45 && // E
      elfHeader.e_ident[2] == 0x4c && // L
      elfHeader.e_ident[3] == 0x46)   // F
  { 
    //puts("This is an ELF file\n");
  } else {
    puts("This is not an ELF file\n");
    exit(4);
  }

  // printf("Entrypoint %08x %lu\n", (unsigned int)elfHeader.e_entry, elfHeader.e_entry);
  // printf("Program header offset %08x %lu\n", (unsigned int)elfHeader.e_phoff, elfHeader.e_phoff);
  // printf("Section header offset %08x %lu\n", (unsigned int)elfHeader.e_shoff, elfHeader.e_shoff);

  // Seeking through a file: https://stackoverflow.com/questions/238603/how-can-i-get-a-files-size-in-c

  // Recover file size:
  fseek(fp, 0L, SEEK_END); // set cursor on the last byte
  int amount_bytes = ftell(fp); // tell which byte we are
  rewind(fp); // next read instruction, start from the beginning
  clearerr(fp); // clear feof()

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
    exit(1);
  }

  char *section_string_table;

  for (int i = 0; i < elfHeader.e_shnum; i++) {

    // Read out Section Header from file
    ret = fread(section_headers + i, elfHeader.e_shentsize, 1, fp);
    if (ret != 1) {
      fprintf(stderr, "Line:%d fread() failed: %zu\n", __LINE__, ret);
      fprintf(stderr, "eof value: %d\n", feof(fp));
      fprintf(stderr, "ferror value: %d\n", ferror(fp));
      exit(1);
    }
    
    // Print the properties of the Section Header
    // printf("%i Str offset: %i, Type: %i, offset: %lu (%#lx), Size: %lu (%#lx)\n",
    //   i, section_headers[i].sh_name, section_headers[i].sh_type,
    //   section_headers[i].sh_offset, section_headers[i].sh_offset,
    //   section_headers[i].sh_size, section_headers[i].sh_size);

    if (i == elfHeader.e_shstrndx) { // This is the _Section Header String Table_
      ret = fseek(fp, section_headers[i].sh_offset, SEEK_SET); // set cursor
      if (ret == -1) {
        fprintf(stderr, "Line:%d fseek() failed: %zu\n", __LINE__, ret);
        exit(1);
      }
      section_string_table = malloc(section_headers[i].sh_size); // allocate memory
      ret = fread(section_string_table, section_headers[i].sh_size, 1, fp); 
      if (ret != 1) {
        fprintf(stderr, "Line:%d fread() failed: %zu\n", __LINE__, ret);
        fprintf(stderr, "eof value: %d\n", feof(fp));
        fprintf(stderr, "ferror value: %d\n", ferror(fp));
        exit(1);
      }
    }
    // if (section_headers[i].sh_type == SHT_PROGBITS) {
    //   // .text, .rodata, ....
    //   if (section_headers[i].sh_flags & SHF_EXECINSTR && // execute bit set
    //       section_headers[i].sh_flags & SHF_ALLOC)       // alloc bit set
    //   {
    //     // only .text ?
    //     puts("Executable program bits, so maybe code is here?");
    //   }
    // }

    // if (section_headers[i].sh_type == SHT_STRTAB) {
    //   // String table, With this we can find the actual names
    //   puts("String table is here\n");
    // }
  }

  unsigned char *buffer;
  uint8_t* buffer_end; //= buffer + sizeof(buffer);
  size_t buffer_size = 0;

  for (int i = 0; i < elfHeader.e_shnum; i++) {
    if (section_headers[i].sh_size == 0) {
      continue;
    }
    // section_headers[i].sh_name // index in section header str table
    char* str = section_string_table + section_headers[i].sh_name;
    // puts(str); // print section name
    if (strcmp(".text", str) == 0) {
      // This is the piece we want to disassemble
      
      // set cursor
      ret = fseek(fp, section_headers[i].sh_offset, SEEK_SET); 
      if (ret == -1) {
        fprintf(stderr, "Line:%d fseek() failed: %zu\n", __LINE__, ret);
        exit(1);
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
        exit(1);
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
}

int main(int argc, char *argv[]) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s [64ELFbinary]...\n", argv[0]);
    exit(1);
  }
  for (int i = 1; i < argc; i++ ) {
    fprintf(stderr, "Running popularity contest for: %s\n", argv[i]);
    popularity_contest(argv[i]);
    fflush(stdout);
    fprintf(stderr, "End of popularity contest: %s\n", argv[i]);
    fprintf(stderr, "%s\n", "--------------------------------------------------------------------------------");
  }


  return 0;
}