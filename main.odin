package main

import "core:fmt"
import "core:sys/windows"
import "core:mem"
import "core:os"
import "core:strings"
import "core:io"
import "core:encoding/hex"

MODE_32 :: false

IMAGE_DOS_HEADER :: struct {
  e_magic : [2]u8,

  e_cblp: u16, 
  e_cp: u16, 
  e_crlc: u16, 
  e_cparhdr: u16, 
  e_minalloc: u16, 
  e_maxalloc: u16, 
  e_ss: u16, 
  e_sp: u16, 
  e_csum: u16, 
  e_ip: u16, 
  e_cs: u16, 
  e_lfarlc: u16, 
  e_ovno: u16,

  e_res: [4]u16,
  e_oemid, e_oeminfo: u16,
  e_res2: [10]u16,
  e_lfanew: i32,
}

IMAGE_FILE_HEADER :: struct {
  Machine: u16,
  NumberOfSections: u16,
  TimeDateStamp: u32,
  PointerToSymbolTable: u32,
  NumberOfSymbols: u32,
  SizeOfOptionalHeader: u16,
  Characteristics: u16
}

IMAGE_DATA_DIRECTORY :: struct {
  VirtualAddress: u32,
  Size: u32
}

IMAGE_NUMBEROF_DIRECTORY_ENTRIES :: 16

IMAGE_OPTIONAL_HEADER64 :: struct {
  Magic: u16,
  MajorLinkerVersion: u8,
  MinorLinkerVersion: u8,
  SizeOfCode: u32,
  SizeOfInitializedData: u32,
  SizeOfUninitializedData: u32,
  AddressOfEntryPoint: u32,
  BaseOfCode: u32,
  ImageBase: u64,
  SectionAlignment: u32,
  FileAlignment: u32,
  MajorOperatingSystemVersion: u16,
  MinorOperatingSystemVersion: u16,
  MajorImageVersion: u16,
  MinorImageVersion: u16,
  MajorSubsystemVersion: u16,
  MinorSubsystemVersion: u16,
  Win32VersionValue: u32,
  SizeOfImage: u32,
  SizeOfHeaders: u32,
  CheckSum: u32,
  Subsystem: u16,
  DllCharacteristics: u16,
  SizeOfStackReserve: u64,
  SizeOfStackCommit: u64,
  SizeOfHeapReserve: u64,
  SizeOfHeapCommit: u64,
  LoaderFlags: u32,
  NumberOfRvaAndSizes: u32,
  DataDirectory: [IMAGE_NUMBEROF_DIRECTORY_ENTRIES]IMAGE_DATA_DIRECTORY,
}

IMAGE_OPTIONAL_HEADER :: struct {
  //
  // Standard fields.
  //

  Magic: windows.WORD,
  MajorLinkerVersion: windows.BYTE,
  MinorLinkerVersion: windows.BYTE,
  SizeOfCode: windows.DWORD,
  SizeOfInitializedData: windows.DWORD,
  SizeOfUninitializedData: windows.DWORD,
  AddressOfEntryPoint: windows.DWORD,
  BaseOfCode: windows.DWORD,
  BaseOfData: windows.DWORD,

  //
  // NT additional fields.
  //

  ImageBase: windows.DWORD,
  SectionAlignment: windows.DWORD,
  FileAlignment: windows.DWORD,
  MajorOperatingSystemVersion: windows.WORD ,
  MinorOperatingSystemVersion: windows.WORD ,
  MajorImageVersion: windows.WORD ,
  MinorImageVersion: windows.WORD ,
  MajorSubsystemVersion: windows.WORD ,
  MinorSubsystemVersion: windows.WORD ,
  Win32VersionValue: windows.DWORD,
  SizeOfImage: windows.DWORD,
  SizeOfHeaders: windows.DWORD,
  CheckSum: windows.DWORD,
  Subsystem: windows.WORD ,
  DllCharacteristics: windows.WORD ,
  SizeOfStackReserve: windows.DWORD,
  SizeOfStackCommit: windows.DWORD,
  SizeOfHeapReserve: windows.DWORD,
  SizeOfHeapCommit: windows.DWORD,
  LoaderFlags: windows.DWORD,
  NumberOfRvaAndSizes: windows.DWORD,
  DataDirectory: [IMAGE_NUMBEROF_DIRECTORY_ENTRIES]IMAGE_DATA_DIRECTORY,
}

IMAGE_NT_HEADERS64 :: struct {
  Signature: [2]u8, 
  FileHeader: IMAGE_FILE_HEADER,
  OptionalHeader: IMAGE_OPTIONAL_HEADER64
}

IMAGE_NT_HEADERS :: struct {
  Signature: [2]u8,
  FileHeader: IMAGE_FILE_HEADER,
  OptionalHeader: IMAGE_OPTIONAL_HEADER,
}

IMAGE_SECTION_HEADER :: struct {
  Name: [8]u8,
  VirtualSize: u32,
  VirtualAddress: u32,
  SizeOfRawData: u32,
  PointerToRawData: u32,
  PointerToRelocations: u32,
  PointerToLineNumbers: u32,
  NumberOfRelocations: u16,
  NumberOfLineNumbers: u16,
  Characteristics: u32
}

IMAGE_IMPORT_DESCRIPTOR :: struct {
  OriginalFirstThunk: u32,
  TimeDateStamp: u32,
  ForwarderChain: u32,
  Name: u32,
  FirstThunk: u32
}

IMAGE_IMPORT_BY_NAME :: struct {
  Hint: u16,
  Name: [1]u8
}


BUFFER_SIZE :: 100000
OutputBuffer :: struct{
  buffer: [BUFFER_SIZE]u8,
  index: int
}

allocate :: proc(using b: ^OutputBuffer, $T: typeid) -> ^T{
  size := size_of(T)
  ptr := &buffer[index]
  index += size
  return cast(^T)ptr
}

write_string :: proc(location: ^u8, s: cstring){
  mem.copy(location, cast(^u8)s, len(s) + 1)
}

alloc_u8_array :: proc(b: ^OutputBuffer, array: [$Size]u8) -> ^[Size]u8 {
  ptr := allocate(b, type_of(array))
  for i in 0..<len(array) {
    ptr[i] = array[i]
  }
  return ptr
}

alloc_u8 :: proc(b: ^OutputBuffer, value: u8) -> ^u8 {
  ptr := allocate(b, u8)
  ptr^ = value
  return ptr
}

alloc_string :: proc(using b: ^OutputBuffer, value: cstring) -> ^cstring {
  write_string(&buffer[index], value)
  ptr := cast(^cstring)&buffer[index]
  index += len(value) + 1
  return ptr
}


RegisterCode :: enum u8 {
  RAX,
  RCX,
  RDX,
  RBX,
  RSP,
  RBP,
  RSI,
  RDI
}

append_array :: proc(array_a: ^[dynamic]$T, array_b: [$S]T){
  for elem in array_b {
    append(array_a, elem)
  }
}


push :: proc(register: RegisterCode) -> u8 {
  return 0x50 | cast(u8)register
}

pop :: proc(register: RegisterCode) -> u8 {
  return 0x58 | cast(u8)register
}

ret :: proc() -> u8 {
  return 0xC3
}

call_relative_32 :: proc(relative_offset: u32) -> [6]u8 {
  offset_local := relative_offset
  OP_CODE: u8 = 0xFF
  output: [6]u8 = {OP_CODE, 0x15, 0, 0, 0, 0}
  mem.copy(&output[2], &offset_local, size_of(offset_local))
  return output
}

movq :: proc(register_a: RegisterCode, register_b: RegisterCode) -> [3]u8 {
  REX :u8 : 0x40 | 0x8
  OP_CODE: u8 : 0x89
  OPERANDS_REGISTER :: 0xC0
  return {REX, OP_CODE, (OPERANDS_REGISTER | (cast(u8)register_b) << 3) | cast(u8)register_a}
}

movq_immidiate :: proc(register_a: RegisterCode, immediate_value: i32) -> [7]u8 {
  REX : u8 : 0x40 | 0x8
  OP_CODE : u8 : 0xC7
  
  output: [7]u8 = {REX, OP_CODE, 0xC0 | cast(u8)register_a, 0, 0, 0, 0}
  value_copy : i32 = immediate_value
  mem.copy(&output[3], &value_copy, size_of(value_copy))
  return output
}

add_q :: proc(register_a: RegisterCode, register_b: RegisterCode) -> [3]u8 {
  REX: u8 : 0x40 | 0x8
  OP_CODE : u8 : 0x01
  OPERANDS_REGISTER :: 0xC0
  return {REX, OP_CODE, (OPERANDS_REGISTER | (cast(u8)register_b) << 3) | cast(u8)register_a}
}

imul :: proc(register_a: RegisterCode, register_b :RegisterCode) -> [4]u8 {
  REX: u8 = 0x40 | 0x8
  OP_CODE: u8 = 0x0F
  OPERANDS_REGISTER :: 0xC0
  return {REX, OP_CODE, 0xAF, (OPERANDS_REGISTER | (cast(u8)register_a) << 3) | cast(u8)register_b}
}

xor :: proc(register_a: RegisterCode, register_b: RegisterCode) -> [3]u8 {
  REX: u8 = 0x40 | 0x8
  OP_CODE: u8 = 0x31
  OPERANDS_REGISTER :: 0xC0
  return {REX, OP_CODE, (OPERANDS_REGISTER | (cast(u8)register_a) << 3) | cast(u8)register_b}
}

idiv :: proc(register_a: RegisterCode) -> [3]u8{
  REX: u8 = 0x40 | 0x8
  OP_CODE: u8 = 0xF7
  OPERANDS_REGISTER :: 0xF8
  return { REX, OP_CODE, (OPERANDS_REGISTER | (cast(u8)register_a))}
}

print_hex_array :: proc(array: [$Size]u8){ 
  fmt.print("[")
  for i in 0..<(len(array) -1){
    fmt.printf("%2x, ", array[i])
  }
  fmt.printf("%2x", array[len(array) - 1])
  fmt.print("]\n")
}

ImportFunctionEntry :: struct {
  name: cstring,
  name_RVA: u64,
  rva: u32
}

ImportEntry :: struct {
  dll_name: cstring,
  functions: []ImportFunctionEntry,
  
  // filled in later
  descriptor_RVA: u32,
  descriptor: ^IMAGE_IMPORT_DESCRIPTOR
}

ImportCall :: struct {
  function_name: cstring,
  buffer_index: int
}


main :: proc(){
  output_buffer := new(OutputBuffer)
  dos_header :^IMAGE_DOS_HEADER = allocate(output_buffer, IMAGE_DOS_HEADER)

  dos_header.e_magic = "MZ"
  dos_header.e_lfanew = size_of(IMAGE_DOS_HEADER)

  IMAGE_FILE_RELOCS_STRIPPED :: 0x0001
  IMAGE_FILE_EXECUTABLE_IMAGE :: 0x0002
  IMAGE_FILE_LINE_NUMS_STRIPPED :: 0x0004
  IMAGE_FILE_LOCAL_SYMS_STRIPPED :: 0x0008
  IMAGE_FILE_LARGE_ADDRESS_AWARE :: 0x0020
  IMAGE_FILE_DEBUG_STRIPPED :: 0x0200

  
  NT_CHARACTERISTICS :u16 = IMAGE_FILE_RELOCS_STRIPPED | IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LOCAL_SYMS_STRIPPED | IMAGE_FILE_LINE_NUMS_STRIPPED | IMAGE_FILE_LARGE_ADDRESS_AWARE

  SECTION_COUNT :: 2
  
  nt_header: ^IMAGE_NT_HEADERS64 = allocate(output_buffer, IMAGE_NT_HEADERS64)
  nt_header.Signature = "PE"
  nt_header.FileHeader = {
    Machine = 0x8664,
    NumberOfSections = SECTION_COUNT,
    SizeOfOptionalHeader = size_of(IMAGE_OPTIONAL_HEADER64),
    Characteristics = NT_CHARACTERISTICS,
  }

  nt_header.OptionalHeader = {
    Magic = 0x20B,
    AddressOfEntryPoint = 4096,
    ImageBase = 0x400000,
    SectionAlignment = 4096,
    FileAlignment = 512,
    MajorSubsystemVersion = 4,
    SizeOfImage = 4096 * (SECTION_COUNT + 1),
    SizeOfHeaders = 512,
    Subsystem = 3,
    NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES
  }

  text_section: ^IMAGE_SECTION_HEADER = allocate(output_buffer, IMAGE_SECTION_HEADER)
  text_section.VirtualSize = 4
  text_section.VirtualAddress = 4096
  text_section.SizeOfRawData = 512
  text_section.PointerToRawData = 512
  text_section.Characteristics = 0x60000020
  write_string(&text_section.Name[0], ".text")


  import_section := allocate(output_buffer, IMAGE_SECTION_HEADER)
  import_section.VirtualSize = 4
  import_section.VirtualAddress = 4096 * 2
  import_section.PointerToRawData = 512 * 2
  import_section.SizeOfRawData = 512
  import_section.Characteristics = 0xC0000040
  write_string(&import_section.Name[0], ".idata")


  
  import_calls: [dynamic]ImportCall 
  
  output_buffer.index = 512
  alloc_u8_array(output_buffer, movq_immidiate(RegisterCode.RBX, 4))
  alloc_u8_array(output_buffer, movq_immidiate(RegisterCode.RAX, 3))
  alloc_u8_array(output_buffer, imul(RegisterCode.RAX, RegisterCode.RBX))
  alloc_u8_array(output_buffer, movq_immidiate(RegisterCode.RBX, 7))
  alloc_u8_array(output_buffer, xor(RegisterCode.RDX, RegisterCode.RDX))
  alloc_u8_array(output_buffer, idiv(RegisterCode.RBX))
  alloc_u8_array(output_buffer, movq(RegisterCode.RAX, RegisterCode.RDX))
  alloc_u8_array(output_buffer, movq(RegisterCode.RCX, RegisterCode.RAX))
  alloc_u8_array(output_buffer, call_relative_32(0x00))

  append(&import_calls, ImportCall{"ExitProcess", output_buffer.index})
  
  alloc_u8(output_buffer, ret())
  
  text_section.VirtualSize = cast(u32)output_buffer.index - 512
  

  // import section
  import_entries: []ImportEntry = {
    {
      dll_name = "KERNEL32.DLL",
      functions = {
        ImportFunctionEntry{name = "ExitProcess"}
      }
    }
  }

  output_buffer.index = cast(int)import_section.PointerToRawData

  IMPORT_RVA := import_section.VirtualAddress - cast(u32)output_buffer.index

  // Descriptors
  for &import_entry in import_entries {
    import_entry.descriptor_RVA = cast(u32)output_buffer.index + IMPORT_RVA
    import_entry.descriptor = allocate(output_buffer, IMAGE_IMPORT_DESCRIPTOR)
  }
  termination_entry := allocate(output_buffer, IMAGE_IMPORT_DESCRIPTOR)

  // Library name strings
  for &import_entry in import_entries {
    import_entry.descriptor.Name = cast(u32)output_buffer.index + IMPORT_RVA
    alloc_string(output_buffer, import_entry.dll_name)
  }

  // function name strings / 'Hints'
  for &import_entry in import_entries {
    for &function_call in import_entry.functions {
      function_call.name_RVA = u64(cast(u32)output_buffer.index + IMPORT_RVA)
      output_buffer.index += 2 // hint
      alloc_string(output_buffer, function_call.name)
    }
  }

  // import table
  for &import_entry in import_entries {
    import_entry.descriptor.FirstThunk = cast(u32)output_buffer.index + IMPORT_RVA
    for &function_call in import_entry.functions {
      function_call.rva = cast(u32)output_buffer.index + IMPORT_RVA
      for import_call in import_calls {
        if import_call.function_name != function_call.name {
          continue
        }

        virtual_address := (cast(u32)import_call.buffer_index - text_section.PointerToRawData) + text_section.VirtualAddress
        offset :u32 = function_call.rva - virtual_address
        mem.copy(&(output_buffer.buffer[import_call.buffer_index - size_of(u32)]), &offset, size_of(u32))
      }
      rva_entry := allocate(output_buffer, u64)
      rva_entry^ = function_call.name_RVA
    }
    output_buffer.index += size_of(u64) // termination entry
  }

  import_section.VirtualSize = cast(u32)(output_buffer.index - 512 * 2)
  
  nt_header.OptionalHeader.DataDirectory[1] = {
    VirtualAddress = import_section.VirtualAddress,
    Size = import_section.VirtualSize
  }

  output_buffer.index = 512 * 3
  
  file, err := os.open("thingy.exe", os.O_CREATE)
  os.write(file, output_buffer.buffer[0: output_buffer.index + 1])
  os.close(file)
}