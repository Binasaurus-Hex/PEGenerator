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

  e_cblp, 
  e_cp, 
  e_crlc, 
  e_cparhdr, 
  e_minalloc, 
  e_maxalloc, 
  e_ss, 
  e_sp, 
  e_csum, 
  e_ip, 
  e_cs, 
  e_lfarlc, 
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
  mem.copy(location, cast(^u8)s, len(s))
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


push :: proc(register: RegisterCode) -> u8 {
  return 0x50 | cast(u8)register
}

pop :: proc(register: RegisterCode) -> u8 {
  return 0x58 | cast(u8)register
}

ret :: proc() -> u8 {
  return 0xC3
}

movq :: proc(register_a: RegisterCode, register_b: RegisterCode) -> [3]u8 {
  REX :u8 : 0x40 | 0x8
  OP_CODE: u8 : 0x89
  OPERANDS_REGISTER :: 0xC0
  return {REX, OP_CODE, (OPERANDS_REGISTER | (cast(u8)register_a) << 3) | cast(u8)register_b}
}

movq_immidiate :: proc(register_a: RegisterCode, immediate_value: u64) -> [3]u8 {
  
}

add_q :: proc(register_a: RegisterCode, register_b: RegisterCode) -> [3]u8 {
  REX: u8 : 0x40 | 0x8
  OP_CODE : u8 : 0x01
  OPERANDS_REGISTER :: 0xC0
  return {REX, OP_CODE, (OPERANDS_REGISTER | (cast(u8)register_a) << 3) | cast(u8)register_b}
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
  IMAGE_FILE_32BIT_MACHINE :: 0x0100
  IMAGE_FILE_DEBUG_STRIPPED :: 0x0200

  
  NT_CHARACTERISTICS :u16 = IMAGE_FILE_RELOCS_STRIPPED | IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LOCAL_SYMS_STRIPPED | IMAGE_FILE_LINE_NUMS_STRIPPED
  
  when MODE_32 {
    HEADER :: IMAGE_NT_HEADERS
    OPTIONAL :: IMAGE_OPTIONAL_HEADER
    CODE :: 0x10B
    NT_CHARACTERISTICS |= IMAGE_FILE_32BIT_MACHINE
  }
  else {
    HEADER :: IMAGE_NT_HEADERS64
    OPTIONAL :: IMAGE_OPTIONAL_HEADER64
    CODE :: 0x20B
    NT_CHARACTERISTICS |= IMAGE_FILE_LARGE_ADDRESS_AWARE
  }

  SECTION_COUNT :: 1
  
  nt_header: ^HEADER = allocate(output_buffer, HEADER)
  nt_header.Signature = "PE"
  nt_header.FileHeader = {
    Machine = 0x14C,
    NumberOfSections = SECTION_COUNT,
    SizeOfOptionalHeader = size_of(OPTIONAL),
    Characteristics = NT_CHARACTERISTICS,
  }

  if !MODE_32 {
    nt_header.FileHeader.Machine = 0x8664
  }

  nt_header.OptionalHeader = {
    Magic = CODE,
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


  import_section := allocate(output_buffer, IMAGE_SECTION_HEADER)
  import_section.VirtualAddress = 4096 * 2
  import_section.PointerToRawData = 512 * 2
  import_section.SizeOfRawData = 512
  import_section.Characteristics = 0xC0000040

  write_string(&text_section.Name[0], ".text")

  output_buffer.index = 512

  code: ^[512]u8 = allocate(output_buffer, [512]u8)
  when MODE_32 {
    code[0] = 0x6A
    code[1] = 100
    code[2] = 0x58
    code[3] = 0xC3
  }
  else {

    testing_import := false

    if !testing_import {

      code_bytes: []u8 = {0x48, 0xC7, 0xC0, 0x28, 0x00, 0x00, 0x00, 0xC3}
      mem.copy(&code[0], &code_bytes[0], len(code_bytes))
      size := cast(u32)len(code_bytes)
      text_section.VirtualSize, text_section.SizeOfRawData = size, size

      fmt.printfln("push instruction : %2x", push(RegisterCode.RBP))
      fmt.printfln("movq instruction : %2x", movq(RegisterCode.RSP, RegisterCode.RBP))
    }
    else {
      code_bytes: []u8 = {0x48, 0x83, 0xEC, 0xB9, 0x06, 0x04, 0x00, 0x00, 0xFF, 0x15, 0x2D, 0x20, 0x00, 0x00}
      mem.copy(&code[0], &code_bytes[0], len(code_bytes))
      text_section.VirtualSize = cast(u32)len(code_bytes)
      text_section.SizeOfRawData = cast(u32)len(code_bytes)
    }

  }
  
  IMPORT_RVA := import_section.VirtualAddress - cast(u32)output_buffer.index 
  // import section
  kernel32_name: cstring = "KERNEL32.DLL"
  kernel_name_RVA :u32 = cast(u32)output_buffer.index + IMPORT_RVA
  write_string(&output_buffer.buffer[output_buffer.index], kernel32_name)
  output_buffer.index += len(kernel32_name)

  exit_process_RVA :u64 = u64(cast(u32)output_buffer.index + IMPORT_RVA)
  output_buffer.index += 2 // hint
  message_box_a_name: cstring = "ExitProcess"
  write_string(&output_buffer.buffer[output_buffer.index], message_box_a_name)
  output_buffer.index += len(message_box_a_name)


  // kernel table
  kernel_table_RVA := cast(u32)output_buffer.index + IMPORT_RVA
  mem.copy(&output_buffer.buffer[output_buffer.index], &exit_process_RVA, size_of(exit_process_RVA))
  output_buffer.index += size_of(exit_process_RVA)
  output_buffer.index += 8 // zero termination

  kernel32_descriptor := allocate(output_buffer, IMAGE_IMPORT_DESCRIPTOR)
  kernel32_descriptor.Name = kernel_name_RVA
  kernel32_descriptor.FirstThunk = kernel_table_RVA

  import_section.VirtualSize = cast(u32)(output_buffer.index - 512 * 2)

  output_buffer.index = 512 * 3
  
  file, err := os.open("thingy.exe", os.O_CREATE)
  os.write(file, output_buffer.buffer[0: output_buffer.index + 1])
  os.close(file)
}