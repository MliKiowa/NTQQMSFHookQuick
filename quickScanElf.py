from elftools.elf.elffile import ELFFile
from capstone import *

def find_symbol_in_got_plt(elf,symbol_name):
    symtab = elf.get_section_by_name('.dynsym')
    if not symtab:
       print("符号表不存在")
       return None
    rel_section = elf.get_section_by_name('.rela.plt')
    if rel_section:
        for rel in rel_section.iter_relocations():
            r_info = rel.entry['r_info']
            rel_symbol_index = r_info >> 32
            rel_symbol = symtab.get_symbol(rel_symbol_index)
            if rel_symbol.name == symbol_name:
                symbol_address = rel['r_offset']
                return symbol_address
    print(f"符号 {symbol_name} 不在段中")
    return None


def get_text_section(elf):
    for section in elf.iter_sections():
        if section.name == '.text':
            return section
    return None

def get_function_ranges(elf):
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.skipdata = True
    text_section = get_text_section(elf)
    code = text_section.data()
    start_addr = text_section['sh_addr']
    end_addr = start_addr + text_section['sh_size']

    functions = []
    current_func = None

    insn_list = list(md.disasm(code, start_addr))

    i = 0
    while i < len(insn_list):
        insn = insn_list[i]
        if insn.mnemonic == 'push' and insn.op_str == 'rbp':
            j = i - 1
            while j >= 0 and insn_list[j].mnemonic == 'push':
                j -= 1
            if current_func:
                functions.append(current_func)
            current_func = {'start': insn_list[j + 1].address, 'end': None}
        elif insn.mnemonic == 'mov' and insn.op_str == 'rbp, rsp':
            if current_func:
                functions.append(current_func)
            current_func = {'start': insn.address, 'end': None}
        if current_func:
            current_func['end'] = insn.address + insn.size
        i += 1

    if current_func:
        functions.append(current_func)

    return functions

def find_function_containing_address(functions, address):
    for func in functions:
        if func['start'] <= address < func['end']:
            return func
    return None

def get_section_range_rva(elf, section_name):
    for section in elf.iter_sections():
        if section.name == section_name:
            return section['sh_addr'], section['sh_addr'] + section['sh_size']
    return None, None

def search_bytes(elf, start, end, bytes):
    for section in elf.iter_sections():
        if section['sh_addr'] <= start < section['sh_addr'] + section['sh_size']:
            data = section.data()
            offset = start - section['sh_addr']
            for i in range(offset, offset + (end - start + 1)):
                if data[i:i + len(bytes)] == bytes:
                    return section['sh_addr'] + i
    return None

def search_bytes_all(elf, start, end, bytes):
    rva_list = []
    for section in elf.iter_sections():
        if section['sh_addr'] <= start < section['sh_addr'] + section['sh_size']:
            data = section.data()
            offset = start - section['sh_addr']
            for i in range(offset, offset + (end - start + 1)):
                if data[i:i + len(bytes)] == bytes:
                    rva_list.append(section['sh_addr'] + i)
    return rva_list

def search_data_pattern_all(elf, pattern, start, end):
    rva_list = []
    pattern = pattern.replace(' ', '').replace('0x', '').lower()
    for section in elf.iter_sections():
        if section['sh_addr'] <= start < section['sh_addr'] + section['sh_size']:
            data = section.data()
            offset = start - section['sh_addr']
            for i in range(offset, offset + (end - start + 1)):
                hex_data = ''.join(['%02x' % x for x in data[i:i + len(pattern) // 2]])
                for j in range(0, len(pattern)):
                    if pattern[j] != '?' and pattern[j] != hex_data[j]:
                        break
                else:
                    rva_list.append(section['sh_addr'] + i)
    return rva_list

def search_data_pattern(elf, pattern, start, end):
    pattern = pattern.replace(' ', '').replace('0x', '').lower()
    for section in elf.iter_sections():
        if section['sh_addr'] <= start < section['sh_addr'] + section['sh_size']:
            data = section.data()
            offset = start - section['sh_addr']
            for i in range(offset, offset + (end - start + 1)):
                hex_data = ''.join(['%02x' % x for x in data[i:i + len(pattern) // 2]])
                for j in range(0, len(pattern)):
                    if pattern[j] != '?' and pattern[j] != hex_data[j]:
                        break
                else:
                    return section['sh_addr'] + i
    return None

def search_data_maybe_xref(elf, string_rva, start, end):
    for section in elf.iter_sections():
        if section['sh_addr'] <= start < section['sh_addr'] + section['sh_size']:
            data = section.data()
            offset = start - section['sh_addr']
            for i in range(offset, offset + (end - start + 1)):
                if int.from_bytes(data[i:i + 4], 'little', signed=True) + section['sh_addr'] + i + 4 == string_rva:
                    return section['sh_addr'] + i
    return None

def search_data_maybe_xref_pattern(elf, pattern, string_rva, start, end):
    pattern = pattern.replace(' ', '').replace('0x', '').lower()
    for section in elf.iter_sections():
        if section['sh_addr'] <= start < section['sh_addr'] + section['sh_size']:
            data = section.data()
            offset = start - section['sh_addr']
            for i in range(offset, offset + (end - start + 1)):
                pattern_len = len(pattern) // 2
                hex_data = ''.join(['%02x' % x for x in data[i:i + pattern_len]]) # hex + 4字节偏移
                for j in range(0, len(pattern)):
                    if pattern[j] != '?' and pattern[j] != hex_data[j]:
                        break
                else:
                    if int.from_bytes(data[i+pattern_len:i + 4+pattern_len], 'little', signed=True) + section['sh_addr'] + i + 4 + pattern_len == string_rva:
                        return section['sh_addr'] + i + pattern_len
    return None

def search_data_maybe_xref_all(elf, string_rva, start, end):
    rva_list = []
    for section in elf.iter_sections():
        if section['sh_addr'] <= start < section['sh_addr'] + section['sh_size']:
            data = section.data()
            offset = start - section['sh_addr']
            for i in range(offset, offset + (end - start + 1)):
                if int.from_bytes(data[i:i + 4], 'little', signed=True) + section['sh_addr'] + i + 4 == string_rva:
                    rva_list.append(section['sh_addr'] + i)
    return rva_list

def get_all_call_range(elf, start, end):
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.skipdata = True
    code = b''
    for section in elf.iter_sections():
        if section['sh_addr'] <= start < section['sh_addr'] + section['sh_size']:
            offset = start - section['sh_addr']
            code = section.data()[offset:offset + (end - start)]
            break
    insn_list = list(md.disasm(code, start))
    call_list = []
    for insn in insn_list:
        if insn.mnemonic == 'call':
            call_target = int(insn.op_str, 16)
            call_list.append(call_target)
    return call_list