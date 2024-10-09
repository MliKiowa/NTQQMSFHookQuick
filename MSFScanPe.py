from quickScanPe import *
import pefile

pe = pefile.PE("F:\\wrapper\\wrapper.28418.node")
pe_image_base = pe.OPTIONAL_HEADER.ImageBase
# 加载段区
section_rdata_range = get_section_range_rva(pe, '.rdata')
rdata_start, rdata_end = section_rdata_range

section_text_range = get_section_range_rva(pe, '.text')
text_start, text_end = section_text_range

section_data_range = get_section_range_rva(pe, '.data')
data_start, data_end = section_data_range

offset_msf_task_vtable_typeinfo_text = search_bytes(pe, data_start, data_end, b'.?AVTaskManager@internal@msf@@')
print('[debug] offset_msf_task_vtable_typeinfo_text: ',hex(offset_msf_task_vtable_typeinfo_text))

# 0x10是8+8的偏移 两个db属性 0x14是被引用元素偏移
offset_msf_task_vtable_typeinfo_rva = offset_msf_task_vtable_typeinfo_text - 0x10
offset_msf_task_vtable_typeinfo_xref = search_bytes(pe, rdata_start, rdata_end, offset_msf_task_vtable_typeinfo_rva.to_bytes(4, 'little'))
print('[debug] offset_msf_task_vtable_typeinfo_xref: ',hex(offset_msf_task_vtable_typeinfo_xref))

offset_msf_ng_text = search_bytes(pe, offset_msf_task_vtable_typeinfo_xref - 0x100, offset_msf_task_vtable_typeinfo_xref + 0x100, b'MSF-NG')
print('[debug] offset_msf_ng_text: ',hex(offset_msf_ng_text))