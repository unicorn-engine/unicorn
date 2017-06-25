// Zero memory for page directories and page tables
mov $0x1000,%edi
mov $0x1000,%ecx
xor %eax,%eax
rep stos %eax,(%edi)

// Load DWORD [0x4000] with 0xDEADBEEF to retrieve later
mov $0x4000,%edi
mov $0xBEEF,%eax
mov %eax, (%edi)

// Identify map the first 4MiB of memory
mov $0x400,%ecx
mov $0x2000,%edi
mov $3, %eax
loop:
stos %eax,(%edi)
add $0x1000,%eax
loop loop

// Map phyiscal address 0x4000 to cirtual address 0x7FF000
mov $0x3ffc,%edi
mov $0x4003,%eax
mov %eax, (%edi)

// Add page tables into page directory
mov $0x1000, %edi
mov $0x2003, %eax
mov %eax, (%edi)
mov $0x1004, %edi
mov $0x3003, %eax
mov %eax, (%edi)

// Load the page directory register
mov $0x1000, %eax
mov %eax, %cr3

// Enable paging
mov %cr0, %eax
or $0x80000000, %eax

// Clear EAX
mov %eax, %cr0

//Load using virtual memory address; EAX = 0xBEEF
xor %eax,%eax
mov $0x7FF000, %esi
mov (%esi), %eax
hlt
