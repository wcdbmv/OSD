#include "stdlib/string.h"
#include "stdlib/assert.h"

#include "kernel/lib/disk/ata.h"
#include "kernel/lib/memory/map.h"
#include "kernel/lib/memory/layout.h"
#include "kernel/lib/console/terminal.h"

#include "kernel/asm.h"
#include "kernel/cpu.h"
#include "kernel/misc/gdt.h"
#include "kernel/misc/elf.h"
#include "kernel/misc/util.h"
#include "kernel/loader/config.h"

struct bios_mmap_entry
{
    uint64_t base_addr;
    uint64_t addr_len;
#define BIOS_MEMORY_AVAILABLE              1
#define BIOS_MEMORY_RESERVED               2
#define BIOS_MEMORY_ACPI_RECLAIMABLE       3
#define BIOS_MEMORY_NVS                    4
#define BIOS_MEMORY_BADRAM                 5
    uint32_t type;
    uint32_t acpi_attrs;
};

// Describe gdtr for long mode
struct gdtr
{
    uint16_t limit;
    uint32_t base;
    uint32_t zero;
} __attribute__((packed));

// Some help from linker script
extern uint8_t boot_stack[], end[];

// Now (in loader) virtual address is equal to physical one
static uint64_t max_physical_address;
static uint8_t *free_memory = end;

static struct page *pages;
//static uint64_t pages_cnt;

pml4e_t *pml4;

struct descriptor *gdt;
struct gdtr gdtr;

void loader_panic(const char *fmt, ...);
panic_t panic = loader_panic;

// Loader uses this struct to pass some
// useful information to kernel
struct kernel_config *config;

void *loader_alloc(uint64_t size, uint32_t align);
uint64_t loader_detect_memory(struct bios_mmap_entry *mm, uint32_t cnt);
int loader_init_memory(struct bios_mmap_entry *mm, uint32_t cnt, uint64_t pages_cnt);
int loader_map_section(uint64_t va, uintptr_t pa, uint64_t len, bool hard);

bool page_is_available(uint64_t paddr, struct bios_mmap_entry *mm, uint32_t cnt);

struct descriptor *loader_init_gdt(void);

int loader_read_kernel(uint64_t *kernel_entry_point);
void loader_enter_long_mode(uint64_t kernel_entry_point);

// Why this address? See 'boot/boot.S'
#define BOOT_MMAP_ADDR 0x7e00

// До перехода на выделение памяти страницами, системе нужно выделить память
// для ряда управляющих структур и каталога страниц. Отметим сразу, что после
// этого ядро практически перестает выделять память под собственные нужды:
// дальнейшее выделение физической памяти происходит только для запуска
// и работы программ пользователя, включая создание новых таблиц страниц.
void loader_main(void)
{
    terminal_init();

#if LAB >= 2
    // Next two parameters are prepared by the first loader
    // Следующие два параметра подготовлены первым загрузчиком:
    // — начальный адрес доступных областей памяти
    // — количество этих самых областей

    // Сохраним указатель на массив дескрипторов областей памяти
    // и на количество элементов в нём
    struct bios_mmap_entry *mm = (struct bios_mmap_entry *)BOOT_MMAP_ADDR;
    // 2. Сохраним количество элементов в массиве
    uint32_t cnt = *((uint32_t *)BOOT_MMAP_ADDR - 1);

    // Загрузим ядро с диска
    uint64_t kernel_entry_point;
    if (loader_read_kernel(&kernel_entry_point) != 0)
        goto something_bad;

    // После выполнения всех предыдущих этапов система может наконец перейти
    // на плоскую модель сегментов и начать использовать страничное преобразование адресов.
    // Переход будет осуществляться функцией loader_init_memory и loader_enter_long_mode

    // Определим количество доступной памяти и инициализируем её
    uint64_t pages_cnt = loader_detect_memory(mm, cnt);
    if (loader_init_memory(mm, cnt, pages_cnt) != 0)
        goto something_bad;

    loader_enter_long_mode(kernel_entry_point);

something_bad:
#endif
    terminal_printf("Stop loading, hang\n");

    while (1)
    {
        /*do nothing*/
    }
}

// LAB2
// - use 'free_memory' as a pointer to memory, witch may be allocated
// - round memory_chunk up to be aligned properly use ROUND_UP
// - save current value of memory_chunk as allocated chunk, don't forget cast to (void*)
// - increase free_memory to record allocation
// - return allocated memory_chunk
void *loader_alloc(uint64_t size, uint32_t align)
{
    //------------------//
    // Выделение памяти //
    // -----------------//

    uint8_t *memory_chunk;
    // Начало доступной памяти выравниваем по align, это и будет адрес начала выделенной памяти
    memory_chunk = (void *)ROUND_UP((uint32_t)free_memory, align);
    // А саму доступную память уменьшаем на размер выделенной памяти
    free_memory = memory_chunk + size;

    return memory_chunk;
}

// LAB2 Instruction:
// - read elf header (see boot/main.c, but use 'elf64_*' here) (for error use terminal_printf)
// - allocate
// - check magic ELF_MAGIC
// - store 'kernel_entry_point'
// - read other segments:
// -- shift 'free_memory' if needed to avoid overlaps in future
// -- load kernel into physical addresses instead of virtual (drop >4Gb part of virtual address)
// -- use loader_alloc
#define KERNEL_BASE_DISK_SECTOR 2048 // 1Mb
int loader_read_kernel(uint64_t *kernel_entry_point)
{
    //-----------------------//
    // Загрузка ядра с диска //
    //-----------------------//

    // Для загрузки ядра системы необходимо определить точку входа и прочитать заголовки elf файла

    // Память для elf_header выделяется с помощью функции loader_alloc
    struct elf64_header *elf_header = loader_alloc(sizeof(*elf_header), PAGE_SIZE);

    // Читаем заголовок KERNEL_BASE_DISK_SECTOR из elf файла
    if (disk_io_read_segment((uint32_t)elf_header, ATA_SECTOR_SIZE, KERNEL_BASE_DISK_SECTOR) != 0) {
        terminal_printf("Can't read elf header\n");
        return -1;
    }

    // Проверяем магическое число в заголовке
    if (elf_header->e_magic != ELF_MAGIC) {
        terminal_printf("Invalid elf format, magic mismatch (%u)", elf_header->e_magic);
        return -1;
    }

    // Читаем хедеры секторов
    for (struct elf64_program_header *ph = ELF64_PHEADER_FIRST(elf_header); ph < ELF64_PHEADER_LAST(elf_header); ph++) {
        // Правильно отображаем виртуальные адреса в физические. Для этого старшие байты
        // виртуального адреса надо отбросить, чтобы поддерживался следующий мэппинг памяти
        // [KERNBASE; KERNBASE+FREEMEM) -> [0; FREEMEM)
        ph->p_va &= 0xFFFFFFFFull;

        uint32_t lba = (ph->p_offset / ATA_SECTOR_SIZE) + KERNEL_BASE_DISK_SECTOR;
        if (disk_io_read_segment(ph->p_va, ph->p_memsz, lba) != 0) {
            terminal_printf("Can't read segment `%u'", lba);
            return -1;
        }

        if (PADDR(free_memory) < PADDR(ph->p_va + ph->p_memsz))
            // Сдвигаем `free_memory', чтобы `loader_alloc()' мог
            // возвращать доступную память после завершения этой функции
            free_memory = (uint8_t *)(uintptr_t)(ph->p_va + ph->p_memsz);
    }
    // Не забываем обновить значение kernel_entry_point
    *kernel_entry_point = elf_header->e_entry;

    return 0;
}

// LAB2 Instruction:
// - check all memory entry points for type 'free'. Constant MEMORY_TYPE_FREE here is to help you
// - detect 'max_physical_address'
// - count total 'pages_cnt', using 'max_physical_address' and 'PAGE_SIZE'
// - use ROUND_DOWN macros
#define MEMORY_TYPE_FREE 1
uint64_t loader_detect_memory(struct bios_mmap_entry *memory_map, uint32_t cnt)
{
    //-------------------//
    // Подготовка памяти //
    // ------------------//

    max_physical_address = 0;
    uint64_t pages_cnt = 0;

    // Для каждой области памяти
    for (uint32_t i = 0; i < cnt; ++i) {
        // Проверяем тип этой области памяти (должна быть доступной)
        if (memory_map[i].type != MEMORY_TYPE_FREE)
            continue;
        // Проверяем, что сумма базового адреса и длины области не больше max_physical_address
        if (memory_map[i].base_addr + memory_map[i].addr_len < max_physical_address)
            continue;

        // В переменной max_physical_address аккумулируется значение по максимально доступной памяти
        max_physical_address = memory_map[i].base_addr + memory_map[i].addr_len;
    }

    // Количество страниц можно узнать, поделив max_physical_address на размер одной страницы
    pages_cnt = ROUND_DOWN(max_physical_address, PAGE_SIZE) / PAGE_SIZE;
    terminal_printf("Available memory: %u Kb (%u pages)\n",
                    (uint32_t)(max_physical_address / 1024), (uint32_t)pages_cnt);

    return pages_cnt;
}

int loader_init_memory(struct bios_mmap_entry *mm, uint32_t cnt, uint64_t pages_cnt)
{
    // Функция должна подготовить управляющие структуры и подготовить список страниц.
    // Сначала выделяется память и заполняется значениям управляющие структуры:
    // - state
    // - config
    // - pml4

    static struct mmap_state state;

    config = loader_alloc(sizeof(*config), PAGE_SIZE);
    memset(config, 0, sizeof(*config));

    // Затем, загружает новую таблицу GDT. Теперь нужно иметь 5 дескрипторов:
    // нулевой, два дескриптора для ядра и два дескриптора для пользователя.

    gdt = loader_init_gdt();

    // Allocate and init PML4
    pml4 = loader_alloc(PAGE_SIZE, PAGE_SIZE);
    memset(pml4, 0, PAGE_SIZE);

    // Allocate and initialize physical pages array
    pages = loader_alloc(SIZEOF_PAGE64 * pages_cnt, PAGE_SIZE);
    memset(pages, 0, SIZEOF_PAGE64 * pages_cnt);

    // Обновляем поля в структуре config и в структуре state

    // Initialize config
    config->pages_cnt = pages_cnt;
    config->pages.ptr = pages;
    config->pml4.ptr = pml4;
    config->gdt.ptr = gdt;

    // Initialize 'mmap_state'
    state.free = (struct mmap_free_pages){NULL};
    state.pages_cnt = pages_cnt;
    state.pages = pages;
    mmap_init(&state);

    // Fill in free pages list, skip ones used by kernel or hardware
    for (uint32_t i = 0; i < pages_cnt; i++)
    {
        uint64_t page_addr = (uint64_t)i * PAGE_SIZE;

        if (page_is_available(page_addr, mm, cnt) == false)
        {
            pages[i].ref = 1;
            continue;
        }

        // Insert head is important, it guarantees that high physical
        // addresses will be used before low ones.
        LIST_INSERT_HEAD(&state.free, &pages[i], link);
    }

    // Map kernel stack
    if (loader_map_section(KERNEL_STACK_TOP - KERNEL_STACK_SIZE, (uintptr_t)boot_stack, KERNEL_STACK_SIZE, true) != 0)
        return -1;

    // Pass some information to kernel
    if (loader_map_section(KERNEL_INFO, (uintptr_t)config, PAGE_SIZE, true) != 0)
        return -1;

    // Make APIC registers available for the kernel
    if (loader_map_section(APIC_BASE, APIC_BASE_PA, PAGE_SIZE, true) != 0)
        return -1;

    // Make IO APIC registers available for the kernel
    if (loader_map_section(IOAPIC_BASE, IOAPIC_BASE_PA, PAGE_SIZE, true) != 0)
        return -1;

    // Map loader to make all addresses valid after paging enable
    // (before jump to kernel entry point). We must map all until
    // 'free_memory' not just 'end', because 'pml4' located after 'end'
    if (loader_map_section(0x0, 0x0, (uintptr_t)free_memory, true) != 0)
        return -1;

    // Make continuous mapping [KERNEL_BASE, KERNEL_BASE + FREE_MEM) -> [0, FREE_MEM)
    // Without this mapping we can't compute virtual address from physical one
    if (loader_map_section(KERNEL_BASE, 0x0, ROUND_DOWN(max_physical_address, PAGE_SIZE), false) != 0)
        return -1;

    return 0;
}

#define NGDT_ENTRIES 5

struct descriptor *loader_init_gdt(void)
{
    uint16_t system_segments_size = sizeof(struct descriptor64) * CPU_MAX_CNT;
    uint16_t user_segments_size = sizeof(struct descriptor) * NGDT_ENTRIES;
    uint16_t gdt_size = user_segments_size + system_segments_size;
    struct descriptor *gdt = loader_alloc(gdt_size, 16);

    gdtr.base = (uintptr_t)gdt;
    gdtr.limit = gdt_size - 1;
    gdtr.zero = 0;

    // according to AMD64 documentation, in 64-bit mode all most
    // fields, like 'UST_W' or 'DPL' for data segment are ignored,
    // but this is not true inside QEMU and Bochs

    // Null descriptor - just in case
    gdt[0] = SEGMENT_DESC(0, 0x0, 0x0);

    // Kernel text
    gdt[GD_KT >> 3] = SEGMENT_DESC(USF_L | USF_P | DPL_S | USF_S | UST_X, 0x0, 0x0);

    // Kernel data
    gdt[GD_KD >> 3] = SEGMENT_DESC(USF_P | USF_S | DPL_S | UST_W, 0x0, 0x0);

    // User text
    gdt[GD_UT >> 3] = SEGMENT_DESC(USF_L | USF_P | DPL_U | USF_S | UST_X, 0x0, 0x0);

    // User data
    gdt[GD_UD >> 3] = SEGMENT_DESC(USF_P | USF_S | DPL_U | UST_W, 0x0, 0x0);

    return gdt;
}

bool page_is_available(uint64_t paddr, struct bios_mmap_entry *mm, uint32_t cnt)
{
    if (paddr == 0)
        // The first page contain some useful bios data structures.
        // Reserve it just in case.
        return false;

    if (paddr >= APIC_BASE_PA && paddr < APIC_BASE_PA + PAGE_SIZE)
        // APIC registers mapped here
        return false;

    if (paddr >= IOAPIC_BASE_PA && paddr < IOAPIC_BASE_PA + PAGE_SIZE)
        // IO APIC registers mapped here
        return false;

    if (paddr >= (uint64_t)(uintptr_t)end &&
        paddr < (uint64_t)(uintptr_t)free_memory)
        // This address range contains kernel
        // and data allocated with 'loader_alloc()'
        return false;

    bool page_is_available = true;
    for (uint32_t i = 0; i < cnt; i++)
    {
        if (mm->base_addr > paddr)
            continue;
        if (paddr + PAGE_SIZE >= mm->base_addr + mm->addr_len)
            continue;

        // Memory areas from bios may be overlapped, so we must check
        // all areas, before we can consider that page is free.
        page_is_available &= mm->type == MEMORY_TYPE_FREE;
    }

    return page_is_available;
}

int loader_map_section(uint64_t va, uintptr_t pa, uint64_t len, bool hard)
{
    uint64_t va_aligned = ROUND_DOWN(va, PAGE_SIZE);
    uint64_t len_aligned = ROUND_UP(len, PAGE_SIZE);

    for (uint64_t i = 0; i < len_aligned; i += PAGE_SIZE)
    {
        pte_t *pte = mmap_lookup(pml4, va_aligned + i, true);
        struct page *page;

        if (pte == NULL)
            return -1;
        assert((*pte & PTE_P) == 0);

        *pte = PTE_ADDR(pa + i) | PTE_P | PTE_W;

        page = pa2page(PTE_ADDR(pa + i));
        if (page->ref != 0)
            // Page already has been removed from free list
            continue;

        page_incref(page);
        if (hard == true)
        {
            // We must remove some pages from free list, to avoid
            // overriding them later
            LIST_REMOVE(page, link);
            page->link.le_next = NULL;
            page->link.le_prev = NULL;
        }
    }

    return 0;
}

void loader_enter_long_mode(uint64_t kernel_entry_point)
{
    // Reload gdt
    asm volatile("lgdt gdtr");

    // Enable PAE
    asm volatile(
        "movl %cr4, %eax\n\t"
        "btsl $5, %eax\n\t"
        "movl %eax, %cr4\n");

    // Setup CR3
    asm volatile("movl %%eax, %%cr3" ::"a"(PADDR(pml4)));

    // Enable long mode (set EFER.LME=1)
    asm volatile(
        "movl $0xc0000080, %ecx\n\t" // EFER MSR number
        "rdmsr\n\t"					 // Read EFER
        "btsl $8, %eax\n\t"			 // Set LME=1
        "wrmsr\n"					 // Write EFER
    );

    // Enable paging to activate long mode
    asm volatile(
        "movl %cr0, %eax\n\t"
        "btsl $31, %eax\n\t"
        "movl %eax, %cr0\n");

    extern void entry_long_mode_asm(uint64_t kernel_entry);
    entry_long_mode_asm(kernel_entry_point); // does not return
}

void loader_panic(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    terminal_vprintf(fmt, ap);
    va_end(ap);

    while (1)
    {
        /*do nothing*/;
    }
}
