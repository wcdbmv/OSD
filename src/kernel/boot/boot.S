#include "kernel/misc/gdt.h"

# Start the CPU: switch to 32-bit protected mode, jump into C.
# The BIOS loads this code from the first sector of the hard disk into
# memory at physical address 0x7c00 and starts executing in real mode
# with %cs=0 %ip=7c00.

.set PROT_MODE_CSEG, 0x8         # kernel code segment selector
.set PROT_MODE_DSEG, 0x10        # kernel data segment selector
.set CR0_PE_ON,      0x1         # protected mode enable flag

.globl boot_entry
boot_entry:

.code16
	// first of all: disable interrupts
	// Во-первых: запретим аппаратные прерывания
	//
	// CLI — сокращение от «Clear Interrupt-Enable Flag».
	// Она сбрасывает interrupt flag (IF) в регистре EFLAGS.
	// Когда этот флаг сброшен процессор игнорирует все прерывания (кроме NMI) от внешних устройств.
	cli

	// initialize segment registers
	// Инициализируем сегментные регистры
	xorw %ax, %ax  // AX = 0
	movw %ax, %ds  // DS = AX = 0
	movw %ax, %es  // ES = AX = 0
	movw %ax, %ss  // SS = AX = 0

	// При проектировании микропроцессора 80286 инженеры Intel допустили ошибку,
	// позволившую из реального режима обращаться к части памяти за пределами
	// младшего мегабайта — так называемой области верхней памяти (HMA).
	// Чтобы компенсировать эту ошибку и гарантировать совместимость со старыми программами,
	// в состав компьютера пришлось включить специальную схему, блокирующую 20-й разряд шины адреса
	// (или все старшие разряды, начиная с 20-го — это зависит от особенностей чипсета) — Gate A20 (вентиль или шлюз линии A20).
	// При использовании старых программ реального режима этот вентиль может быть закрыт,
	// что обеспечит присутствие на линии A20 логического нуля, а при работе новых программ,
	// поддерживающих защищённый режим, этот вентиль должен быть ОБЯЗАТЕЛЬНО открыт.

	// enable a20: wait until 8042 will be ready
	// Для открытия вентиля линии A20 используется контроллер клавиатуры 8042,
	// взаимодействие с которым осуществляется через порты 0x60 и 0x64.
	// Перед отправкой команды или данных контроллеру необходимо дождаться,
	// пока он не будет готов их принять.
	call wait_8042

	// tell 8042 that we want to write
	// Сообщаем контроллеру клавиатуры 8042, что мы хотим в него записать
	movb $0xd1, %al  // 0xD1 == Command Write, помещаем в регистр al
	outb %al, $0x64  // Посылаем регистр al в порт 0x64

	// wait until 8042 will be ready
	call wait_8042

	// Отправляет в порт данных 0x60 контроллера клавиатуры значение 0xdf,
	// что приводит к открытию вентиля линии A20

	movb $0xdf, %al
	outb %al, $0x60

	// wait until 8042 process our command
	call wait_8042
	jmp a20_enabled

	wait_8042:
		inb $0x64, %al   // Получаем статус порта 0x64
		testb $0x2, %al  // Занят?
		jnz wait_8042    // Да — ждём
		ret              // Нет — выходим

	a20_enabled:

	//--------------------------//
	// Вентиль линии А20 открыт //
	//--------------------------//

	// Store memory map into 0x7e00 (0x7c00 + 512)
	// Будем сохранять карту памяти по адресу 0x7E00
	movw $0x7de8, %di  // DI  = 0x7e00 - 24
	xorl %ebx, %ebx    // EBX = 0

	// before first call '%edx' must contain this magic value
	// Перед первым вызовом регистр EDX должен содержать магическое значение 0x534d4150
	movl $0x534d4150, %edx // EDX = 'SMAP'
	xorl %esi, %esi        // ESI = 0

	// Для определения доступных областей физической памяти
	// используется функция 0xE820 прерывания 0x15 BIOS.
	// Данную функцию необходимо вызывать в цикле до тех пор,
	// пока не будут возвращены все известные области памяти.
	detect_high_memory:
		movl $0xe820, %eax
		movl $24, %ecx
		addw $24, %di
		int $0x15  // Вызываем прерывание 0x15 BIOS

		// carry flag is clear in case all is ok
		// Если регистр CF == 0, то всё ок выходим из цикла
		jc memory_detected

		// magic value must be inside '%eax' in case success call
		// регистр EАX должен содержать магическое значение 0x534d4150 в случае если всё ок
		cmpl $0x534d4150, %eax // EAX == 'SMAP' ?
		jne memory_detected    // если нет — выходим из цикла

		// increase records count
		// Увеличиваем счётчик областей памяти
		incl %esi  // ++ESI

		// '%ebx' will be set to '0' at the end of list
		// В последней области памяти EBX == 0
		test %ebx, %ebx         // EBX == 0 ?
		jnz detect_high_memory  // если нет — продолжаем цикл


	memory_detected:

	//-----------------------------//
	// Доступная память определена //
	//-----------------------------//

	// enable protected mode (set first bit in cr0)
	// Переходим в защищённый режим установкой первого бита в регистре CR0
	// Мы не можем выполнять арифметические операции с регистрами CR
	// Но может читать и писать в них, поэтому воспользуемся другим регистром
	movl %cr0, %eax        // EAX = CR0
	orl  $CR0_PE_ON, %eax  // EAX |= 0x1
	movl %eax, %cr0        // CR0 = EAX

	//-----------------------------------------------//
	// Теперь процессор работает в защищённом режиме //
	//-----------------------------------------------//

	// Загружаем базовый адрес глобальной таблицы дескрипторов
	lgdt gdtdesc  // GDTR = &gdtdesc
	ljmp $PROT_MODE_CSEG, $complete_flush  // long jump в функцию complete_flush

.code32

complete_flush:
	// set up protected mode segment registers
	// Устанавливаем сегментные регистры защищённого режима
	movw $PROT_MODE_DSEG, %ax  // AX = 0x10
	movw %ax, %ds  // DS = AX = 0x10
	movw %ax, %es  // ES = AX = 0x10
	movw %ax, %ss  // SS = AX = 0x10
	movw %ax, %fs  // FS = AX = 0x10
	movw %ax, %gs  // GS = AX = 0x10

	// setup stack, and start our C part of the bootloader
	// Устанавливаем стек, и начинаем нашу Си часть загрузчика
	movl $boot_entry, %esp  // ESP = &boot_entry

	// Ugly hack, to store records count. It works in case bootloader
	// size lower than 508
	// Предварительно сохранив количество областей памяти
	movl $0x7e00, %edi
	movl %esi, -4(%edi)

	// Переходим ко второму загрузчику
	call bootmain

	// we should never reach this code
	spin:
		jmp spin

// force 4 byte alignment
.p2align 2

// Для перехода в защищённый режим системному ПО необходимо объявить GDT,
// содержащую минимум 3 дескриптора сегмента:
// — нулевой,
// — дескриптор сегмента кода,
// — дескриптор сегмента данных.
gdt:
	SEG(0x0, 0x0, 0x0) // null seg
	SEG(UST_X|USF_D|USF_P|USF_S|USF_G|UST_R, 0x0, 0xfffff) // code seg
	SEG(USF_D|USF_P|USF_S|USF_G|UST_W, 0x0, 0xfffff) // data seg

gdtdesc:
	.word (. - gdt - 1)
	.long gdt
