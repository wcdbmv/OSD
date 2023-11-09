#include "stdlib/assert.h"
#include "stdlib/string.h"

#include "kernel/asm.h"
#include "kernel/thread.h"

#include "kernel/misc/gdt.h"
#include "kernel/misc/util.h"

#include "kernel/lib/memory/map.h"
#include "kernel/lib/memory/layout.h"
#include "kernel/lib/console/terminal.h"

#if LAB >= 7
// arguments are passed via 'rdi', 'rsi', 'rdx' (see IA-32 calling conventions)
static void thread_foo(struct task *thread, thread_func_t foo, void *arg)
{
	assert(thread != NULL && foo != NULL);

	foo(arg);

	task_destroy(thread);

	// call schedule
	asm volatile ("int3");
}
#endif

// LAB7 Instruction:
// 1. create new task
// 2. allocate and map stack (hint: you can use 'USER_STACK_TOP')
// 3. pass function arguments via 'rdi, rsi, rdx' (store 'data' on new stack)
// 4. setup segment registers
// 5. setup instruction pointer and stack pointer
// Don't override stack (don't use large 'data')
struct task *thread_create(const char *name, thread_func_t foo, const uint8_t *data, size_t size)
{
	// По действиям функция почти аналогична функции task_create

	struct page *stack;
	struct task *task;

	// Необходимо создать новый поток
	if ((task = task_new(name)) == NULL) {
		goto cleanup;
	}

	// Выделим память для стека (хватит одной страницы)
	if ((stack = page_alloc()) == NULL) {
		terminal_printf("Can't create thread `%s': no memory for stack\n", name);
		goto cleanup;
	}
	// Вставим выделенную страницу с правильными битами разрешения в pml4
	if (page_insert(task->pml4, stack, USER_STACK_TOP-PAGE_SIZE, PTE_U | PTE_W) != 0) {
		terminal_printf("Can't create thread `%s': page_insert(stack) failed\n", name);
		goto cleanup;
	}

	// Теперь надо подготовить стек и аргументы
	uint8_t *stack_top = (uint8_t *)USER_STACK_TOP;
	{
		// Перезагрузить регистр cr3, новым значением из потока,
		// не забыть сохранить предыдущее значение cr3
		uintptr_t cr3 = rcr3();
		lcr3(PADDR(task->pml4));

		// Теперь можно заняться загрузкой данных (data)

		// Прежде всего проверить значение на NULL
		if (data != NULL) {
			// После этого указатель на данные должен быть выровнен
			void *data_ptr = (void *)ROUND_DOWN((uintptr_t)(stack_top-size), sizeof(void *));

			// После этого можно скопировать данные функцией memcpy
			memcpy(data_ptr, data, size);
			// Сохранить указатель в data, (stack_top) из (data_ptr)
			data = stack_top = data_ptr;
		}

		// Адрес возврата будет высчитывать как разница между (stack_top) и размером (uintptr_t)
		stack_top -= sizeof(uintptr_t);
		// В этот адрес необходимо записать значение 0. Необходимо помнить только, что (stack_top) надо привести к типу (uintptr_t)
		*(uintptr_t *)stack_top = (uintptr_t)0;

		// После этого можно воспользоваться кодом из листинга 9.2. Передача параметров в функцию thread_foo
		task->context.gprs.rdi = (uintptr_t)task;
		task->context.gprs.rsi = (uintptr_t)foo;
		task->context.gprs.rdx = (uintptr_t)data;

		// В конце концов надо восстановить значение cr3
		lcr3(cr3);
	}

	// После этого надо загрузить сегментные регистры cs, ds, es, ss и регистры rip
	task->context.cs = GD_KT;
	task->context.ds = GD_KD;
	task->context.es = GD_KD;
	task->context.ss = GD_KD;

	task->context.rip = (uintptr_t)thread_foo;
	task->context.rsp = (uintptr_t)stack_top;

	// После всех действий этого можно возвратить созданный поток.
	return task;

cleanup:
	if (task != NULL) {
		task_destroy(task);
	}

	return NULL;
}

// LAB7 Instruction:
// change 'state', so scheduler can run this thread
void thread_run(struct task *thread)
{
	assert(thread->state == TASK_STATE_DONT_RUN);
	thread->state = TASK_STATE_READY;
}
