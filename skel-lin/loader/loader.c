/*
 * Loader Implementation
 *
 * 2018, Operating Systems
 */

#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "exec_parser.h"
#include "../so_stdio.h"

/* Defines */
#define handle_error(msg)				\
	do { perror(msg); exit(EXIT_FAILURE); } while (0)

#define PAGE_SIZE_DEF 4096U

/* Variables */
static const uint32_t PAGE_SIZE = PAGE_SIZE_DEF;
static char buffer[PAGE_SIZE_DEF];

static so_exec_t *exec;
static struct sigaction default_sigsegv_action;
static SO_FILE *file_fd;

/* Declarations */
static void set_sigsegv_handler(void);
static void sigsegv_handler(int signum, siginfo_t *info, void *context);

int so_init_loader(void)
{
	set_sigsegv_handler();

	return 0;
}

int so_execute(char *path, char *argv[])
{
	int i;
	int no_pages;
	int vec_size;

	exec = so_parse_exec(path);
	if (!exec)
		return -1;

	file_fd = so_fopen(path, "r");
	if (file_fd == NULL)
		handle_error("fopen");

	/* a bitmap for the allocated pages */
	for (i = 0; i < exec->segments_no; ++i) {
		no_pages = exec->segments[i].mem_size / PAGE_SIZE;
		if (exec->segments[i].mem_size % PAGE_SIZE)
			++no_pages;
		vec_size = no_pages / 8;
		if (no_pages % 8)
			++vec_size;
		exec->segments[i].data = calloc(vec_size, sizeof(char));
	}

	so_start_exec(exec, argv);

	return -1;
}

void set_sigsegv_handler(void)
{
	struct sigaction action;

	memset(&action, 0, sizeof(struct sigaction));

	/* block other SIGSEGV signals while handler runs */
	if (sigemptyset(&action.sa_mask) == -1)
		handle_error("sigemptyset");
	if (sigaddset(&action.sa_mask, SIGSEGV) == -1)
		handle_error("sigaddset");

	action.sa_flags = SA_SIGINFO;
	action.sa_sigaction = sigsegv_handler;

	sigaction(SIGSEGV, &action, &default_sigsegv_action);
}

void sigsegv_handler(int signum, siginfo_t *info, void *context)
{
	int req_seg;
	uintptr_t req_seg_offset;
	int page_index;
	int page_vec_offset;
	int page_bit_offset;
	uintptr_t page_address;
	long page_address_in_file;
	unsigned int perm;
	void *p;
	int ret;
	size_t nmemb;

	req_seg_offset = (uintptr_t) info->si_addr;
	for (req_seg = 0; req_seg < exec->segments_no; ++req_seg) {
		/* seg_addr [] req_addr [] seg_addr + seg_size */
		if (req_seg_offset >= exec->segments[req_seg].vaddr
			&& req_seg_offset < exec->segments[req_seg].vaddr
				+ exec->segments[req_seg].mem_size)
			break;
	}

	/* if the required address is not in a segment */
	if (req_seg == exec->segments_no) {
		default_sigsegv_action.sa_sigaction(signum, info, context);
		return;
	}
	/* if the required address was allocated */
	page_index = (req_seg_offset - exec->segments[req_seg].vaddr)
			/ PAGE_SIZE;

	page_vec_offset = page_index / 8;
	page_bit_offset = page_index % 8;
	if (((char *) exec->segments[req_seg].data)[page_vec_offset]
			& (1U << page_bit_offset)) {
		default_sigsegv_action.sa_sigaction(signum, info, context);
		return;
	}

	/* allocate virtual memory for the page */
	page_address = exec->segments[req_seg].vaddr + page_index * PAGE_SIZE;
	if (page_address >= exec->segments[req_seg].vaddr
			+ exec->segments[req_seg].mem_size)
		perm = 0x0;
	else
		perm = exec->segments[req_seg].perm;
	p = mmap((void *) page_address,
		PAGE_SIZE,
		PERM_W,
		MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
		-1,
		0);
	if (p == MAP_FAILED)
		handle_error("mmap");

	/* populate the page with information if
	 * - permissions allow &&
	 * - page still in file_size
	 */
	if (perm && page_index * PAGE_SIZE
			<= exec->segments[req_seg].file_size) {
		page_address_in_file = exec->segments[req_seg].offset
				+ page_index * PAGE_SIZE;

		if (so_fseek(file_fd, page_address_in_file, SEEK_SET) == -1)
			handle_error("so_fseek");

		if (exec->segments[req_seg].file_size
				< page_index * PAGE_SIZE + PAGE_SIZE)
			nmemb = exec->segments[req_seg].file_size
					- page_index * PAGE_SIZE;
		else
			nmemb = PAGE_SIZE;

		ret = so_fread(buffer, sizeof(buffer[0]), nmemb, file_fd);
		memcpy(p, buffer, ret);

	}

	if (mprotect(p, PAGE_SIZE, perm) == -1)
		handle_error("mprotect");

	((char *) exec->segments[req_seg].data)[page_vec_offset]
			|= (1U << page_bit_offset);
}

#undef PAGE_SIZE_DEF
