#include <kernel/process.h>
#include <kernel/string.h>

static fs_node_t * _entries[24] = {
	(fs_node_t *)1, (fs_node_t *)1, (fs_node_t *)1,
	NULL,
};

static uint64_t _offsets[24] = {0};
static int _modes[24] = {O_RDWR, O_RDWR, O_RDWR, 0};

static fd_table_t _fake_fds = {
	_entries,
	_offsets,
	_modes,
	3,
	24,
	1,
};

static process_t _fake_process = {
	.user = 0,
	.real_user = 0,
	.wd_name = "/",
	.fds = &_fake_fds,
};

volatile process_t * current_process = &_fake_process;

unsigned long process_append_fd(process_t * proc, fs_node_t * node) {
	/* Fill gaps */
	for (unsigned long i = 0; i < proc->fds->length; ++i) {
		if (!proc->fds->entries[i]) {
			proc->fds->entries[i] = node;
			/* modes, offsets must be set by caller */
			proc->fds->modes[i] = 0;
			proc->fds->offsets[i] = 0;
			return i;
		}
	}
	/* No gaps, expand */
	if (proc->fds->length == proc->fds->capacity) {
		proc->fds->capacity *= 2;
		proc->fds->entries = realloc(proc->fds->entries, sizeof(fs_node_t *) * proc->fds->capacity);
		proc->fds->modes   = realloc(proc->fds->modes,   sizeof(int) * proc->fds->capacity);
		proc->fds->offsets = realloc(proc->fds->offsets, sizeof(uint64_t) * proc->fds->capacity);
	}
	proc->fds->entries[proc->fds->length] = node;
	/* modes, offsets must be set by caller */
	proc->fds->modes[proc->fds->length] = 0;
	proc->fds->offsets[proc->fds->length] = 0;
	proc->fds->length++;
	return proc->fds->length-1;
}
