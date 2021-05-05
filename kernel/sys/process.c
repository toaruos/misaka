#include <kernel/process.h>

static process_t _fake_process = {
	.user = 0,
	.real_user = 0,
	.wd_name = "/",
};

volatile process_t * current_process = &_fake_process;

