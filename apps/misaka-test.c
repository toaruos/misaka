/**
 * @file  misaka-test.c
 * @brief Test app for Misaka with a bunch of random stuff.
 */
#include <stdio.h>
#include <unistd.h>

#include <toaru/graphics.h>

#include <kuroko/kuroko.h>
#include <kuroko/vm.h>

static void demo_runKurokoSnippet(void) {
	krk_initVM(0);
	krk_startModule("__main__");
	krk_interpret("import kuroko\nprint('Kuroko',kuroko.version)\n", "<stdin>");
	krk_freeVM();
}

static void demo_drawWallpaper(void) {
	/* Set up a wrapper context for the framebuffer */
	gfx_context_t * ctx = init_graphics_fullscreen();

	/* Load the wallpaper. */
	sprite_t wallpaper = { 0 };
	load_sprite(&wallpaper, "/usr/share/wallpaper.jpg");
	wallpaper.alpha = ALPHA_EMBEDDED;

	printf("wallpaper sprite info: %d x %d\n", wallpaper.width, wallpaper.height);

	draw_sprite_scaled(ctx, &wallpaper, 0, 0, 1440, 900);
	flip(ctx);
	//blur_context_box(&ctx, 10);
}

int main(int argc, char * argv[]) {
	demo_drawWallpaper();
	demo_runKurokoSnippet();

	return execve("/bin/kuroko",(char*[]){"kuroko",NULL},(char*[]){NULL});
}
