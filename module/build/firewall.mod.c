#include <linux/module.h>
#define INCLUDE_VERMAGIC
#include <linux/build-salt.h>
#include <linux/elfnote-lto.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

BUILD_SALT;
BUILD_LTO_INFO;

MODULE_INFO(vermagic, VERMAGIC_STRING);
MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__section(".gnu.linkonce.this_module") = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

#ifdef CONFIG_RETPOLINE
MODULE_INFO(retpoline, "Y");
#endif

static const struct modversion_info ____versions[]
__used __section("__versions") = {
	{ 0x367fcc51, "module_layout" },
	{ 0x6bc3fbc0, "__unregister_chrdev" },
	{ 0x58f94a7a, "kmalloc_caches" },
	{ 0xeae2f6cd, "device_destroy" },
	{ 0xf0d8f0d, "__register_chrdev" },
	{ 0xab5b1df7, "filp_close" },
	{ 0x85df9b6c, "strsep" },
	{ 0x5b8239ca, "__x86_return_thunk" },
	{ 0x557272bc, "kernel_read" },
	{ 0x536af521, "class_unregister" },
	{ 0x82dba992, "device_create" },
	{ 0x8c8569cb, "kstrtoint" },
	{ 0x1b4d5951, "init_net" },
	{ 0x10e12734, "nf_register_net_hook" },
	{ 0x4d2800f0, "nf_unregister_net_hook" },
	{ 0xd0da656b, "__stack_chk_fail" },
	{ 0x92997ed8, "_printk" },
	{ 0xbdfb6dbb, "__fentry__" },
	{ 0xcbb0ae81, "kmem_cache_alloc_trace" },
	{ 0x37a0cba, "kfree" },
	{ 0x3b6c41ea, "kstrtouint" },
	{ 0x7fbb56eb, "class_destroy" },
	{ 0x13c49cc2, "_copy_from_user" },
	{ 0xec8c17d0, "__class_create" },
	{ 0xde99224e, "filp_open" },
};

MODULE_INFO(depends, "");


MODULE_INFO(srcversion, "70E757776CCC8E9F65C5D9D");
