#include <linux/module.h>    // included for all kernel modules
#include <linux/kernel.h>    // included for KERN_INFO
#include <linux/init.h>      // included for __init and __exit macros

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Havner");
MODULE_DESCRIPTION("Linux RSI playground");


static int __init rsi_init(void)
{
	printk(KERN_INFO "Hello world!\n");

	return 0;    // Non-zero return means that the module couldn't be loaded.
}

static void __exit rsi_cleanup(void)
{
	printk(KERN_INFO "Cleaning up module.\n");
}


module_init(rsi_init);
module_exit(rsi_cleanup);
