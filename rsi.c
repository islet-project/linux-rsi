#include <linux/module.h>    // included for all kernel modules
#include <linux/kernel.h>    // included for KERN_INFO
#include <linux/init.h>      // included for __init and __exit macros

#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>

#include <asm/rsi.h>
#include <asm/uaccess.h>
#include <linux/cc_platform.h>

#include "rsi.h"


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Havner");
MODULE_DESCRIPTION("Linux RSI playground");


#define RSI_TAG   "rsi: "
#define RSI_INFO  KERN_INFO  RSI_TAG
#define RSI_ALERT KERN_ALERT RSI_TAG

#define DEVICE_NAME       "rsi"       /* Name of device in /proc/devices */
#define DEVICE_WRITE_LEN  64

static int device_major;              /* Major number assigned to our device driver */
static int device_open_count = 0;     /* Used to prevent multiple open */

// this will hold attestation token, needs to be page size
static char device_buf[RSI_GRANULE_SIZE];
static size_t device_len;

static struct class *cls;


static void rsi_playground(void)
{
	unsigned long ret = 0;
	bool realm = false;
	unsigned long ver = 0;
	const char *msg = "Welcome to RSI playground!\n";

	// creative use of an API
	realm = cc_platform_has(CC_ATTR_MEM_ENCRYPT);
	printk(RSI_INFO "Is realm: %s\n", realm ? "true" : "false");

	// version
	ver = rsi_get_version();
	printk(RSI_INFO "RSI version: %lu.%lu\n",
	       RSI_ABI_VERSION_GET_MAJOR(ver), RSI_ABI_VERSION_GET_MINOR(ver));

	// get config
	ret = rsi_get_realm_config(&config);
	printk(RSI_INFO "Config ret: %lu, Bits: %lX\n", ret, config.ipa_bits);

	// copy initial test output content
	device_len = strlen(msg);
	strncpy(device_buf, msg, device_len);
}

#if 0
static int nullify_input(char *input, size_t len, size_t max_len)
{
	if (len > max_len)
		return -EINVAL;

	if (len == max_len && input[len - 1] != '\n')
		return -EINVAL;

	if (input[len - 1] == '\n')
		input[len - 1] = '\0';
	else
		input[len] = '\0';

	return 0;
}

static int set_page_state(void *buf, enum ripas ripas)
{
	phys_addr_t start;
	struct arm_smccc_1_2_regs input = {0}, output = {0};

	start = virt_to_phys(buf);
	start = ALIGN_DOWN(start, RSI_GRANULE_SIZE);

	input.a0 = SMC_RSI_IPA_STATE_SET;
	input.a1 = start;
	input.a2 = RSI_GRANULE_SIZE;
	input.a3 = ripas;
	arm_smccc_1_2_smc(&input, &output);

	if (output.a0 != RSI_SUCCESS)
		return -rsi_ret_to_errno(output.a0);

	return 0;
}

#define BYTE_STRING_LEN 4
static void print_data(char *data, size_t len)
{
	size_t i;
	char ch[BYTE_STRING_LEN], line[32] = {0};

	for (i = 0; i < len; ++i) {
		if (i > 0 && i % 8 == 0) {
			printk(RSI_INFO "%s\n", line);
			line[0] = '\0';
		}
		snprintf(ch, BYTE_STRING_LEN, "%.2X ", data[i]);
		strncat(line, ch, BYTE_STRING_LEN);
	}

	if (line[0] != '\0')
		printk(RSI_INFO "%s\n", line);
}
#endif

static int rsi_ret_to_errno(unsigned long rsi_ret)
{
	switch (rsi_ret) {
	case RSI_SUCCESS:
		return 0;
	case RSI_ERROR_INPUT:
		return EFAULT;
	case RSI_ERROR_STATE:
		return EBADF;
	case RSI_INCOMPLETE:
		return 0;
	default:
		printk(RSI_ALERT "unknown ret code returned from RSI: %lu\n", rsi_ret);
		return ENXIO;
	}
}

/*
 * Chardev
 */

static int device_open(struct inode *i, struct file *f)
{
	printk(RSI_INFO "device %s open\n", DEVICE_NAME);

	if (device_open_count > 0)
		return -EBUSY;

	++device_open_count;
	if (!try_module_get(THIS_MODULE))
		return -ENOENT;

	return 0;
}

static int device_release(struct inode *i, struct file *f)
{
	printk(RSI_INFO "device %s released\n", DEVICE_NAME);

	module_put(THIS_MODULE);
	--device_open_count;

	return 0;
}

// data that can be read is an output from RSI commands (e.g. tokens)
// should be done after ioctl
// respects offset, can be read in parts
static ssize_t device_read(struct file *f, char *buffer, size_t len, loff_t *offset)
{
	int ret;
	size_t left_to_read = device_len - *offset;
	size_t will_read = min(left_to_read, len);

	// TODO: safety check, this should probably be done in a different way
	// can seek extend beyond file size? how is file size checked? what it if changes?
	if (*offset > device_len) {
		printk(RSI_ALERT "*offset > device_len, this should not happen\n");
		return -EINVAL;
	}

	printk(RSI_INFO "device_read: %lu, will_read: %lu, offset: %lld\n",
	       len, will_read, *offset);

	if (left_to_read == 0)
		return 0;

	ret = copy_to_user(buffer, device_buf + *offset, will_read);
	if (ret != 0) {
		printk(RSI_ALERT "Failed to copy_to_user %d bytes\n", ret);
		return ret;
	}

	*offset += will_read;

	return will_read;
}

// data written is an input for RSI commands (e.g. challenges)
// should be done before ioctl
// single write per data, ignores offset
static ssize_t device_write(struct file *f, const char *buffer, size_t len, loff_t *offset)
{
	int ret;

	printk(RSI_INFO "device_write: %lu\n", len);

	if (len == 0 || len > DEVICE_WRITE_LEN)
		return -EINVAL;

	ret = copy_from_user(device_buf, buffer, len);
	if (ret != 0) {
		printk(RSI_ALERT "Failed to copy_from_user %d bytes\n", ret);
		return ret;
	}
	device_len = len;

	//print_data(device_buf, device_len);

	return len;
}

static int do_measurement_read(uint32_t index)
{
	struct arm_smccc_1_2_regs input = {0}, output = {0};

	input.a0 = SMC_RSI_MEASUREMENT_READ;
	input.a1 = index;
	arm_smccc_1_2_smc(&input, &output);

	if (output.a0 != RSI_SUCCESS)
		return -rsi_ret_to_errno(output.a0);

	device_len = sizeof(output.a1) * 8;
	memcpy(device_buf, (char*)&output.a1, device_len);

	//print_data(device_buf, device_len);

	return 0;
}

static int do_measurement_extend(uint32_t index, uint32_t len)
{
	struct arm_smccc_1_2_regs input = {0}, output = {0};

	if (len > 64) {
		printk(RSI_ALERT "ioctl: can't use more than 64 bytes\n");
		return -EINVAL;
	}

	if (device_len < len) {
		printk(RSI_ALERT "ioctl: too little data in the buffer\n");
		return -EINVAL;
	}

	input.a0 = SMC_RSI_MEASUREMENT_EXTEND;
	input.a1 = index;
	input.a2 = len;
	memcpy((char*)&output.a3, device_buf, len);

	arm_smccc_1_2_smc(&input, &output);

	if (output.a0 != RSI_SUCCESS)
		return -rsi_ret_to_errno(output.a0);

	return 0;
}

static int do_attestation_init(phys_addr_t page)
{
	struct arm_smccc_1_2_regs input = {0}, output = {0};

	if (device_len != 64) {
		printk(RSI_ALERT "ioctl: we need exactly 64 bytes in the buffer\n");
		return -EINVAL;
	}

	input.a0 = SMC_RSI_ATTESTATION_TOKEN_INIT;
	input.a1 = page;
	memcpy((char*)&output.a2, device_buf, device_len);

	arm_smccc_1_2_smc(&input, &output);

	// TODO: which is correct?
	if (output.a0 == RSI_INCOMPLETE || output.a0 == RSI_SUCCESS)
		return 0;
	else
		return -rsi_ret_to_errno(output.a0);
}

static int do_attestation_continue(phys_addr_t page, size_t *token_len)
{
	struct arm_smccc_1_2_regs input = {0}, output = {0};

	if (device_len != 64) {
		printk(RSI_ALERT "ioctl: we need exactly 64 bytes in the buffer\n");
		return -EINVAL;
	}

	input.a0 = SMC_RSI_ATTESTATION_TOKEN_CONTINUE;
	input.a1 = page;

	arm_smccc_1_2_smc(&input, &output);

	if (output.a0 == RSI_SUCCESS) {
		*token_len = output.a1;
		return 0;  // we're done
	}

	if (output.a0 == RSI_INCOMPLETE)
		return 1;  // carry on

	return -rsi_ret_to_errno(output.a0);
}

static int do_attestation(void)
{
	int ret;
	size_t token_len;
	phys_addr_t page = virt_to_phys(rsi_page_buf);

	ret = do_attestation_init(page);

	if (ret != 0)
		return ret;

	do {
		ret = do_attestation_continue(page, &token_len);
	} while (ret == 1);

	if (ret == 0) {
		device_len = token_len;
		memcpy(device_buf, rsi_page_buf, token_len);

		//print_data(device_buf, min((size_t)64, device_len));
	}

	return ret;
}

static long device_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
	int ret;
	uint32_t index;
	uint32_t version;
	uint32_t extend[2];

	switch (cmd) {
	case RSIIO_ABI_VERSION:
		printk(RSI_INFO "ioctl: abi_version\n");

		version = (uint32_t)rsi_get_version();
		ret = copy_to_user((uint32_t*)arg, &version, sizeof(uint32_t));
		if (ret != 0) {
			printk(RSI_ALERT "ioctl: copy_to_user failed: %d\n", ret);
			return ret;
		}

		break;
	case RSIIO_MEASUREMENT_READ:
		ret = copy_from_user(&index, (uint32_t*)arg, sizeof(index));
		if (ret != 0) {
			printk(RSI_ALERT "ioctl: copy_from_user failed: %d\n", ret);
			return ret;
		}

		printk(RSI_INFO "ioctl: measurement_read: %u\n", index);

		ret = do_measurement_read(index);
		if (ret != 0) {
			printk(RSI_ALERT "ioctl: measurement_read failed: %d\n", ret);
			return ret;
		}

		break;
	case RSIIO_MEASUREMENT_EXTEND:
		ret = copy_from_user(extend, (uint32_t*)arg, sizeof(extend));
		if (ret != 0) {
			printk(RSI_ALERT "ioctl: copy_from_user failed: %d\n", ret);
			return ret;
		}

		printk(RSI_INFO "ioctl: measurement_extend: %u, %u\n", extend[0], extend[1]);

		ret = do_measurement_extend(extend[0], extend[1]);
		if (ret != 0) {
			printk(RSI_ALERT "ioctl: measurement_extend failed: %d\n", ret);
			return ret;
		}

		break;
	case RSIIO_ATTESTATION_TOKEN:
		printk(RSI_INFO "ioctl: attestation_token");

		ret = do_attestation();
		if (ret != 0) {
			printk(RSI_ALERT "ioctl: attestation failed: %d\n", ret);
			return ret;
		}

		break;
	default:
		printk(RSI_ALERT "ioctl: unknown ioctl cmd\n");
		return -EINVAL;
	}

	return 0;
}

static struct file_operations chardev_fops = {
	.open = device_open,
	.release = device_release,
	.read = device_read,
	.write = device_write,
	.unlocked_ioctl = device_ioctl,
};

/*
 * Module
 */

static int __init rsi_init(void)
{
	printk(RSI_INFO "Initializing\n");

	device_major = register_chrdev(0, DEVICE_NAME, &chardev_fops);
	if (device_major < 0) {
		printk(RSI_ALERT "register_chrdev failed with %d\n", device_major);
		return device_major;
	}

	printk(RSI_INFO "Chardev registered with major %d\n", device_major);

	cls = class_create(THIS_MODULE, DEVICE_NAME);
	device_create(cls, NULL, MKDEV(device_major, 0), NULL, DEVICE_NAME);

	printk(RSI_INFO "Device created on /dev/%s\n", DEVICE_NAME);

	rsi_playground();

	return 0;
}

static void __exit rsi_cleanup(void)
{
	printk(RSI_INFO "Cleaning up module\n");

	device_destroy(cls, MKDEV(device_major, 0));
	class_destroy(cls);

	unregister_chrdev(device_major, DEVICE_NAME);
}


module_init(rsi_init);
module_exit(rsi_cleanup);
