#include <linux/ioctl.h>


#ifndef RSI_ABI_VERSION_GET_MAJOR
#define RSI_ABI_VERSION_GET_MAJOR(_version) ((_version) >> 16)
#endif
#ifndef RSI_ABI_VERSION_GET_MINOR
#define RSI_ABI_VERSION_GET_MINOR(_version) ((_version) & 0xFFFF)
#endif

#define RSI_GRANULE_SIZE	0x1000

#define RSIIO_ABI_VERSION                 _IOR('x', 190, uint32_t /*version*/)
#define RSIIO_MEASUREMENT_READ            _IOW('x', 192, uint32_t /*index*/)
#define RSIIO_MEASUREMENT_EXTEND          _IOW('x', 193, uint32_t[2] /*index*/)
#define RSIIO_ATTESTATION_TOKEN           _IO('x', 194)

/*
 * Those are pages that have to be defined in the kernel itself.
 * They are used as output pages for RSI calls.
 * Needs small patch to the kernel.
 *
 * This will not be required when the module is builtin in the kernel.
 */
extern struct realm_config __attribute((aligned(RSI_GRANULE_SIZE))) config;
extern char __attribute__((aligned(RSI_GRANULE_SIZE))) rsi_page_buf[RSI_GRANULE_SIZE];
