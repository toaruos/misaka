/**
 * @file kernel/net/e1000.c
 * @brief Intel Gigabit Ethernet device driver
 *
 * @copyright
 * This file is part of ToaruOS and is released under the terms
 * of the NCSA / University of Illinois License - see LICENSE.md
 * Copyright (C) 2017-2021 K. Lange
 */
#include <kernel/types.h>
#include <kernel/string.h>
#include <kernel/printf.h>
#include <kernel/process.h>
#include <kernel/pci.h>
#include <kernel/mmu.h>
#include <kernel/pipe.h>
#include <kernel/list.h>
#include <kernel/spinlock.h>
#include <kernel/time.h>
#include <kernel/vfs.h>
#include <kernel/mod/net.h>
#include <errno.h>

#include <kernel/arch/x86_64/irq.h>

static fs_node_t * e1000_fsdev = NULL;
static uint32_t e1000_device_pci = 0x00000000;
static int e1000_irq = 0;
static uintptr_t mem_base = 0;
static int has_eeprom = 0;
static uint8_t mac[6];
static int rx_index = 0;
static int tx_index = 0;
static int link_is_up = 0;

static list_t * net_queue = NULL;
static spin_lock_t net_queue_lock = { 0 };
static list_t * rx_wait;

static uint32_t mmio_read32(uintptr_t addr) {
	return *((volatile uint32_t*)(addr));
}
static void mmio_write32(uintptr_t addr, uint32_t val) {
	(*((volatile uint32_t*)(addr))) = val;
}

static void write_command(uint16_t addr, uint32_t val) {
	mmio_write32(mem_base + addr, val);
}

static uint32_t read_command(uint16_t addr) {
	return mmio_read32(mem_base + addr);
}

#define E1000_NUM_RX_DESC 32
#define E1000_NUM_TX_DESC 8

struct rx_desc {
	volatile uint64_t addr;
	volatile uint16_t length;
	volatile uint16_t checksum;
	volatile uint8_t  status;
	volatile uint8_t  errors;
	volatile uint16_t special;
} __attribute__((packed)); /* this looks like it should pack fine as-is */

struct tx_desc {
	volatile uint64_t addr;
	volatile uint16_t length;
	volatile uint8_t  cso;
	volatile uint8_t  cmd;
	volatile uint8_t  status;
	volatile uint8_t  css;
	volatile uint16_t special;
} __attribute__((packed));

static uint8_t * rx_virt[E1000_NUM_RX_DESC];
static uint8_t * tx_virt[E1000_NUM_TX_DESC];
static struct rx_desc * rx;
static struct tx_desc * tx;
static uintptr_t rx_phys;
static uintptr_t tx_phys;

static void enqueue_packet(void * buffer) {
	spin_lock(net_queue_lock);
	list_insert(net_queue, buffer);
	spin_unlock(net_queue_lock);
}

static struct ethernet_packet * dequeue_packet(void) {
	while (!net_queue->length) {
		sleep_on(rx_wait);
	}

	spin_lock(net_queue_lock);
	node_t * n = list_dequeue(net_queue);
	void* value = n->value;
	free(n);
	spin_unlock(net_queue_lock);

	return value;
}

static uint8_t* get_mac() {
	return mac;
}

#define E1000_REG_CTRL       0x0000
#define E1000_REG_STATUS     0x0008
#define E1000_REG_EEPROM     0x0014
#define E1000_REG_CTRL_EXT   0x0018
#define E1000_REG_ICR        0x00C0

#define E1000_REG_RCTRL      0x0100
#define E1000_REG_RXDESCLO   0x2800
#define E1000_REG_RXDESCHI   0x2804
#define E1000_REG_RXDESCLEN  0x2808
#define E1000_REG_RXDESCHEAD 0x2810
#define E1000_REG_RXDESCTAIL 0x2818

#define E1000_REG_TCTRL      0x0400
#define E1000_REG_TXDESCLO   0x3800
#define E1000_REG_TXDESCHI   0x3804
#define E1000_REG_TXDESCLEN  0x3808
#define E1000_REG_TXDESCHEAD 0x3810
#define E1000_REG_TXDESCTAIL 0x3818

#define E1000_REG_RXADDR     0x5400

#define RCTL_EN                         (1 << 1)    /* Receiver Enable */
#define RCTL_SBP                        (1 << 2)    /* Store Bad Packets */
#define RCTL_UPE                        (1 << 3)    /* Unicast Promiscuous Enabled */
#define RCTL_MPE                        (1 << 4)    /* Multicast Promiscuous Enabled */
#define RCTL_LPE                        (1 << 5)    /* Long Packet Reception Enable */
#define RCTL_LBM_NONE                   (0 << 6)    /* No Loopback */
#define RCTL_LBM_PHY                    (3 << 6)    /* PHY or external SerDesc loopback */
#define RCTL_RDMTS_HALF                 (0 << 8)    /* Free Buffer Threshold is 1/2 of RDLEN */
#define RCTL_RDMTS_QUARTER              (1 << 8)    /* Free Buffer Threshold is 1/4 of RDLEN */
#define RCTL_RDMTS_EIGHTH               (2 << 8)    /* Free Buffer Threshold is 1/8 of RDLEN */
#define RCTL_MO_36                      (0 << 12)   /* Multicast Offset - bits 47:36 */
#define RCTL_MO_35                      (1 << 12)   /* Multicast Offset - bits 46:35 */
#define RCTL_MO_34                      (2 << 12)   /* Multicast Offset - bits 45:34 */
#define RCTL_MO_32                      (3 << 12)   /* Multicast Offset - bits 43:32 */
#define RCTL_BAM                        (1 << 15)   /* Broadcast Accept Mode */
#define RCTL_VFE                        (1 << 18)   /* VLAN Filter Enable */
#define RCTL_CFIEN                      (1 << 19)   /* Canonical Form Indicator Enable */
#define RCTL_CFI                        (1 << 20)   /* Canonical Form Indicator Bit Value */
#define RCTL_DPF                        (1 << 22)   /* Discard Pause Frames */
#define RCTL_PMCF                       (1 << 23)   /* Pass MAC Control Frames */
#define RCTL_SECRC                      (1 << 26)   /* Strip Ethernet CRC */

#define RCTL_BSIZE_256                  (3 << 16)
#define RCTL_BSIZE_512                  (2 << 16)
#define RCTL_BSIZE_1024                 (1 << 16)
#define RCTL_BSIZE_2048                 (0 << 16)
#define RCTL_BSIZE_4096                 ((3 << 16) | (1 << 25))
#define RCTL_BSIZE_8192                 ((2 << 16) | (1 << 25))
#define RCTL_BSIZE_16384                ((1 << 16) | (1 << 25))

#define TCTL_EN                         (1 << 1)    /* Transmit Enable */
#define TCTL_PSP                        (1 << 3)    /* Pad Short Packets */
#define TCTL_CT_SHIFT                   4           /* Collision Threshold */
#define TCTL_COLD_SHIFT                 12          /* Collision Distance */
#define TCTL_SWXOFF                     (1 << 22)   /* Software XOFF Transmission */
#define TCTL_RTLC                       (1 << 24)   /* Re-transmit on Late Collision */

#define CMD_EOP                         (1 << 0)    /* End of Packet */
#define CMD_IFCS                        (1 << 1)    /* Insert FCS */
#define CMD_IC                          (1 << 2)    /* Insert Checksum */
#define CMD_RS                          (1 << 3)    /* Report Status */
#define CMD_RPS                         (1 << 4)    /* Report Packet Sent */
#define CMD_VLE                         (1 << 6)    /* VLAN Packet Enable */
#define CMD_IDE                         (1 << 7)    /* Interrupt Delay Enable */

#define ICR_TXDW   (1 << 0)
#define ICR_TXQE   (1 << 1)  /* Transmit queue is empty */
#define ICR_LSC    (1 << 2)  /* Link status changed */
#define ICR_RXSEQ  (1 << 3)  /* Receive sequence count error */
#define ICR_RXDMT0 (1 << 4)  /* Receive descriptor minimum threshold */
/* what's 5 (0x20)? */
#define ICR_RXO    (1 << 6)  /* Receive overrun */
#define ICR_RXT0   (1 << 7)  /* Receive timer interrupt? */

static int eeprom_detect(void) {

	write_command(E1000_REG_EEPROM, 1);

	for (int i = 0; i < 100000 && !has_eeprom; ++i) {
		uint32_t val = read_command(E1000_REG_EEPROM);
		if (val & 0x10) has_eeprom = 1;
	}

	return 0;
}

static uint16_t eeprom_read(uint8_t addr) {
	uint32_t temp = 0;
	write_command(E1000_REG_EEPROM, 1 | ((uint32_t)(addr) << 8));
	while (!((temp = read_command(E1000_REG_EEPROM)) & (1 << 4)));
	return (uint16_t)((temp >> 16) & 0xFFFF);
}


static void find_e1000(uint32_t device, uint16_t vendorid, uint16_t deviceid, void * extra) {
	if ((vendorid == 0x8086) && (deviceid == 0x100e || deviceid == 0x1004 || deviceid == 0x100f || deviceid == 0x10ea)) {
		*((uint32_t *)extra) = device;
	}
}

static void write_mac(void) {

	uint32_t low;
	uint32_t high;

	memcpy(&low, &mac[0], 4);
	memcpy(&high,&mac[4], 2);
	memset((uint8_t *)&high + 2, 0, 2);
	high |= 0x80000000;

	write_command(E1000_REG_RXADDR + 0, low);
	write_command(E1000_REG_RXADDR + 4, high);
}

static void read_mac(void) {
	if (has_eeprom) {
		uint32_t t;
		t = eeprom_read(0);
		mac[0] = t & 0xFF;
		mac[1] = t >> 8;
		t = eeprom_read(1);
		mac[2] = t & 0xFF;
		mac[3] = t >> 8;
		t = eeprom_read(2);
		mac[4] = t & 0xFF;
		mac[5] = t >> 8;
	} else {
		uint8_t * mac_addr = (uint8_t *)(mem_base + E1000_REG_RXADDR);
		for (int i = 0; i < 6; ++i) {
			mac[i] = mac_addr[i];
		}
	}
}

static int irq_handler(struct regs *r) {

	uint32_t status = read_command(E1000_REG_ICR);

	if (!status) {
		return 0;
	}

	irq_ack(e1000_irq);

	if (status & ICR_LSC) {
		/* TODO: Change interface link status. */
		link_is_up = (read_command(E1000_REG_STATUS) & (1 << 1));
	}

	if (status & ICR_TXQE) {
		/* Transmit queue empty; nothing to do. */
	}

	if (status & (ICR_RXO | ICR_RXT0)) {
		/* Packet received. */
		do {
			rx_index = read_command(E1000_REG_RXDESCTAIL);
			if (rx_index == (int)read_command(E1000_REG_RXDESCHEAD)) return 1;
			rx_index = (rx_index + 1) % E1000_NUM_RX_DESC;
			if (rx[rx_index].status & 0x01) {
				uint8_t * pbuf = (uint8_t *)rx_virt[rx_index];
				uint16_t  plen = rx[rx_index].length;

				void * packet = malloc(8092);
				memcpy(packet, pbuf, plen);

				rx[rx_index].status = 0;

				enqueue_packet(packet);

				write_command(E1000_REG_RXDESCTAIL, rx_index);
			} else {
				break;
			}
		} while (1);
		wakeup_queue(rx_wait);
	}

	return 1;
}

static void send_packet(uint8_t* payload, size_t payload_size) {
	tx_index = read_command(E1000_REG_TXDESCTAIL);

	memcpy(tx_virt[tx_index], payload, payload_size);
	tx[tx_index].length = payload_size;
	tx[tx_index].cmd = CMD_EOP | CMD_IFCS | CMD_RS; //| CMD_RPS;
	tx[tx_index].status = 0;

	tx_index = (tx_index + 1) % E1000_NUM_TX_DESC;
	write_command(E1000_REG_TXDESCTAIL, tx_index);
}

static void init_rx(void) {

	write_command(E1000_REG_RXDESCLO, rx_phys);
	write_command(E1000_REG_RXDESCHI, 0);

	write_command(E1000_REG_RXDESCLEN, E1000_NUM_RX_DESC * sizeof(struct rx_desc));

	write_command(E1000_REG_RXDESCHEAD, 0);
	write_command(E1000_REG_RXDESCTAIL, E1000_NUM_RX_DESC - 1);

	rx_index = 0;

	write_command(E1000_REG_RCTRL,
		RCTL_EN  |
		(read_command(E1000_REG_RCTRL) & (~((1 << 17) | (1 << 16)))));

}

static void init_tx(void) {


	write_command(E1000_REG_TXDESCLO, tx_phys);
	write_command(E1000_REG_TXDESCHI, 0);

	write_command(E1000_REG_TXDESCLEN, E1000_NUM_TX_DESC * sizeof(struct tx_desc));

	write_command(E1000_REG_TXDESCHEAD, 0);
	write_command(E1000_REG_TXDESCTAIL, 0);

	tx_index = 0;

	write_command(E1000_REG_TCTRL,
		TCTL_EN |
		TCTL_PSP |
		read_command(E1000_REG_TCTRL));
}

static int ioctl_e1000(fs_node_t * node, int request, void * argp) {
	switch (request) {
		case 0x12340001:
			/* fill argp with mac */
			memcpy(argp, mac, sizeof(mac));
			return 0;
		default:
			return -EINVAL;
	}
}

static uint64_t write_e1000(fs_node_t *node, uint64_t offset, uint64_t size, uint8_t *buffer) {
	/* write packet */
	send_packet(buffer, size);
	return size;
}

static uint64_t read_e1000(fs_node_t *node, uint64_t offset, uint64_t size, uint8_t *buffer) {
	if (size != 8092) return 0;
	struct ethernet_packet * packet = dequeue_packet();
	memcpy(buffer, packet, 8092);
	free(packet);
	return 8092;
}

static void e1000_init(void * data) {
	uint16_t command_reg = pci_read_field(e1000_device_pci, PCI_COMMAND, 2);
	command_reg |= (1 << 2);
	command_reg |= (1 << 0);
	pci_write_field(e1000_device_pci, PCI_COMMAND, 2, command_reg);

	unsigned long s, ss;
	relative_time(0, 10000, &s, &ss);
	sleep_until((process_t *)this_core->current_process, s, ss);
	switch_task(0);

	uint32_t initial_bar = pci_read_field(e1000_device_pci, PCI_BAR0, 4);
	/* We can't use the general -128GiB mapping are because _certain VMs_
	 * won't let us access this MMIO range through 1GiB pages, so we'll
	 * map to the region just above the heap */
	mem_base = 0xffffff1fc0000000;
	for (size_t i = 0; i < 0x80000; i += 0x1000) {
		union PML * p = mmu_get_page(mem_base + i, MMU_GET_MAKE);
		mmu_frame_map_address(p, MMU_FLAG_KERNEL | MMU_FLAG_WRITABLE | MMU_FLAG_NOCACHE | MMU_FLAG_WRITETHROUGH, initial_bar + i);
		mmu_invalidate(mem_base + i);
	}

	eeprom_detect();
	read_mac();
	write_mac();
	uint32_t ctrl = read_command(E1000_REG_CTRL);

	/* reset phy */
	write_command(E1000_REG_CTRL, ctrl | (0x80000000));
	read_command(E1000_REG_STATUS);
	relative_time(0, 10000, &s, &ss);
	sleep_until((process_t *)this_core->current_process, s, ss);
	switch_task(0);

	/* reset mac */
	write_command(E1000_REG_CTRL, ctrl | (0x04000000));
	read_command(E1000_REG_STATUS);
	relative_time(0, 10000, &s, &ss);
	sleep_until((process_t *)this_core->current_process, s, ss);
	switch_task(0);

	/* Reload EEPROM */
	write_command(E1000_REG_CTRL, ctrl | (0x00002000));
	read_command(E1000_REG_STATUS);
	relative_time(0, 20000, &s, &ss);
	sleep_until((process_t *)this_core->current_process, s, ss);
	switch_task(0);


	/* initialize */
	write_command(E1000_REG_CTRL, ctrl | (1 << 26));

	/* wait */
	relative_time(0, 10000, &s, &ss);
	sleep_until((process_t *)this_core->current_process, s, ss);
	switch_task(0);

	uint32_t status = read_command(E1000_REG_CTRL);
	status |= (1 << 5);   /* set auto speed detection */
	status |= (1 << 6);   /* set link up */
	status &= ~(1 << 3);  /* unset link reset */
	status &= ~(1UL << 31UL); /* unset phy reset */
	status &= ~(1 << 7);  /* unset invert loss-of-signal */
	write_command(E1000_REG_CTRL, status);

	/* Disables flow control */
	write_command(0x0028, 0);
	write_command(0x002c, 0);
	write_command(0x0030, 0);
	write_command(0x0170, 0);

	/* Unset flow control */
	status = read_command(E1000_REG_CTRL);
	status &= ~(1 << 30);
	write_command(E1000_REG_CTRL, status);

	relative_time(0, 10000, &s, &ss);
	sleep_until((process_t *)this_core->current_process, s, ss);
	switch_task(0);

	net_queue = list_create("e1000 net queue", NULL);
	rx_wait = list_create("e1000 rx sem", NULL);

	e1000_irq = pci_get_interrupt(e1000_device_pci);

	irq_install_handler(e1000_irq, irq_handler, "e1000");

	for (int i = 0; i < 128; ++i) {
		write_command(0x5200 + i * 4, 0);
	}

	for (int i = 0; i < 64; ++i) {
		write_command(0x4000 + i * 4, 0);
	}

#if 0
	/* This would rewrite the MAC address... */
	write_command(0x5400, *(uint32_t*)(&mac[0]));
	write_command(0x5404, *(uint16_t*)(&mac[4]));
	write_command(0x5404, read_command(0x5404) | (1 << 31));
#endif

	write_command(E1000_REG_RCTRL, (1 << 4));

	init_rx();
	init_tx();

	/* Twiddle interrupts */
	write_command(0x00D0, 0xFF);
	write_command(0x00D8, 0xFF);
	write_command(0x00D0,(1 << 2) | (1 << 6) | (1 << 7) | (1 << 1) | (1 << 0));

	relative_time(0, 10000, &s, &ss);
	sleep_until((process_t *)this_core->current_process, s, ss);
	switch_task(0);

	link_is_up = (read_command(E1000_REG_STATUS) & (1 << 1));

	e1000_fsdev = calloc(sizeof(fs_node_t),1);
	snprintf(e1000_fsdev->name, 100, "eth0");
	e1000_fsdev->flags = FS_BLOCKDEVICE; /* NETDEVICE? */
	e1000_fsdev->mask  = 0666; /* let everyone in on the party for now */
	e1000_fsdev->ioctl = ioctl_e1000;
	e1000_fsdev->write = write_e1000;
	e1000_fsdev->read  = read_e1000;

	vfs_mount("/dev/eth0", e1000_fsdev);

	/* FIXME: We are not destroying kernel worker threads correctly... */
	switch_task(0);
}

void e1000_initialize(void) {
	pci_scan(&find_e1000, -1, &e1000_device_pci);

	if (!e1000_device_pci) {
		return;
	}

	/* Allocate a frame to use for stuff */
	rx_phys = mmu_allocate_a_frame() << 12;
	if (rx_phys == 0) {
		printf("e1000: unable to allocate memory for buffers\n");
		return;
	}
	rx = mmu_map_from_physical(rx_phys);
	tx_phys = rx_phys + 512;
	tx = mmu_map_from_physical(tx_phys);

	/* Allocate buffers */
	for (int i = 0; i < E1000_NUM_RX_DESC; ++i) {
		rx[i].addr = mmu_allocate_n_frames(2) << 12;
		if (rx[i].addr == 0) {
			printf("e1000: unable to allocate memory for receive buffer\n");
			return;
		}
		rx_virt[i] = mmu_map_from_physical(rx[i].addr);
		rx[i].status = 0;
	}

	for (int i = 0; i < E1000_NUM_TX_DESC; ++i) {
		tx[i].addr = mmu_allocate_n_frames(2) << 12;
		if (tx[i].addr == 0) {
			printf("e1000: unable to allocate memory for receive buffer\n");
			return;
		}
		tx_virt[i] = mmu_map_from_physical(tx[i].addr);
		tx[i].status = 0;
		tx[i].cmd = (1 << 0);
	}

	spawn_worker_thread(e1000_init, "[e1000]", NULL);

#if 0
	create_kernel_tasklet(e1000_init, "[e1000]", NULL);
#endif
}

