// SPDX-License-Identifier: GPL-2.0-only OR MIT
/* Copyright (c) 2023 Imagination Technologies Ltd. */

#include "pvr_device.h"
#include "pvr_fw.h"
#include "pvr_fw_mips.h"
#include "pvr_gem.h"
#include "pvr_rogue_mips.h"
#include "pvr_vm_mips.h"

#include <linux/elf.h>
#include <linux/err.h>
#include <linux/types.h>

#define ROGUE_FW_HEAP_MIPS_BASE 0xC0000000
#define ROGUE_FW_HEAP_MIPS_SHIFT 24 /* 16 MB */
#define ROGUE_FW_HEAP_MIPS_RESERVED_SIZE SZ_1M

/**
 * process_elf_command_stream() - Process ELF firmware image and populate
 *                                firmware sections
 * @pvr_dev: Device pointer.
 * @fw: Pointer to firmware image.
 * @fw_code_ptr: Pointer to FW code section.
 * @fw_data_ptr: Pointer to FW data section.
 * @fw_core_code_ptr: Pointer to FW coremem code section.
 * @fw_core_data_ptr: Pointer to FW coremem data section.
 *
 * Returns :
 *  * 0 on success, or
 *  * -EINVAL on any error in ELF command stream.
 */
static int
process_elf_command_stream(struct pvr_device *pvr_dev, const u8 *fw, u8 *fw_code_ptr,
			   u8 *fw_data_ptr, u8 *fw_core_code_ptr, u8 *fw_core_data_ptr)
{
	struct elf32_hdr *header = (struct elf32_hdr *)fw;
	struct elf32_phdr *program_header = (struct elf32_phdr *)(fw + header->e_phoff);
	struct drm_device *drm_dev = from_pvr_device(pvr_dev);
	u32 entry;
	int err;

	for (entry = 0; entry < header->e_phnum; entry++, program_header++) {
		void *write_addr;

		/* Only consider loadable entries in the ELF segment table */
		if (program_header->p_type != PT_LOAD)
			continue;

		err = pvr_fw_find_mmu_segment(pvr_dev, program_header->p_vaddr,
					      program_header->p_memsz, fw_code_ptr, fw_data_ptr,
					      fw_core_code_ptr, fw_core_data_ptr, &write_addr);
		if (err) {
			drm_err(drm_dev,
				"Addr 0x%x (size: %d) not found in any firmware segment",
				program_header->p_vaddr, program_header->p_memsz);
			return err;
		}

		/* Write to FW allocation only if available */
		if (write_addr) {
			memcpy(write_addr, fw + program_header->p_offset,
			       program_header->p_filesz);

			memset((u8 *)write_addr + program_header->p_filesz, 0,
			       program_header->p_memsz - program_header->p_filesz);
		}
	}

	return 0;
}

static int
pvr_mips_init(struct pvr_device *pvr_dev)
{
	pvr_fw_heap_info_init(pvr_dev, ROGUE_FW_HEAP_MIPS_SHIFT, ROGUE_FW_HEAP_MIPS_RESERVED_SIZE);

	return pvr_vm_mips_init(pvr_dev);
}

static void
pvr_mips_fini(struct pvr_device *pvr_dev)
{
	pvr_vm_mips_fini(pvr_dev);
}

// Function to dump the stack
void dump_mips_stack(struct pvr_device *pvr_dev, const u8 *stack_base,
		     u32 stack_size)
{
	u32 *stack_ptr =
		(u32 *)stack_base; // Assuming the stack is 32-bit aligned
	int i;

	printk(KERN_INFO "Dumping MIPS Stack (Base: %p, Size: 0x%x):\n",
	       stack_base, stack_size);
	for (i = 0; i < stack_size / sizeof(u32); i++) {
		if (i % 4 == 0) { // Print 4 words per line
			printk(KERN_INFO "\n0x%08x: ",
			       (u32)(stack_base + i * sizeof(u32)));
		}
		printk(KERN_CONT "0x%08x ", stack_ptr[i]);
	}
	printk(KERN_INFO "\n");
}

static struct rogue_mipsfw_boot_data *boot_data;
static struct rogue_mips_state *mips_state_data;

void print_rogue_mips_state()
{
//	struct pvr_fw_mem *fw_mem = &pvr_dev->fw_dev.mem;

	struct rogue_mips_state *state = mips_state_data;
	int i;

	//pvr_fw_object_vmap(fw_mem->core_data_obj);


	if (!state) {
		printk(KERN_ERR "Invalid MIPS state pointer\n");
		return;
	}

	printk(KERN_INFO "MIPS State:\n");
	printk(KERN_INFO "Error State: 0x%x\n", state->error_state);
	printk(KERN_INFO "Error EPC: 0x%x\n", state->error_epc);
	printk(KERN_INFO "Status Register: 0x%x\n", state->status_register);
	printk(KERN_INFO "Cause Register: 0x%x\n", state->cause_register);
	printk(KERN_INFO "Bad Register: 0x%x\n", state->bad_register);
	printk(KERN_INFO "EPC: 0x%x\n", state->epc);
	printk(KERN_INFO "SP (Stack Pointer): 0x%x\n", state->sp);
	printk(KERN_INFO "Debug: 0x%x\n", state->debug);
	printk(KERN_INFO "DEPC: 0x%x\n", state->depc);
	printk(KERN_INFO "Bad Instruction: 0x%x\n", state->bad_instr);
	printk(KERN_INFO "Unmapped Address: 0x%x\n", state->unmapped_address);

	// Print TLB entries
	printk(KERN_INFO "TLB Entries:\n");
	for (i = 0; i < ROGUE_MIPSFW_NUMBER_OF_TLB_ENTRIES; i++) {
		printk(KERN_INFO
		       "TLB[%d]: Page Mask: 0x%x, Hi: 0x%x, Lo0: 0x%x, Lo1: 0x%x\n",
		       i, state->tlb[i].tlb_page_mask, state->tlb[i].tlb_hi,
		       state->tlb[i].tlb_lo0, state->tlb[i].tlb_lo1);
	}

	// Print Remap entries
	printk(KERN_INFO "Remap Entries:\n");
	for (i = 0; i < ROGUE_MIPSFW_NUMBER_OF_REMAP_ENTRIES; i++) {
		printk(KERN_INFO
		       "Remap[%d]: Addr In: 0x%x, Addr Out: 0x%x, Region Size: 0x%x\n",
		       i, state->remap[i].remap_addr_in,
		       state->remap[i].remap_addr_out,
		       state->remap[i].remap_region_size);
	}

	printk(KERN_INFO "MIPS state dump completed.\n");
}

#include <linux/io.h>  // for memremap and memunmap
#include <linux/dma-map-ops.h>

#define STACK_SIZE 4096

static dma_addr_t stack_phys_addr_saved;

int pvr_mips_print_stack(void)
{
	void *stack_virt_addr;
	dma_addr_t stack_phys_addr;
	int i;

	stack_phys_addr = stack_phys_addr_saved;


	//arch_sync_dma_for_device(stack_phys_addr, STACK_SIZE, DMA_FROM_DEVICE);

	// Map the physical address to a virtual address
	stack_virt_addr = memremap(stack_phys_addr, STACK_SIZE, MEMREMAP_WB);
	if (!stack_virt_addr) {
		printk(KERN_ERR
		       "Failed to map stack physical address to virtual address\n");
		return -ENOMEM;
	}

	// Print the stack in hex, 16 bytes per line
	printk(KERN_INFO "Stack contents (physical addr: 0x%llx):\n",
	       (unsigned long long)stack_phys_addr);
	for (i = 0; i < STACK_SIZE; i += 16) {
		printk(KERN_INFO "0x%08x: %*phN\n", stack_phys_addr + i, 16,
		       (u8 *)(stack_virt_addr + i));
	}

	// Unmap the memory when done
	memunmap(stack_virt_addr);

	return 0;
}

static int
pvr_mips_fw_process(struct pvr_device *pvr_dev, const u8 *fw,
		    u8 *fw_code_ptr, u8 *fw_data_ptr, u8 *fw_core_code_ptr, u8 *fw_core_data_ptr,
		    u32 core_code_alloc_size)
{
	struct pvr_fw_device *fw_dev = &pvr_dev->fw_dev;
	struct pvr_fw_mips_data *mips_data = fw_dev->processor_data.mips_data;
	const struct pvr_fw_layout_entry *boot_code_entry;
	const struct pvr_fw_layout_entry *boot_data_entry;
	const struct pvr_fw_layout_entry *exception_code_entry;
	const struct pvr_fw_layout_entry *stack_entry;
	struct rogue_mipsfw_boot_data *boot_data;
	struct rogue_mips_state *mips_state_data;
	dma_addr_t dma_addr;
	u32 page_nr;
	int err;

	err = process_elf_command_stream(pvr_dev, fw, fw_code_ptr, fw_data_ptr, fw_core_code_ptr,
					 fw_core_data_ptr);
	if (err)
		return err;


	///mips_stat

	boot_code_entry = pvr_fw_find_layout_entry(pvr_dev, MIPS_BOOT_CODE);
	boot_data_entry = pvr_fw_find_layout_entry(pvr_dev, MIPS_BOOT_DATA);
	exception_code_entry = pvr_fw_find_layout_entry(pvr_dev, MIPS_EXCEPTIONS_CODE);
	if (!boot_code_entry || !boot_data_entry || !exception_code_entry)
		return -EINVAL;

	WARN_ON(pvr_gem_get_dma_addr(fw_dev->mem.code_obj->gem, boot_code_entry->alloc_offset,
				     &mips_data->boot_code_dma_addr));
	WARN_ON(pvr_gem_get_dma_addr(fw_dev->mem.data_obj->gem, boot_data_entry->alloc_offset,
				     &mips_data->boot_data_dma_addr));
	WARN_ON(pvr_gem_get_dma_addr(fw_dev->mem.code_obj->gem,
				     exception_code_entry->alloc_offset,
				     &mips_data->exception_code_dma_addr));

	stack_entry = pvr_fw_find_layout_entry(pvr_dev, MIPS_STACK);
	if (!stack_entry)
		return -EINVAL;

	boot_data = (struct rogue_mipsfw_boot_data *)(fw_data_ptr + boot_data_entry->alloc_offset +
						      ROGUE_MIPSFW_BOOTLDR_CONF_OFFSET);

	mips_state_data = (struct rogue_mips_state*)(fw_data_ptr + boot_data_entry->alloc_offset +
						      ROGUE_MIPSFW_NMI_SHARED_DATA_BASE);

	WARN_ON(pvr_fw_object_get_dma_addr(fw_dev->mem.data_obj, stack_entry->alloc_offset,
					   &dma_addr));
	boot_data->stack_phys_addr = dma_addr;

	stack_phys_addr_saved = dma_addr;

	boot_data->reg_base = pvr_dev->regs_resource->start;

	for (page_nr = 0; page_nr < ARRAY_SIZE(boot_data->pt_phys_addr); page_nr++) {
		/* Firmware expects 4k pages, but host page size might be different. */
		u32 src_page_nr = (page_nr * ROGUE_MIPSFW_PAGE_SIZE_4K) >> PAGE_SHIFT;
		u32 page_offset = (page_nr * ROGUE_MIPSFW_PAGE_SIZE_4K) & ~PAGE_MASK;

		boot_data->pt_phys_addr[page_nr] = mips_data->pt_dma_addr[src_page_nr] +
						   page_offset;
	}

	boot_data->pt_log2_page_size = ROGUE_MIPSFW_LOG2_PAGE_SIZE_4K;
	boot_data->pt_num_pages = ROGUE_MIPSFW_MAX_NUM_PAGETABLE_PAGES;
	boot_data->reserved1 = 0;
	boot_data->reserved2 = 0;

	//pvr_mips_print_stack();

	return 0;
}

static int
pvr_mips_wrapper_init(struct pvr_device *pvr_dev)
{
	struct pvr_fw_mips_data *mips_data = pvr_dev->fw_dev.processor_data.mips_data;
	const u64 remap_settings = ROGUE_MIPSFW_BOOT_REMAP_LOG2_SEGMENT_SIZE;
	u32 phys_bus_width;

	int err = PVR_FEATURE_VALUE(pvr_dev, phys_bus_width, &phys_bus_width);

	if (WARN_ON(err))
		return err;

	/* Currently MIPS FW only supported with physical bus width > 32 bits. */
	if (WARN_ON(phys_bus_width <= 32))
		return -EINVAL;

	pvr_cr_write32(pvr_dev, ROGUE_CR_MIPS_WRAPPER_CONFIG,
		       (ROGUE_MIPSFW_REGISTERS_VIRTUAL_BASE >>
			ROGUE_MIPSFW_WRAPPER_CONFIG_REGBANK_ADDR_ALIGN) |
		       ROGUE_CR_MIPS_WRAPPER_CONFIG_BOOT_ISA_MODE_MICROMIPS);

	/* Configure remap for boot code, boot data and exceptions code areas. */
	pvr_cr_write64(pvr_dev, ROGUE_CR_MIPS_ADDR_REMAP1_CONFIG1,
		       ROGUE_MIPSFW_BOOT_REMAP_PHYS_ADDR_IN |
		       ROGUE_CR_MIPS_ADDR_REMAP1_CONFIG1_MODE_ENABLE_EN);
	pvr_cr_write64(pvr_dev, ROGUE_CR_MIPS_ADDR_REMAP1_CONFIG2,
		       (mips_data->boot_code_dma_addr &
			~ROGUE_CR_MIPS_ADDR_REMAP1_CONFIG2_ADDR_OUT_CLRMSK) | remap_settings);

	if (PVR_HAS_QUIRK(pvr_dev, 63553)) {
		/*
		 * WA always required on 36 bit cores, to avoid continuous unmapped memory accesses
		 * to address 0x0.
		 */
		WARN_ON(phys_bus_width != 36);

		pvr_cr_write64(pvr_dev, ROGUE_CR_MIPS_ADDR_REMAP5_CONFIG1,
			       ROGUE_CR_MIPS_ADDR_REMAP5_CONFIG1_MODE_ENABLE_EN);
		pvr_cr_write64(pvr_dev, ROGUE_CR_MIPS_ADDR_REMAP5_CONFIG2,
			       (mips_data->boot_code_dma_addr &
				~ROGUE_CR_MIPS_ADDR_REMAP5_CONFIG2_ADDR_OUT_CLRMSK) |
			       remap_settings);
	}

	pvr_cr_write64(pvr_dev, ROGUE_CR_MIPS_ADDR_REMAP2_CONFIG1,
		       ROGUE_MIPSFW_DATA_REMAP_PHYS_ADDR_IN |
		       ROGUE_CR_MIPS_ADDR_REMAP2_CONFIG1_MODE_ENABLE_EN);
	pvr_cr_write64(pvr_dev, ROGUE_CR_MIPS_ADDR_REMAP2_CONFIG2,
		       (mips_data->boot_data_dma_addr &
			~ROGUE_CR_MIPS_ADDR_REMAP2_CONFIG2_ADDR_OUT_CLRMSK) | remap_settings);

	pvr_cr_write64(pvr_dev, ROGUE_CR_MIPS_ADDR_REMAP3_CONFIG1,
		       ROGUE_MIPSFW_CODE_REMAP_PHYS_ADDR_IN |
		       ROGUE_CR_MIPS_ADDR_REMAP3_CONFIG1_MODE_ENABLE_EN);
	pvr_cr_write64(pvr_dev, ROGUE_CR_MIPS_ADDR_REMAP3_CONFIG2,
		       (mips_data->exception_code_dma_addr &
			~ROGUE_CR_MIPS_ADDR_REMAP3_CONFIG2_ADDR_OUT_CLRMSK) | remap_settings);

	/* Garten IDLE bit controlled by MIPS. */
	pvr_cr_write64(pvr_dev, ROGUE_CR_MTS_GARTEN_WRAPPER_CONFIG,
		       ROGUE_CR_MTS_GARTEN_WRAPPER_CONFIG_IDLE_CTRL_META);

	/* Turn on the EJTAG probe. */
	pvr_cr_write32(pvr_dev, ROGUE_CR_MIPS_DEBUG_CONFIG, 0);

	return 0;
}

static u32
pvr_mips_get_fw_addr_with_offset(struct pvr_fw_object *fw_obj, u32 offset)
{
	struct pvr_device *pvr_dev = to_pvr_device(gem_from_pvr_gem(fw_obj->gem)->dev);

	/* MIPS cacheability is determined by page table. */
	return ((fw_obj->fw_addr_offset + offset) & pvr_dev->fw_dev.fw_heap_info.offset_mask) |
	       ROGUE_FW_HEAP_MIPS_BASE;
}

static bool
pvr_mips_has_fixed_data_addr(void)
{
	return true;
}

const struct pvr_fw_defs pvr_fw_defs_mips = {
	.init = pvr_mips_init,
	.fini = pvr_mips_fini,
	.fw_process = pvr_mips_fw_process,
	.vm_map = pvr_vm_mips_map,
	.vm_unmap = pvr_vm_mips_unmap,
	.get_fw_addr_with_offset = pvr_mips_get_fw_addr_with_offset,
	.wrapper_init = pvr_mips_wrapper_init,
	.has_fixed_data_addr = pvr_mips_has_fixed_data_addr,
	.irq = {
		.enable_reg = ROGUE_CR_MIPS_WRAPPER_IRQ_ENABLE,
		.status_reg = ROGUE_CR_MIPS_WRAPPER_IRQ_STATUS,
		.clear_reg = ROGUE_CR_MIPS_WRAPPER_IRQ_CLEAR,
		.event_mask = ROGUE_CR_MIPS_WRAPPER_IRQ_STATUS_EVENT_EN,
		.clear_mask = ROGUE_CR_MIPS_WRAPPER_IRQ_CLEAR_EVENT_EN,
	},
};
