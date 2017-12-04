import time
import angr
import claripy
import simuvex
import logging

start = time.time()



# Specify if thumb2 mode is used
THUMB_MODE = 1

# Stack hardcoded address
STACK_INIT_ADDR = 0x10000
STACK_INIT_SIZE = 0x1000

# Global list of symbolic arguments from entry point
LST_SYM_ARGS = []

# Hardcoded return LR address (We'll use this to search for end of analysis)
RET_LR_ADDR = 0xCAFEBABE

# Hardcoded symbolic memory chunk
SYM_MEM_BUF1 = 0x20000
SYM_MEM_BUF2 = 0x30000

# Hardcoded concrete memory chunk
CONCR_MEM_BUF1 = 0x40000
CONCR_MEM_BUF2 = 0x50000
CONCR_MEM_BUF3 = 0x60000
TEST_STRING = "AAAABBBBCCCCDDDD 111222333"


# tz_mod_MMB29Q syscalls
# - (25, 'tzbsp_nfdbg_config', 0x3801, 0xfe81050e, 6),
# - (29, 'tzbsp_cpu_config_query', 0x406, 0xfe814252, 6),
# - (37, 'tzbsp_smmu_set_pt_mem', 0x3004, 0xfe858746, 5),
# - (38, 'tzbsp_video_set_va_ranges', 0x3008, 0xfe85139e, 4),
# - (39, 'tzbsp_mpu_protect_memory', 0x3001, 0xfe810c3e, 5),
# - (40, 'tzbsp_memprot_lock2', 0x300a, 0xfe859600, 6),
# - (41, 'tzbsp_memprot_map2', 0x300b, 0xfe8596e8, 5),
# - (43, 'tzbsp_memprot_tlbinval', 0x300d, 0xfe8599ac, 6),
# - (50, 'tz_write_hdcp_registers', 0x4401, 0xfe84d96e, 10),
# - (65, 'tzbsp_ssd_decrypt_elf_seg_frag_ns', 0x1c08, 0xfe85d694, 8),
lst_syscalls_MMB29Q = [
                        (0, 'tzbsp_pil_init_image_ns', 0x801, 0xfe84c81a, 2),
                        (1, 'tzbsp_pil_auth_reset_ns', 0x805, 0xfe84ca6a, 1),
                        (2, 'tzbsp_pil_mem_area', 0x802, 0xfe84c284, 3),
                        (3, 'tzbsp_pil_unlock_area', 0x806, 0xfe84c2e6, 1),
                        (4, 'tzbsp_pil_is_subsystem_supported', 0x807, 0xfe84cac4, 3),
                        (5, 'tzbsp_pil_is_subsystem_mandated', 0x808, 0xfe84cb08, 3),
                        (6, 'tzbsp_pil_get_mem_area', 0x809, 0xfe84cb4c, 3),
                        (7, 'tzbsp_write_lpass_qdsp6_nmi', 0xc01, 0xfe8510b4, 1),
                        (8, 'tzbsp_set_cpu_ctx_buf', 0xc02, 0xfe8075dc, 2),
                        (9, 'tzbsp_set_l1_dump_buf', 0xc04, 0xfe80992a, 2),
                        (10, 'tzbsp_query_l1_dump_buf_size', 0xc06, 0xfe8099e6, 3),
                        (11, 'tzbsp_set_l2_dump_buf', 0xc07, 0xfe8062c8, 2),
                        (12, 'tzbsp_query_l2_dump_buf_size', 0xc08, 0xfe806356, 3),
                        (13, 'tzbsp_set_ocmem_dump_buf', 0xc09, 0xfe8517e0, 2),
                        (14, 'tzbsp_query_ocmem_dump_buf_size', 0xc0a, 0xfe851846, 3),
                        (15, 'tzbsp_qfprom_write_row', 0x2003, 0xfe811a68, 4),
                        (16, 'tzbsp_qfprom_write_multiple_rows', 0x2004, 0xfe811b02, 4),
                        (17, 'tzbsp_qfprom_read_row', 0x2005, 0xfe811bd4, 4),
                        (18, 'tzbsp_qfprom_rollback_write_row', 0x2006, 0xfe85a062, 4),
                        (19, 'tzbsp_prng_getdata_syscall', 0x2801, 0xfe810dba, 2),
                        (20, 'tzbsp_resource_config', 0x1002, 0xfe811eca, -1),
                        (21, 'tzbsp_dcvs_create_group', 0x3401, 0xfe810696, -1),
                        (22, 'tzbsp_dcvs_register_core', 0x3402, 0xfe81069a, -1),
                        (23, 'tzbsp_dcvs_set_alg_params', 0x3403, 0xfe81069e, -1),
                        (24, 'tzbsp_dcvs_init', 0x3405, 0xfe810692, -1),
                        (25, 'tzbsp_nfdbg_config', 0x3801, 0xfe81050e, 4),
                        (26, 'tzbsp_nfdbg_ctx_size', 0x3802, 0xfe8105e8, 2),
                        (27, 'tzbsp_nfdbg_is_int_ok', 0x3803, 0xfe81060c, 3),
                        (28, 'tzbsp_cpu_config', 0x405, 0xfe81423c, 2),
                        (29, 'tzbsp_cpu_config_query', 0x406, 0xfe814252, 4),
                        (30, 'tzbsp_ocmem_lock_region', 0x3c01, 0xfe858a9e, 4),
                        (31, 'tzbsp_ocmem_unlock_region', 0x3c02, 0xfe858d5c, 3),
                        (32, 'tzbsp_ocmem_enable_mem_dump', 0x3c03, 0xfe858f32, 3),
                        (33, 'tzbsp_ocmem_disable_mem_dump', 0x3c04, 0xfe858fd4, 3),
                        (34, 'tzbsp_get_secure_state', 0x1804, 0xfe85b8b4, 2),
                        (35, 'tzbsp_smmu_set_cp_pool_size', 0x3005, 0xfe8586ca, 4),
                        (36, 'tzbsp_smmu_get_pt_size', 0x3003, 0xfe858700, 3),
                        (37, 'tzbsp_smmu_set_pt_mem', 0x3004, 0xfe858746, 4),
                        (38, 'tzbsp_video_set_va_ranges', 0x3008, 0xfe85139e, 4),
                        (39, 'tzbsp_mpu_protect_memory', 0x3001, 0xfe810c3e, 4),
                        (40, 'tzbsp_memprot_lock2', 0x300a, 0xfe859600, 4),
                        (41, 'tzbsp_memprot_map2', 0x300b, 0xfe8596e8, 4),
                        (42, 'tzbsp_memprot_unmap2', 0x300c, 0xfe8598e8, 4),
                        (43, 'tzbsp_memprot_tlbinval', 0x300d, 0xfe8599ac, 4),
                        (44, 'tzbsp_memprot_sd_ctrl', 0x300f, 0xfe859a26, 3),
                        (45, 'tzbsp_vmidmt_set_memtype', 0x3009, 0xfe847c44, 3),
                        (46, 'tzbsp_xpu_config_violation_err_fatal', 0x300e, 0xfe846378, 4),
                        (47, 'tzbsp_smmu_fault_regs_dump', 0xc0c, 0xfe8587f6, 4),
                        (48, 'tzbsp_graphics_dcvs_init', 0x3406, 0xfe8103b0, 1),
                        (49, 'tzbsp_video_set_state', 0x40a, 0xfe8514e8, 4),
                        (50, 'tz_write_hdcp_registers', 0x4401, 0xfe84d96e, 4),
                        (51, 'tzbsp_set_boot_addr', 0x401, 0xfe811212, 2),
                        (52, 'tzbsp_milestone_set', 0x403, 0xfe811282, 2),
                        (53, 'tzbsp_wdt_disable', 0x407, 0xfe80a24e, 1),
                        (54, 'config_hw_for_offline_ram_dump', 0x409, 0xfe80a2a8, 2),
                        (55, 'tzbsp_wdt_trigger', 0x408, 0xfe80a274, 1),
                        (56, 'tzbsp_is_service_available', 0x1801, 0xfe8081b4, 3),
                        (57, 'tzbsp_exec_smc', 0x3f001, 0xfe808540, 2),
                        (58, 'tzbsp_exec_smc_ext', 0x3e801, 0xfe80855a, 3),
                        (59, 'tzbsp_tzos_smc', 0x3f401, 0xfe808574, 4),
                        (60, 'tzbsp_ssd_decrypt_img_ns', 0x1c01, 0xfe85d78e, 4),
                        (61, 'ks_ns_encrypt_keystore_ns', 0x1c02, 0xfe85d046, 2),
                        (62, 'tzbsp_ssd_protect_keystore_ns', 0x1c05, 0xfe85d822, 4),
                        (63, 'tzbsp_ssd_parse_md_ns', 0x1c06, 0xfe85d61e, 4),
                        (64, 'tzbsp_ssd_decrypt_img_frag_ns', 0x1c07, 0xfe85d776, 2),
                        (65, 'tzbsp_ssd_decrypt_elf_seg_frag_ns', 0x1c08, 0xfe85d694, 4),
                        (66, 'tz_blow_sw_fuse', 0x2001, 0xfe853d18, 1),
                        (67, 'tz_is_sw_fuse_blown', 0x2002, 0xfe853cd4, 3),
                        (68, 'tzbsp_get_diag', 0x1802, 0xfe812fec, 2),
                        (69, 'tzbsp_es_save_partition_hash', 0x4001, 0xfe8144f2, 2),
                        (70, 'tzbsp_es_is_activated', 0x4002, 0xfe8144ee, -1),
                        (71, 'tzbsp_sec_cfg_restore', 0x3002, 0xfe811e1c, 2),
                        (72, 'tzbsp_fver_get_version', 0x1803, 0xfe84f9a0, 3),
                        (73, 'tzbsp_security_allows_mem_dump', 0xc0b, 0xfe811176, 2),
                        (74, 'tzbsp_is_retail_unlock_enable', 0xc0d, 0xfe8111b2, 2),
                        (75, 'tzbsp_spin_irqs_fiqs_masked_ns', 0x40d, 0xfe8111d6, -1),
                        (76, 'motorola_tzbsp_ns_service', 0x3f801, 0xfc865ee, 4),
                      ]


# tz_mod_MOB31S syscalls
# - (25, 'tzbsp_nfdbg_config', 0x3801, 0xfe81050e, 6),
# - (29, 'tzbsp_cpu_config_query', 0x406, 0xfe814298, 6),
# - (30, 'tzbsp_ocmem_lock_region', 0x3c01, 0xfe8590b6, 6),
# - (38, 'tzbsp_video_set_va_ranges', 0x3008, 0xfe8519ae, 6),
# - (40, 'tzbsp_memprot_lock2', 0x300a, 0xfe859c1e, 6),
# - (50, 'tz_write_hdcp_registers', 0x4401, 0xfe84df6e, 10),
# - (65, 'tzbsp_ssd_decrypt_elf_seg_frag_ns', 0x1c08, 0xfe85dcb4, 8),
lst_syscalls_MOB31S = [
                        (0, 'tzbsp_pil_init_image_ns', 0x801, 0xfe84ce1a, 4),
                        (1, 'tzbsp_pil_auth_reset_ns', 0x805, 0xfe84d06a, 4),
                        (2, 'tzbsp_pil_mem_area', 0x802, 0xfe84c884, 3),
                        (3, 'tzbsp_pil_unlock_area', 0x806, 0xfe84c8e6, 1),
                        (4, 'tzbsp_pil_is_subsystem_supported', 0x807, 0xfe84d0c4, 4),
                        (5, 'tzbsp_pil_is_subsystem_mandated', 0x808, 0xfe84d108, 4),
                        (6, 'tzbsp_pil_get_mem_area', 0x809, 0xfe84d14c, 3),
                        (7, 'tzbsp_write_lpass_qdsp6_nmi', 0xc01, 0xfe8516c4, -1),
                        (8, 'tzbsp_set_cpu_ctx_buf', 0xc02, 0xfe8075dc, 2),
                        (9, 'tzbsp_set_l1_dump_buf', 0xc04, 0xfe80992a, 2),
                        (10, 'tzbsp_query_l1_dump_buf_size', 0xc06, 0xfe8099e6, 3),
                        (11, 'tzbsp_set_l2_dump_buf', 0xc07, 0xfe8062c8, 2),
                        (12, 'tzbsp_query_l2_dump_buf_size', 0xc08, 0xfe806356, 3),
                        (13, 'tzbsp_set_ocmem_dump_buf', 0xc09, 0xfe851df0, 2),
                        (14, 'tzbsp_query_ocmem_dump_buf_size', 0xc0a, 0xfe851e56, 3),
                        (15, 'tzbsp_qfprom_write_row', 0x2003, 0xfe811a68, 4),
                        (16, 'tzbsp_qfprom_write_multiple_rows', 0x2004, 0xfe811b02, 4),
                        (17, 'tzbsp_qfprom_read_row', 0x2005, 0xfe811c00, 4),
                        (18, 'tzbsp_qfprom_rollback_write_row', 0x2006, 0xfe85a682, 4),
                        (19, 'tzbsp_prng_getdata_syscall', 0x2801, 0xfe810dba, 2),
                        (20, 'tzbsp_resource_config', 0x1002, 0xfe811ef6, -1),
                        (21, 'tzbsp_dcvs_create_group', 0x3401, 0xfe810696, -1),
                        (22, 'tzbsp_dcvs_register_core', 0x3402, 0xfe81069a, -1),
                        (23, 'tzbsp_dcvs_set_alg_params', 0x3403, 0xfe81069e, -1),
                        (24, 'tzbsp_dcvs_init', 0x3405, 0xfe810692, -1),
                        (25, 'tzbsp_nfdbg_config', 0x3801, 0xfe81050e, 6),
                        (26, 'tzbsp_nfdbg_ctx_size', 0x3802, 0xfe8105e8, 2),
                        (27, 'tzbsp_nfdbg_is_int_ok', 0x3803, 0xfe81060c, 3),
                        (28, 'tzbsp_cpu_config', 0x405, 0xfe814282, 2),
                        (29, 'tzbsp_cpu_config_query', 0x406, 0xfe814298, 4),
                        (30, 'tzbsp_ocmem_lock_region', 0x3c01, 0xfe8590b6, 4),
                        (31, 'tzbsp_ocmem_unlock_region', 0x3c02, 0xfe85937a, 3),
                        (32, 'tzbsp_ocmem_enable_mem_dump', 0x3c03, 0xfe859550, 3),
                        (33, 'tzbsp_ocmem_disable_mem_dump', 0x3c04, 0xfe8595f2, 3),
                        (34, 'tzbsp_get_secure_state', 0x1804, 0xfe85bed4, 2),
                        (35, 'tzbsp_smmu_set_cp_pool_size', 0x3005, 0xfe858cd0, 4),
                        (36, 'tzbsp_smmu_get_pt_size', 0x3003, 0xfe858d06, 3),
                        (37, 'tzbsp_smmu_set_pt_mem', 0x3004, 0xfe858d4c, 4),
                        (38, 'tzbsp_video_set_va_ranges', 0x3008, 0xfe8519ae, 4),
                        (39, 'tzbsp_mpu_protect_memory', 0x3001, 0xfe810c3e, 4),
                        (40, 'tzbsp_memprot_lock2', 0x300a, 0xfe859c1e, 4),
                        (41, 'tzbsp_memprot_map2', 0x300b, 0xfe859d06, 4),
                        (42, 'tzbsp_memprot_unmap2', 0x300c, 0xfe859f06, 4),
                        (43, 'tzbsp_memprot_tlbinval', 0x300d, 0xfe859fca, 4),
                        (44, 'tzbsp_memprot_sd_ctrl', 0x300f, 0xfe85a044, 3),
                        (45, 'tzbsp_vmidmt_set_memtype', 0x3009, 0xfe847c44, 3),
                        (46, 'tzbsp_xpu_config_violation_err_fatal', 0x300e, 0xfe846378, 4),
                        (47, 'tzbsp_smmu_fault_regs_dump', 0xc0c, 0xfe858dfc, 4),
                        (48, 'tzbsp_graphics_dcvs_init', 0x3406, 0xfe8103b0, 4),
                        (49, 'tzbsp_video_set_state', 0x40a, 0xfe851af8, 4),
                        (50, 'tz_write_hdcp_registers', 0x4401, 0xfe84df6e, 4),
                        (51, 'tzbsp_set_boot_addr', 0x401, 0xfe811212, 2),
                        (52, 'tzbsp_milestone_set', 0x403, 0xfe811282, 2),
                        (53, 'tzbsp_wdt_disable', 0x407, 0xfe80a24e, 1),
                        (54, 'config_hw_for_offline_ram_dump', 0x409, 0xfe80a2a8, 2),
                        (55, 'tzbsp_wdt_trigger', 0x408, 0xfe80a274, 1),
                        (56, 'tzbsp_is_service_available', 0x1801, 0xfe8081b4, 3),
                        (57, 'tzbsp_exec_smc', 0x3f001, 0xfe808540, 2),
                        (58, 'tzbsp_exec_smc_ext', 0x3e801, 0xfe80855a, 2),
                        (59, 'tzbsp_tzos_smc', 0x3f401, 0xfe808574, 3),
                        (60, 'tzbsp_ssd_decrypt_img_ns', 0x1c01, 0xfe85ddae, 4),
                        (61, 'ks_ns_encrypt_keystore_ns', 0x1c02, 0xfe85d666, 4),
                        (62, 'tzbsp_ssd_protect_keystore_ns', 0x1c05, 0xfe85de42, 4),
                        (63, 'tzbsp_ssd_parse_md_ns', 0x1c06, 0xfe85dc3e, 4),
                        (64, 'tzbsp_ssd_decrypt_img_frag_ns', 0x1c07, 0xfe85dd96, 4),
                        (65, 'tzbsp_ssd_decrypt_elf_seg_frag_ns', 0x1c08, 0xfe85dcb4, 4),
                        (66, 'tz_blow_sw_fuse', 0x2001, 0xfe854328, 1),
                        (67, 'tz_is_sw_fuse_blown', 0x2002, 0xfe8542e4, 3),
                        (68, 'tzbsp_get_diag', 0x1802, 0xfe813018, 2),
                        (69, 'tzbsp_es_save_partition_hash', 0x4001, 0xfe814536, 4),
                        (70, 'tzbsp_es_is_activated', 0x4002, 0xfe814532, -1),
                        (71, 'tzbsp_sec_cfg_restore', 0x3002, 0xfe811e48, 2),
                        (72, 'tzbsp_fver_get_version', 0x1803, 0xfe84ffa0, 3),
                        (73, 'tzbsp_security_allows_mem_dump', 0xc0b, 0xfe811176, 2),
                        (74, 'tzbsp_is_retail_unlock_enable', 0xc0d, 0xfe8111b2, 2),
                        (75, 'tzbsp_spin_irqs_fiqs_masked_ns', 0x40d, 0xfe8111d6, -1),
                        (76, 'motorola_tzbsp_ns_service', 0x3f801, 0xfc865ee, 1),
                      ]


def IP(ip):
    return ip + THUMB_MODE


def is_mem_on_stack(mem):
    return mem >= STACK_INIT_ADDR - STACK_INIT_SIZE and mem <= STACK_INIT_ADDR


def is_addr_tainted(state, addr):
    lst_vars = map(lambda x:x.split('_')[0], list(state.se.variables(addr)))
    for s in LST_SYM_ARGS:
        if s.args[0].split('_')[0] in lst_vars:
            return True
    return False


def check_for_symb_eip(pg):
    if len(pg.unconstrained) > 0:
        print '\n[+] *** Symbolic EIP: %08x' % (pg.unconstrained[0].state.ip.args[0])
        exit()


def track_memreads(state):
    addr = state.inspect.mem_read_address
    
    # Skip if the memory read is a stash pop operation
    # @TODO: stack memory disclosure?
    if addr.concrete and is_mem_on_stack(addr.args[0]):
        return
    
    # POTENTIAL VULN: Symbolic memory read address
    if not addr.concrete and is_addr_tainted(state, addr):
        
        # Make a copy so that our added constraints won't affect subsequent operations
        state2 = state.copy()
        addr2 = state2.inspect.mem_read_address
        
        # We want the memory read to be possible within the TZ memory region (sensitive areas)
        state2.add_constraints(addr2 >= 0xfe82eca8)
        state2.add_constraints(addr2 <= 0xfe82eea8)
        
        if not state2.satisfiable():
            #print '\n[+] *** Symbolic memory read addr [%08x] ==> UNSATISFIABLE!' % state2.ip.args[0]
            return
    
        print '\n[+] *** Symbolic memory read addr'
        print '[-]   [%08x] BP:Read' % (state.ip.args[0]), state.inspect.mem_read_expr, 'from', state.inspect.mem_read_address
        print state.se.variables(addr)
        print_constraints(state)
        print '[-]   ---'
        print '[-]   Concretize[addr_write]:', hex(state2.se.any_int(addr2))


def track_memwrites(state):
    addr = state.inspect.mem_write_address
    
    # Skip if the memory write is a stash push operation
    # @TODO: stack overflow?
    if addr.concrete and is_mem_on_stack(addr.args[0]):
        return
    
    # POTENTIAL VULN: Symbolic memory write address
    if not addr.concrete and is_addr_tainted(state, addr):
        
        # Make a copy so that our added constraints won't affect subsequent operations
        state2 = state.copy()
        addr2 = state2.inspect.mem_write_address
        
        # We want the memory write to be possible within the TZ memory region (sensitive areas)
        state2.add_constraints(addr2 >= 0xfe82eca8)
        state2.add_constraints(addr2 <= 0xfe82eea8)
        
        if not state2.satisfiable():
            #print '\n[+] *** Symbolic memory write addr [%08x] ==> UNSATISFIABLE!' % state2.ip.args[0]
            return
        
        print '\n[+] *** Symbolic memory write addr'
        print '[-]   [%08x] BP:Write' % (state2.ip.args[0]), state2.inspect.mem_write_expr, 'to', state2.inspect.mem_write_address
        print state.se.variables(addr)
        print_constraints(state)
        print '[-]   ---'
        print '[-]   Concretize[addr_write]:', hex(state2.se.any_int(addr2))


def track_constraints(state):
    lst_cons = state.inspect.added_constraints
    for c in lst_cons:
        b = c.args[0]
        if b != True and b != False:
            print '[track_constraints][%x]:' % (state.ip.args[0]), c


def print_addr_trace(path):
    for i, eip in enumerate(path.addr_trace.hardcopy):
        print '   path.edge[%d]' % i, hex(eip)


def print_constraints(state):
    print '[-]   ---'
    for i, c in enumerate(state.se.constraints):
        print '[-]   Constraint[%d]:' % i, list(state.se.variables(c))
        print '          ', c
    print '[-]   ---'
    for i, a in enumerate(LST_SYM_ARGS):
        print '[-]   Concretize[%s]:' % (a.args[0]), hex(state.se.any_int(a))


def hook_simple_ret(proj, addr_fr, addr_to, retval):
    """ Hook a given function and have it return a specified value using R0.
    """
    def set_r0(state, val=retval):
        state.regs.r0=val
    proj.hook(addr_fr, set_r0, length=addr_to-addr_fr)


def get_nargs(proj, eip):
    b = proj.factory.block(addr=eip)
    insn = b.capstone.insns[0].insn
    
    # Error if it's not a push instruction
    if not 'push' in insn.insn_name():
        print '[-]   get_nargs: EIP:%08x instruction is not a PUSH' % (eip)
        return -1
    
    o = insn.operands[0]
    
    # Error if it's not pushing a register
    if o.type != 1:
        print '[-]   get_nargs: EIP:%08x instruction does not use a register operand' % (eip)
        return -1
    
    # Error if register is not what we expect
    if o.value.reg > 70:
        print '[-]   get_nargs: EIP:%08x instruction uses a register operand > R4: %d' % (eip, o.value.reg)
        return -1
    
    # 66:R0, 67:R1, 68:R2, 69:R3, 70:R4
    return o.value.reg - 66


def test_explore(eip_start, fw_fname, nargs, hooks=[], eip_find=IP(RET_LR_ADDR), eip_avoid=[]):
    global LST_SYM_ARGS
    
    # Load binary
    proj = angr.Project(fw_fname)
    
    # Start with a blank state
    state = proj.factory.blank_state(addr=eip_start,
                                     remove_options={simuvex.o.LAZY_SOLVES})
    
    # Init tainted states
    for i in xrange(nargs):
        if i == 0:
            state.regs.r0 = state.se.BVS("arg1", 32)
            LST_SYM_ARGS.append(state.regs.r0)
        if i == 1:
            state.regs.r1 = state.se.BVS("arg2", 32)
            LST_SYM_ARGS.append(state.regs.r1)
        if i == 2:
            state.regs.r2 = state.se.BVS("arg3", 32)
            LST_SYM_ARGS.append(state.regs.r2)
        if i == 3:
            state.regs.r3 = state.se.BVS("arg4", 32)
            LST_SYM_ARGS.append(state.regs.r3)
    
    # Init stack and return address
    state.regs.sp = STACK_INIT_ADDR
    state.regs.lr = IP(RET_LR_ADDR)
    
    # Hook those functions where we know there is no value to explore
    for h_func, h_fr, h_to, retval in hooks:
        h_func(proj, h_fr, h_to, retval)
    
    # Track memory operations
    #state.inspect.b('constraints', when=simuvex.BP_AFTER, action=track_constraints)
    state.inspect.b('mem_read', when=simuvex.BP_AFTER, action=track_memreads)
    state.inspect.b('mem_write', when=simuvex.BP_AFTER, action=track_memwrites)
    
    # Init a path group for path exploration
    # (Make it mutable so that the path exploration can be interrupted, and 
    # less resources)
    path = proj.factory.path(state=state, immutable=False)
    
    # Call explorer to execute the function
    # Note that Veritesting is important since we want to avoid unnecessary branching
    ex = angr.surveyors.Explorer(proj, start=path, find=(eip_find,), avoid=eip_avoid, enable_veritesting=False)
    
    # Continue to explore all paths until we reach our desired code location
    r = ex.run()
    cnt = 1
    while r.active:
        print '\n[+] -------------------------------[ Exploring path %d:' % cnt
        r = ex.run()
        cnt += 1
        
        # POTENTIAL VULN: Check for symbolic EIP
        check_for_symb_eip(r)
    
    # Continue to explore all paths until we reach our desired code location
    """
    pg = proj.factory.path_group(state, immutable=False)
    cnt = 1
    while pg.active:
        print '\n[+] -------------------------------[ Exploring path %d:' % cnt
        pg.explore(find=eip_find, avoid=eip_avoid)
        cnt += 1
        
        # POTENTIAL VULN: Check for symbolic EIP
        check_for_symb_eip(pg)
    """


def get_syscalls(fw_fname='tz_mod_MMB29Q.mbn', g_syscall_table=0xFE82B01C):
    proj = angr.Project(fw_fname)
    state = proj.factory.entry_state()
    simuvex.s_type.define_struct('struct tzbsp_syscall_slot_t { int id; int name; int flags; unsigned int func; int nargs; }')
    
    addr = g_syscall_table
    entry = state.mem[addr].tzbsp_syscall_slot_t
    cnt = 0
    lst_syscalls = []
    
    while entry.id.concrete != 0:
        #print '[%02d] %s -- id:%x -- func:%x' % (cnt, entry.name.deref.string.concrete, entry.id.concrete, entry.func.concrete)
        print '(%d, \'%s\', 0x%x, 0x%x, %d),' % (cnt, entry.name.deref.string.concrete, entry.id.concrete, entry.func.concrete-1, entry.nargs.concrete)
        lst_syscalls.append((entry.name.deref.string.concrete, entry.id.concrete, entry.func.concrete-1))
        addr = addr + ((5 + entry.nargs.concrete) * 4)
        entry = state.mem[addr].tzbsp_syscall_slot_t
        cnt += 1
    
    return lst_syscalls


def test_firmware(is_old=True):
    if is_old:
        hooks = [
                (hook_simple_ret, IP(0xFE812CD0), IP(0xFE812D02), 1),        # is_debugging_disabled
                (hook_simple_ret, IP(0xFE815E90), IP(0xFE815EC0), 1),        # is_disallowed_range   => False (not disallowed)
                (hook_simple_ret, IP(0xFE807DA2), IP(0xFE807DEA), 0),        # is_qsee_not_in_region => True (not blacklisted)
                ]
        lst_syscalls = lst_syscalls_MMB29Q
        fw_fname = 'tz_mod_MMB29Q.mbn'
    else:
        hooks = [
                (hook_simple_ret, IP(0xFE812CFC), IP(0xFE812D2E), 1),        # is_debugging_disabled
                (hook_simple_ret, IP(0xFE815EBE), IP(0xFE815F00), 1),        # is_disallowed_range   => False (not disallowed)
                (hook_simple_ret, IP(0xFE807DA2), IP(0xFE807DEA), 0),        # is_qsee_not_in_region => True (not blacklisted)
                ]
        lst_syscalls = lst_syscalls_MOB31S
        fw_fname='tz_mod_MOB31S.mbn'
    
    for i, name, _, func, nargs in lst_syscalls:
        if nargs == -1:
            print '\n[+] [%02d] Skipping: %s -- func:%x' % (i, name, func)
            continue
        
        if i < 47 or i > 48:
            continue
        print '\n[+] [%02d] Checking: %s -- func:%x, nargs:%d' % (i, name, func, nargs)
        test_explore(eip_start=IP(func), fw_fname=fw_fname, hooks=hooks, nargs=nargs)


def track_addrconcrete(state):
    mem = state.inspect.address_concretization_memory
    print '\n----track_addrconcrete: %s [0x%08x]' % (state.inspect.address_concretization_action, state.ip.args[0])
    print state.inspect.address_concretization_strategy
    print mem
    print state.inspect.address_concretization_expr
    print state.inspect.address_concretization_strategy.concretize(mem, state.inspect.address_concretization_expr)
    print hex(state.se.min(state.inspect.address_concretization_expr)), hex(state.se.max(state.inspect.address_concretization_expr))


def get_nargs_heuristics():
    """ Infer number of arguments based on number of tainted constraints.
    """
    pass


def wv_explore():
    global LST_SYM_ARGS
    
    ### SETTINGS <<<
    #   0xF54 - handle_5x_cmd
    fw_fname = 'widevine_MMB29Q.mbn'            # widevine_MRA58K
    start_addr = 0x1FEC
    ### SETTINGS <<<
    
    # Load project
    proj = angr.Project(fw_fname)
    state = proj.factory.blank_state(addr=start_addr, remove_options={simuvex.o.LAZY_SOLVES})
    
    # Add symbolic args
    in_sym_mem_len = 0x3000
    in_sym_mem = state.se.BVS("arg1_mem", 8 * in_sym_mem_len)
    state.memory.store(SYM_MEM_BUF1, in_sym_mem)
    out_sym_mem_len = 0x128
    out_sym_mem = state.se.BVS("arg1_mem", 8 * out_sym_mem_len)
    state.memory.store(SYM_MEM_BUF2, out_sym_mem)
    LST_SYM_ARGS.append(in_sym_mem)
    LST_SYM_ARGS.append(out_sym_mem)
    
    # Init stack and return address
    state.regs.r0 = SYM_MEM_BUF1
    state.regs.r1 = in_sym_mem_len
    state.regs.r2 = SYM_MEM_BUF2
    state.regs.r3 = out_sym_mem_len
    state.regs.sp = STACK_INIT_ADDR
    state.regs.lr = RET_LR_ADDR
    
    # hooks
    '''
    hook_simple_ret(proj, IP(0x4DA0), IP(0x4DE2), 1)        # qsee_log
    hook_simple_ret(proj, IP(0x744), IP(0x75E), 0)          # get_secapi_hnd
    hook_simple_ret(proj, IP(0x7F2), IP(0x80A), 0)          # secapi_delete
    hook_simproc(proj, 0x27074, 0x27144, 'memcpy', libname='tz_arm32')
    hook_simproc(proj, IP(0x26F48), IP(0x26F80), 'strlen', libname='tz_arm32')
    hook_simproc(proj, IP(0x27236), IP(0x27274), 'memset2', libname='tz_arm32')
    hook_simproc(proj, IP(0xDE2), IP(0xDF2), 'malloc', libname='tz_arm32')
    hook_simproc(proj, IP(0xDF6), IP(0xE06), 'free', libname='tz_arm32')
    '''
    hook_simple_ret(proj, IP(0x4DA0), IP(0x4DE2), 1)
    hook_simple_ret(proj, IP(0x744), IP(0x75E), 0)          # get_secapi_hnd
    hook_simple_ret(proj, IP(0x7F2), IP(0x80A), 0)          # secapi_delete
    hook_simproc(proj, 0x271B0, 0x27280, 'memcpy', libname='tz_arm32')
    hook_simproc(proj, IP(0x27084), IP(0x270BC), 'strlen', libname='tz_arm32')
    hook_simproc(proj, IP(0x27372), IP(0x273B0), 'memset2', libname='tz_arm32')
    hook_simproc(proj, IP(0xDE2), IP(0xDF2), 'malloc', libname='tz_arm32')
    hook_simproc(proj, IP(0xDF6), IP(0xE06), 'free', libname='tz_arm32')
    hook_simple_ret(proj, 0x27B68, 0x27B84, 0)              # qsee_syscall
    
    
    # breakpoints
    #state.inspect.b('address_concretization', when=simuvex.BP_AFTER, action=track_addrconcrete)
    state.inspect.b('mem_write', when=simuvex.BP_AFTER, action=track_memwrites)
    
    pg = proj.factory.path_group(state, immutable=False, hierarchy=False, veritesting=True)
    cnt = 1
    n_found = 0
    
    '''
    #////////
    pg.explore(find=(0x5B48,), avoid=RET_LR_ADDR)
    s = pg.found[0].state
    #print s.regs.r0
    #print s.regs.r1
    #print s.regs.r2
    #print s.se.constraints
    #print '----'
    #print s.memory.load(s.regs.r0.args[0])
    return
    #////////
    '''
    
    while pg.active:
        print '\n[+] -------------------------------[ Iteration %d:' % cnt
        pg.explore(find=(RET_LR_ADDR,))
        print pg
        
        # clear paths that don't need exploring
        n_found += len(pg.found)
        pg.stashes['found'] = []
        pg.stashes['errored'] = []
        pg.stashes['deadended'] = []
        
        # POTENTIAL VULN: Check for symbolic EIP
        check_for_symb_eip(pg)
        cnt += 1


def test_callable():
    def call(fn, *kwargs):
        res = fn(kwargs)
        if res.concrete:
            return fn(kwargs).args[0]
        return fn(kwargs)
    proj = angr.Project('widevine_MRA58K.mbn')
    s = proj.factory.blank_state()
    fn = proj.factory.callable(addr=IP(0xDE2), base_state=s)
    
    #sym_mem = claripy.BVS("arg1_mem", 8 * 2)
    #s.inspect.b('address_concretization', when=simuvex.BP_AFTER, action=track_addrconcrete)
    
    #s.memory.store(CONCR_MEM_BUF1, TEST_STRING + '\x00')
    #s.memory.store(CONCR_MEM_BUF2, '\x00' * (len(TEST_STRING) + 1))
    #call(fn, CONCR_MEM_BUF2, CONCR_MEM_BUF1, 1, CONCR_MEM_BUF3)
    #print s.mem[CONCR_MEM_BUF1].string.concrete
    #print s.mem[CONCR_MEM_BUF2].string.concrete
    
    print call(fn, 0x10)



def hook_simproc(proj, addr_fr, addr_to, proc_type, libname='libc.so.6'):
    """ Hook a given function using a predesignated SimProcedure.
    """
    proj.hook(addr_fr, angr.Hook(simuvex.SimProcedures[libname][proc_type]), length=addr_to-addr_fr)



def test_hooks():
    proj = angr.Project('widevine_MRA58K.mbn')
    s = proj.factory.blank_state(addr=IP(0xDE2), remove_options={simuvex.o.LAZY_SOLVES})
    
    #s.memory.store(CONCR_MEM_BUF1, TEST_STRING + '\x00')
    #s.memory.store(CONCR_MEM_BUF2, '\x00' * (len(TEST_STRING) + 1))
    
    #print 'BEFORE:'
    #print '\t[1]', s.mem[CONCR_MEM_BUF1].string
    #print '\t   ', s.mem[CONCR_MEM_BUF1].string.concrete
    #print '\t[2]', s.mem[CONCR_MEM_BUF2].string
    #print '\t   ', s.mem[CONCR_MEM_BUF2].string.concrete
    
    #sym_mem = claripy.BVS("arg1_mem", 8 * 16)
    #s.memory.store(CONCR_MEM_BUF1, sym_mem)
    
    #s.regs.r0 = CONCR_MEM_BUF1
    #s.regs.r1 = 6
    #s.regs.r1 = CONCR_MEM_BUF1
    #s.regs.r2 = len(TEST_STRING) + 1
    
    s.regs.r0 = claripy.BVS("arg1_mem", 8 * 2)
    s.regs.sp = STACK_INIT_ADDR
    s.regs.lr = RET_LR_ADDR
    
    #hook_simproc(proj, 0x27074, 0x27144, 'memcpy', libname='tz_arm32')
    #hook_simproc(proj, IP(0x26F48), IP(0x26F80), 'strlen', libname='tz_arm32')
    #hook_simproc(proj, IP(0x27236), IP(0x27274), 'memset2', libname='tz_arm32')
    hook_simproc(proj, IP(0xde2), IP(0xdf2), 'malloc', libname='tz_arm32')
    
    pg = proj.factory.path_group(s, immutable=False, hierarchy=False, veritesting=True)
    pg.explore(find=(RET_LR_ADDR,))
    
    s = pg.found[0].state
    print s.regs.r0
    print s.se.symbolic(s.regs.r0)
    
    #print 'AFTER:'
    #print '\t[1]', s.mem[CONCR_MEM_BUF1].string
    #print '\t   ', s.mem[CONCR_MEM_BUF1].string.concrete
    #print '\t[2]', s.mem[CONCR_MEM_BUF2].string
    #print '\t   ', s.mem[CONCR_MEM_BUF2].string.concrete


#==============================================================================
if __name__ == '__main__':
    
    wv_explore()
    #test_callable()
    #test_hooks()
    
    print 'Time elapsed: %f sec' % (time.time() - start)