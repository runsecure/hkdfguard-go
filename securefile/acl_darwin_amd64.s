// Trampolines to the libSystem ACL functions acl_darwin.go calls, made as golang.org/x/sys/unix
// (zsyscall_darwin_amd64.s) makes them for its libc calls.

//go:build darwin && amd64

#include "textflag.h"

TEXT libc_acl_get_link_np_trampoline<>(SB),NOSPLIT,$0-0
	JMP	libc_acl_get_link_np(SB)
GLOBL	·libc_acl_get_link_np_trampoline_addr(SB), RODATA, $8
DATA	·libc_acl_get_link_np_trampoline_addr(SB)/8, $libc_acl_get_link_np_trampoline<>(SB)

TEXT libc_acl_get_entry_trampoline<>(SB),NOSPLIT,$0-0
	JMP	libc_acl_get_entry(SB)
GLOBL	·libc_acl_get_entry_trampoline_addr(SB), RODATA, $8
DATA	·libc_acl_get_entry_trampoline_addr(SB)/8, $libc_acl_get_entry_trampoline<>(SB)

TEXT libc_acl_get_tag_type_trampoline<>(SB),NOSPLIT,$0-0
	JMP	libc_acl_get_tag_type(SB)
GLOBL	·libc_acl_get_tag_type_trampoline_addr(SB), RODATA, $8
DATA	·libc_acl_get_tag_type_trampoline_addr(SB)/8, $libc_acl_get_tag_type_trampoline<>(SB)

TEXT libc_acl_get_flagset_np_trampoline<>(SB),NOSPLIT,$0-0
	JMP	libc_acl_get_flagset_np(SB)
GLOBL	·libc_acl_get_flagset_np_trampoline_addr(SB), RODATA, $8
DATA	·libc_acl_get_flagset_np_trampoline_addr(SB)/8, $libc_acl_get_flagset_np_trampoline<>(SB)

TEXT libc_acl_get_flag_np_trampoline<>(SB),NOSPLIT,$0-0
	JMP	libc_acl_get_flag_np(SB)
GLOBL	·libc_acl_get_flag_np_trampoline_addr(SB), RODATA, $8
DATA	·libc_acl_get_flag_np_trampoline_addr(SB)/8, $libc_acl_get_flag_np_trampoline<>(SB)

TEXT libc_acl_get_permset_trampoline<>(SB),NOSPLIT,$0-0
	JMP	libc_acl_get_permset(SB)
GLOBL	·libc_acl_get_permset_trampoline_addr(SB), RODATA, $8
DATA	·libc_acl_get_permset_trampoline_addr(SB)/8, $libc_acl_get_permset_trampoline<>(SB)

TEXT libc_acl_get_perm_np_trampoline<>(SB),NOSPLIT,$0-0
	JMP	libc_acl_get_perm_np(SB)
GLOBL	·libc_acl_get_perm_np_trampoline_addr(SB), RODATA, $8
DATA	·libc_acl_get_perm_np_trampoline_addr(SB)/8, $libc_acl_get_perm_np_trampoline<>(SB)

TEXT libc_acl_get_qualifier_trampoline<>(SB),NOSPLIT,$0-0
	JMP	libc_acl_get_qualifier(SB)
GLOBL	·libc_acl_get_qualifier_trampoline_addr(SB), RODATA, $8
DATA	·libc_acl_get_qualifier_trampoline_addr(SB)/8, $libc_acl_get_qualifier_trampoline<>(SB)

TEXT libc_acl_free_trampoline<>(SB),NOSPLIT,$0-0
	JMP	libc_acl_free(SB)
GLOBL	·libc_acl_free_trampoline_addr(SB), RODATA, $8
DATA	·libc_acl_free_trampoline_addr(SB)/8, $libc_acl_free_trampoline<>(SB)

TEXT libc_mbr_uuid_to_id_trampoline<>(SB),NOSPLIT,$0-0
	JMP	libc_mbr_uuid_to_id(SB)
GLOBL	·libc_mbr_uuid_to_id_trampoline_addr(SB), RODATA, $8
DATA	·libc_mbr_uuid_to_id_trampoline_addr(SB)/8, $libc_mbr_uuid_to_id_trampoline<>(SB)
