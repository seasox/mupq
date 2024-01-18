.global send_r4_r5
.global fault_window_start
.global fault_window_end
.global delay_some_time

.section .data
    num_iters:               .word 0x280DE80 // (1 secs * 168 MHz)/(4 [cycles per iteration]) = 4.2 * 10**7 (# of loop iterations)
    register_value:          .word 0xaaaaaaaa
    end_seq:                 .byte 0x42, 0x42, 0x42, 0x42
    fault_window_start_seq:  .byte 42, 42, 42, 42
    fault_window_end_seq:    .byte 0x13, 0x37, 0x13, 0x37
.section .text
send_r4_r5:
    push {r0,r1,r4,r5,lr}
    // some register cannot be pushed to the stack, copy them to pushable registers first
    // mov r4, rX 
    // mov r5, rY
    push {r4,r5}
    mov r0, sp  // mov sp (location of the registers) to r0
    mov r1, #8  // r0 = begin of registers, r1 = size of two registers
    bl _transfer
    pop {r4,r5}
    ldr r0, =end_seq  // Call transfer with end_seq
    mov r1, #4
    bl _transfer
    pop {r0,r1,r4,r5,pc}
fault_window_start:
    push {lr}
    ldr r0, =fault_window_start_seq
    mov r1, #4
    bl _transfer
    pop {pc}
fault_window_end:
    push {lr}
    ldr r0, =fault_window_end_seq
    mov r1, #4
    bl _transfer
    pop {pc}
delay_some_time:
    push {r7,lr}
    ldr r7, =num_iters
    ldr r7, [r7]
    _loop:
        cmp r7, #0
        beq end_loop
        sub r7, r7, #1  // r7 <- r7 - 1
        b _loop
    end_loop:
        pop {r7,pc}
