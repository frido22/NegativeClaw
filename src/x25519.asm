; X25519 key exchange — Curve25519 scalar multiplication
; Field: GF(2^255-19), 16x64-bit signed limbs (TweetNaCl style)

BITS 64
DEFAULT REL

section .data
align 16

; Basepoint u=9 as field element (16 limbs)
x25519_basepoint:
    dq 9, 0, 0, 0, 0, 0, 0, 0
    dq 0, 0, 0, 0, 0, 0, 0, 0

; (A-2)/4 = 121665 for Curve25519 Montgomery form
_121665:
    dq 0xDB41, 0, 0, 0, 0, 0, 0, 0
    dq 0, 0, 0, 0, 0, 0, 0, 0

section .bss
align 16
    fe_e:    resq 16              ; scratch field elements for ladder
    fe_f:    resq 16
    fe_t:    resq 31              ; multiplication accumulator

section .text
    global x25519_keygen
    global x25519_scalarmult

; x25519_keygen(rdi=privkey_inout, rsi=pubkey_out)
; Clamps privkey in place per RFC 7748, computes pubkey = privkey * basepoint
x25519_keygen:
    push r12
    push r13

    mov r12, rdi
    mov r13, rsi

    and byte [r12], 248             ; clamp: clear bottom 3 bits
    and byte [r12 + 31], 127        ; clear top bit
    or  byte [r12 + 31], 64         ; set second-to-top bit

    mov rdi, r13
    mov rsi, r12
    lea rdx, [x25519_basepoint]
    call x25519_scalarmult

    pop r13
    pop r12
    ret

; x25519_scalarmult(rdi=out, rsi=scalar, rdx=point)
; Montgomery ladder, constant-time
x25519_scalarmult:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    mov rbp, rsp
    sub rsp, 640
    ; Stack layout: z[32] | x[128] | a[128] | b[128] | c[128] | d[128]

    mov r12, rdi
    mov r13, rsi
    mov r14, rdx

    ; Copy and clamp scalar
    lea rdi, [rsp]
    mov rsi, r13
    mov rcx, 32
    rep movsb

    mov al, [rsp]
    and al, 248
    mov [rsp], al
    mov al, [rsp + 31]
    and al, 127
    or al, 64
    mov [rsp + 31], al

    lea rdi, [rsp + 32]
    mov rsi, r14
    call fe_unpack

    ; Montgomery ladder init: a=1, b=x, c=0, d=1
    lea rdi, [rsp + 160]            ; a
    call fe_one

    lea rdi, [rsp + 288]            ; b
    lea rsi, [rsp + 32]             ; x
    call fe_copy

    lea rdi, [rsp + 416]            ; c
    call fe_zero

    lea rdi, [rsp + 544]            ; d
    call fe_one

    ; Process bits 254 down to 0
    mov r15d, 254

.ladder_loop:
    ; Extract current scalar bit
    mov eax, r15d
    shr eax, 3
    movzx ecx, byte [rsp + rax]
    mov eax, r15d
    and eax, 7
    shr ecx, cl
    and ecx, 1

    ; Conditional swap based on bit value
    lea rdi, [rsp + 160]            ; a
    lea rsi, [rsp + 288]            ; b
    mov edx, ecx
    call fe_cswap

    lea rdi, [rsp + 416]            ; c
    lea rsi, [rsp + 544]            ; d
    mov edx, ecx
    call fe_cswap

    ; Montgomery ladder differential addition step
    lea rdi, [fe_e]
    lea rsi, [rsp + 160]            ; a
    lea rdx, [rsp + 416]            ; c
    call fe_add

    ; a = a - c
    lea rdi, [rsp + 160]            ; a (output)
    lea rsi, [rsp + 160]            ; a
    lea rdx, [rsp + 416]            ; c
    call fe_sub

    ; c = b + d
    lea rdi, [rsp + 416]            ; c (output)
    lea rsi, [rsp + 288]            ; b
    lea rdx, [rsp + 544]            ; d
    call fe_add

    ; b = b - d
    lea rdi, [rsp + 288]            ; b (output)
    lea rsi, [rsp + 288]            ; b
    lea rdx, [rsp + 544]            ; d
    call fe_sub

    ; d = e^2
    lea rdi, [rsp + 544]            ; d
    lea rsi, [fe_e]
    call fe_sq

    ; f = a^2
    lea rdi, [fe_f]
    lea rsi, [rsp + 160]            ; a
    call fe_sq

    ; a = c * a
    lea rdi, [rsp + 160]            ; a
    lea rsi, [rsp + 416]            ; c
    lea rdx, [rsp + 160]            ; a (old value still valid)
    call fe_mul

    ; c = b * e
    lea rdi, [rsp + 416]            ; c
    lea rsi, [rsp + 288]            ; b
    lea rdx, [fe_e]
    call fe_mul

    ; e = a + c
    lea rdi, [fe_e]
    lea rsi, [rsp + 160]            ; a
    lea rdx, [rsp + 416]            ; c
    call fe_add

    ; a = a - c
    lea rdi, [rsp + 160]            ; a
    lea rsi, [rsp + 160]            ; a
    lea rdx, [rsp + 416]            ; c
    call fe_sub

    ; b = a^2
    lea rdi, [rsp + 288]            ; b
    lea rsi, [rsp + 160]            ; a
    call fe_sq

    ; c = d - f
    lea rdi, [rsp + 416]            ; c
    lea rsi, [rsp + 544]            ; d
    lea rdx, [fe_f]
    call fe_sub

    ; a = c * 121665
    lea rdi, [rsp + 160]            ; a
    lea rsi, [rsp + 416]            ; c
    lea rdx, [_121665]
    call fe_mul

    ; a = a + d
    lea rdi, [rsp + 160]            ; a
    lea rsi, [rsp + 160]            ; a
    lea rdx, [rsp + 544]            ; d
    call fe_add

    ; c = c * a
    lea rdi, [rsp + 416]            ; c
    lea rsi, [rsp + 416]            ; c
    lea rdx, [rsp + 160]            ; a
    call fe_mul

    ; a = d * f
    lea rdi, [rsp + 160]            ; a
    lea rsi, [rsp + 544]            ; d
    lea rdx, [fe_f]
    call fe_mul

    ; d = b * x
    lea rdi, [rsp + 544]            ; d
    lea rsi, [rsp + 288]            ; b
    lea rdx, [rsp + 32]             ; x
    call fe_mul

    ; b = e^2
    lea rdi, [rsp + 288]            ; b
    lea rsi, [fe_e]
    call fe_sq

    ; Swap back (same bit)
    mov eax, r15d
    shr eax, 3
    movzx ecx, byte [rsp + rax]
    mov eax, r15d
    and eax, 7
    shr ecx, cl
    and ecx, 1

    lea rdi, [rsp + 160]            ; a
    lea rsi, [rsp + 288]            ; b
    mov edx, ecx
    call fe_cswap

    lea rdi, [rsp + 416]            ; c
    lea rsi, [rsp + 544]            ; d
    mov edx, ecx
    call fe_cswap

    dec r15d
    jns .ladder_loop

    ; Result = a * c^(-1)
    lea rdi, [rsp + 416]            ; c (will hold c^-1)
    lea rsi, [rsp + 416]            ; c
    call fe_inv

    lea rdi, [rsp + 160]            ; a (will hold result)
    lea rsi, [rsp + 160]            ; a
    lea rdx, [rsp + 416]            ; c^-1
    call fe_mul

    mov rdi, r12
    lea rsi, [rsp + 160]            ; a
    call fe_pack

    add rsp, 640
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; Field element ops — GF(2^255-19), 16x64-bit signed limbs

fe_zero:
    ; rdi = output
    xor eax, eax
    mov rcx, 16
.loop:
    mov [rdi], rax
    add rdi, 8
    dec rcx
    jnz .loop
    ret

fe_one:
    mov qword [rdi], 1
    xor eax, eax
    mov rcx, 15
    add rdi, 8
.loop:
    mov [rdi], rax
    add rdi, 8
    dec rcx
    jnz .loop
    ret

fe_copy:
    mov rcx, 16
.loop:
    mov rax, [rsi]
    mov [rdi], rax
    add rsi, 8
    add rdi, 8
    dec rcx
    jnz .loop
    ret

; fe_cswap(a, b, flag) — constant-time conditional swap
fe_cswap:
    neg rdx                         ; 0 -> 0, 1 -> -1 (all 1s)
    mov rcx, 16
.loop:
    mov rax, [rdi]
    mov r8, [rsi]
    mov r9, rax
    xor r9, r8                      ; r9 = a ^ b
    and r9, rdx                     ; r9 = (a ^ b) & mask
    xor rax, r9                     ; a ^= r9
    xor r8, r9                      ; b ^= r9
    mov [rdi], rax
    mov [rsi], r8
    add rdi, 8
    add rsi, 8
    dec rcx
    jnz .loop
    ret

; fe_add/fe_sub — out = a +/- b
fe_add:
    mov rcx, 16
.loop:
    mov rax, [rsi]
    add rax, [rdx]
    mov [rdi], rax
    add rsi, 8
    add rdx, 8
    add rdi, 8
    dec rcx
    jnz .loop
    ret

fe_sub:
    mov rcx, 16
.loop:
    mov rax, [rsi]
    sub rax, [rdx]
    mov [rdi], rax
    add rsi, 8
    add rdx, 8
    add rdi, 8
    dec rcx
    jnz .loop
    ret

; fe_mul(out, a, b) — schoolbook multiply + reduce mod 2^255-19
fe_mul:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    mov rbp, rsp

    mov r12, rdi
    mov r13, rsi
    mov r14, rdx

    ; Clear t[0..30]
    lea rdi, [fe_t]
    xor eax, eax
    mov rcx, 31
.clear_t:
    mov [rdi], rax
    add rdi, 8
    dec rcx
    jnz .clear_t

    ; t[i+j] += a[i] * b[j]
    xor r8d, r8d                    ; i = 0
.outer:
    cmp r8d, 16
    jge .reduce

    xor r9d, r9d                    ; j = 0
.inner:
    cmp r9d, 16
    jge .next_i

    ; t[i+j] += a[i] * b[j]
    mov rax, [r13 + r8*8]           ; a[i]
    imul rax, [r14 + r9*8]          ; a[i] * b[j] (signed)
    mov r10d, r8d
    add r10d, r9d                   ; i + j
    add [fe_t + r10*8], rax

    inc r9d
    jmp .inner

.next_i:
    inc r8d
    jmp .outer

.reduce:
    ; Reduce: t[i] += 38 * t[i+16] (since 2^256 ≡ 38 mod p)
    xor r8d, r8d
.reduce_loop:
    cmp r8d, 15
    jge .carry

    mov rax, [fe_t + r8*8 + 128]    ; t[i+16]
    imul rax, 38
    add [fe_t + r8*8], rax

    inc r8d
    jmp .reduce_loop

.carry:
    ; Carry propagation (car25519)
    mov rcx, 16
    lea rsi, [fe_t]
    mov r8, 0x10000                  ; 1 << 16

.carry_loop:
    mov rax, [rsi]
    add rax, r8                     ; bias for signed arithmetic
    mov rdx, rax
    sar rdx, 16                     ; carry

    cmp rcx, 1                      ; last limb wraps mod p
    jne .not_last

    mov r9, rdx
    dec r9                          ; c - 1
    imul r9, 37
    add [fe_t], r9
    jmp .store_limb

.not_last:
    ; o[i+1] += c - 1
    lea r9, [rdx - 1]
    add [rsi + 8], r9

.store_limb:
    mov r9, rdx
    shl r9, 16
    sub rax, r9
    mov [rsi], rax

    add rsi, 8
    dec rcx
    jnz .carry_loop

    ; Second carry pass
    mov rcx, 16
    lea rsi, [fe_t]

.carry2_loop:
    mov rax, [rsi]
    add rax, r8
    mov rdx, rax
    sar rdx, 16

    cmp rcx, 1
    jne .not_last2

    mov r9, rdx
    dec r9
    imul r9, 37
    add [fe_t], r9
    jmp .store_limb2

.not_last2:
    lea r9, [rdx - 1]
    add [rsi + 8], r9

.store_limb2:
    mov r9, rdx
    shl r9, 16
    sub rax, r9
    mov [rsi], rax

    add rsi, 8
    dec rcx
    jnz .carry2_loop

    mov rdi, r12
    lea rsi, [fe_t]
    mov rcx, 16
.copy_out:
    mov rax, [rsi]
    mov [rdi], rax
    add rsi, 8
    add rdi, 8
    dec rcx
    jnz .copy_out

    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; fe_sq(out, a) — squaring via fe_mul(out, a, a)
fe_sq:
    mov rdx, rsi
    jmp fe_mul

; fe_inv(out, a) — a^(p-2) mod p via Fermat's little theorem
; p-2 = 2^255-21, all bits 1 except bits 0 and 2
fe_inv:
    push rbx
    push r12
    push r13
    push rbp
    mov rbp, rsp
    sub rsp, 256                    ; c[128] for intermediate

    mov r12, rdi
    mov r13, rsi

    lea rdi, [rsp]
    mov rsi, r13
    call fe_copy

    mov ebx, 253                    ; square-and-multiply from bit 253

.inv_loop:
    ; c = c^2
    lea rdi, [rsp]
    lea rsi, [rsp]
    call fe_sq

    ; Skip multiply for zero bits (positions 0 and 2)
    cmp ebx, 2
    je .skip_mul
    cmp ebx, 0
    je .skip_mul

    ; c = c * a
    lea rdi, [rsp]
    lea rsi, [rsp]
    mov rdx, r13
    call fe_mul

.skip_mul:
    dec ebx
    jns .inv_loop

    mov rdi, r12
    lea rsi, [rsp]
    call fe_copy

    add rsp, 256
    pop rbp
    pop r13
    pop r12
    pop rbx
    ret

; fe_unpack(out, in) — 32 bytes → 16 limbs, 2 bytes each, little-endian
fe_unpack:
    mov rcx, 16
.loop:
    movzx eax, word [rsi]
    mov [rdi], rax
    add rsi, 2
    add rdi, 8
    dec rcx
    jnz .loop

    and qword [rdi - 8], 0x7fff     ; clear top bit of last limb
    ret

; fe_pack(out, in) — 16 limbs → 32 bytes with final reduction
fe_pack:
    push rbx
    push r12
    push r13
    push rbp
    mov rbp, rsp
    sub rsp, 256                    ; t[128], m[128]

    mov r12, rdi
    mov r13, rsi

    lea rdi, [rsp]
    mov rsi, r13
    call fe_copy

    mov r8d, 3
.carry_rounds:
    lea rsi, [rsp]
    call fe_carry
    dec r8d
    jnz .carry_rounds

    ; m = t - p (p = 2^255-19), then conditionally select
    mov rax, [rsp]
    sub rax, 0xffed
    mov [rsp + 128], rax

    ; m[1..14] = t[i] - 0xffff - borrow from previous
    mov rcx, 14
    mov r8d, 1
.sub_loop:
    mov rax, [rsp + r8*8]
    mov rdx, [rsp + 128 + r8*8 - 8]
    sar rdx, 16
    and rdx, 1                      ; borrow bit
    sub rax, 0xffff
    sub rax, rdx
    mov [rsp + 128 + r8*8], rax

    and qword [rsp + 128 + r8*8 - 8], 0xffff

    inc r8d
    dec rcx
    jnz .sub_loop

    mov rax, [rsp + 120]            ; t[15]
    mov rdx, [rsp + 128 + 112]     ; m[14]
    sar rdx, 16
    and rdx, 1
    sub rax, 0x7fff
    sub rax, rdx
    mov [rsp + 128 + 120], rax

    mov rdx, rax                    ; b = underflow indicator
    sar rdx, 16
    and edx, 1

    and qword [rsp + 128 + 112], 0xffff

    ; Conditional select: use m if no underflow, else keep t
    xor edx, 1
    neg rdx                         ; mask: 0 or all-1s

    mov rcx, 16
    lea rsi, [rsp]                  ; t
    lea rdi, [rsp + 128]            ; m
.select_loop:
    mov rax, [rsi]
    mov r8, [rdi]
    mov r9, rax
    xor r9, r8                      ; t ^ m
    and r9, rdx                     ; (t ^ m) & mask
    xor rax, r9
    mov [rsi], rax
    add rsi, 8
    add rdi, 8
    dec rcx
    jnz .select_loop

    mov rdi, r12
    lea rsi, [rsp]
    mov rcx, 16
.pack_loop:
    mov rax, [rsi]
    mov [rdi], ax
    add rsi, 8
    add rdi, 2
    dec rcx
    jnz .pack_loop

    add rsp, 256
    pop rbp
    pop r13
    pop r12
    pop rbx
    ret

; fe_carry(rsi) — single pass carry propagation
fe_carry:
    push rbx
    mov rcx, 16
    mov r8, 0x10000

.loop:
    mov rax, [rsi]
    add rax, r8
    mov rdx, rax
    sar rdx, 16

    cmp rcx, 1
    jne .not_last

    mov r9, rdx
    dec r9
    imul r9, 37
    lea rbx, [rsi]
    sub rbx, 120                    ; point to o[0]
    add [rbx], r9
    jmp .store

.not_last:
    lea r9, [rdx - 1]
    add [rsi + 8], r9

.store:
    mov r9, rdx
    shl r9, 16
    sub rax, r9
    mov [rsi], rax

    add rsi, 8
    dec rcx
    jnz .loop

    pop rbx
    ret
