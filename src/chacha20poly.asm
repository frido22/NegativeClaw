; ChaCha20-Poly1305 AEAD — RFC 7539/8439
; ChaCha20: 256-bit key, 96-bit nonce, 32-bit counter
; Poly1305: 130-bit one-time MAC with 5x26-bit limbs

BITS 64
DEFAULT REL

section .data
align 16

chacha_const:                       ; "expand 32-byte k"
    dd 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574

section .bss
align 16
    chacha_state:    resd 16         ; initial state
    chacha_working:  resd 16         ; working copy
    chacha_output:   resb 64         ; keystream block output

    poly_h:          resq 5          ; accumulator (5x26-bit limbs)
    poly_r:          resq 5          ; clamped r key
    poly_r5:         resq 4          ; r[i]*5 precomputed
    poly_s:          resd 4          ; s pad (128 bits)
    poly_temp:       resb 64

section .text
    global chacha20_poly1305_encrypt
    global chacha20_poly1305_decrypt

; chacha20_poly1305_encrypt(rdi=ct_out, rsi=pt, rdx=pt_len, rcx=aad, r8=aad_len,
;                           r9=key, [rbp+16]=nonce) -> rax=ct_len+16
chacha20_poly1305_encrypt:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    mov rbp, rsp
    sub rsp, 96

    mov [rsp], rdi
    mov [rsp+8], rsi
    mov [rsp+16], rdx
    mov [rsp+24], rcx
    mov [rsp+32], r8
    mov [rsp+40], r9
    mov rax, [rbp+16]
    mov [rsp+48], rax

    ; Generate Poly1305 one-time key from ChaCha20 block 0
    mov rdi, [rsp+40]
    mov rsi, [rsp+48]
    xor edx, edx
    call chacha20_block

    lea rdi, [chacha_output]
    call poly1305_init

    ; Encrypt with ChaCha20 starting at counter=1
    mov rdi, [rsp]
    mov rsi, [rsp+8]
    mov rdx, [rsp+16]
    mov rcx, [rsp+40]
    mov r8, [rsp+48]
    mov r9d, 1
    call chacha20_encrypt

    ; Poly1305 MAC: aad || pad || ciphertext || pad || len(aad) || len(ct)
    mov rdi, [rsp+24]
    mov rsi, [rsp+32]
    call poly1305_update

    mov rax, [rsp+32]
    and rax, 15
    jz .aad_aligned
    mov rcx, 16
    sub rcx, rax
    lea rdi, [poly_temp]
    xor eax, eax
    rep stosb
    lea rdi, [poly_temp]
    mov rsi, rcx
    call poly1305_update
.aad_aligned:

    mov rdi, [rsp]
    mov rsi, [rsp+16]
    call poly1305_update

    mov rax, [rsp+16]
    and rax, 15
    jz .ct_aligned
    mov rcx, 16
    sub rcx, rax
    lea rdi, [poly_temp]
    xor eax, eax
    rep stosb
    lea rdi, [poly_temp]
    mov rsi, rcx
    call poly1305_update
.ct_aligned:

    mov rax, [rsp+32]
    mov [poly_temp], rax
    mov rax, [rsp+16]
    mov [poly_temp+8], rax
    lea rdi, [poly_temp]
    mov rsi, 16
    call poly1305_update

    mov rdi, [rsp]
    add rdi, [rsp+16]               ; tag position = output + pt_len
    call poly1305_final

    mov rax, [rsp+16]
    add rax, 16

    add rsp, 96
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; chacha20_poly1305_decrypt(rdi=pt_out, rsi=ct_with_tag, rdx=ct_len_with_tag,
;   rcx=aad, r8=aad_len, r9=key, [rbp+16]=nonce) -> rax=pt_len or -1
chacha20_poly1305_decrypt:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    mov rbp, rsp
    sub rsp, 112

    sub rdx, 16                     ; strip tag from length

    mov [rsp], rdi
    mov [rsp+8], rsi
    mov [rsp+16], rdx
    mov [rsp+24], rcx
    mov [rsp+32], r8
    mov [rsp+40], r9
    mov rax, [rbp+16]
    mov [rsp+48], rax
    mov rdi, [rsp+40]
    mov rsi, [rsp+48]
    xor edx, edx
    call chacha20_block

    lea rdi, [chacha_output]
    call poly1305_init

    ; Verify MAC (same AEAD construction as encrypt)
    mov rdi, [rsp+24]
    mov rsi, [rsp+32]
    call poly1305_update

    mov rax, [rsp+32]
    and rax, 15
    jz .dec_aad_aligned
    mov rcx, 16
    sub rcx, rax
    lea rdi, [poly_temp]
    xor eax, eax
    rep stosb
    lea rdi, [poly_temp]
    mov rsi, rcx
    call poly1305_update
.dec_aad_aligned:

    mov rdi, [rsp+8]
    mov rsi, [rsp+16]
    call poly1305_update

    mov rax, [rsp+16]
    and rax, 15
    jz .dec_ct_aligned
    mov rcx, 16
    sub rcx, rax
    lea rdi, [poly_temp]
    xor eax, eax
    rep stosb
    lea rdi, [poly_temp]
    mov rsi, rcx
    call poly1305_update
.dec_ct_aligned:

    mov rax, [rsp+32]
    mov [poly_temp], rax
    mov rax, [rsp+16]
    mov [poly_temp+8], rax
    lea rdi, [poly_temp]
    mov rsi, 16
    call poly1305_update

    lea rdi, [rsp+64]               ; computed tag
    call poly1305_final

    ; Constant-time tag comparison
    lea rsi, [rsp+64]
    mov rdi, [rsp+8]
    add rdi, [rsp+16]               ; received tag
    xor eax, eax
    mov ecx, 16
.verify_loop:
    mov bl, [rsi]
    xor bl, [rdi]
    or al, bl
    inc rsi
    inc rdi
    dec ecx
    jnz .verify_loop

    test al, al
    jnz .auth_failed

    mov rdi, [rsp]
    mov rsi, [rsp+8]
    mov rdx, [rsp+16]
    mov rcx, [rsp+40]
    mov r8, [rsp+48]
    mov r9d, 1
    call chacha20_encrypt           ; XOR is its own inverse

    mov rax, [rsp+16]
    jmp .dec_done

.auth_failed:
    mov rax, -1

.dec_done:
    add rsp, 112
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; chacha20_block(rdi=key, rsi=nonce, edx=counter) -> chacha_output[64]
chacha20_block:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp

    ; State: constants[4] | key[8] | counter[1] | nonce[3]
    lea rax, [chacha_const]
    mov r8d, [rax]
    mov r9d, [rax+4]
    mov r10d, [rax+8]
    mov r11d, [rax+12]
    mov [chacha_state], r8d
    mov [chacha_state+4], r9d
    mov [chacha_state+8], r10d
    mov [chacha_state+12], r11d

    mov eax, [rdi]
    mov [chacha_state+16], eax
    mov eax, [rdi+4]
    mov [chacha_state+20], eax
    mov eax, [rdi+8]
    mov [chacha_state+24], eax
    mov eax, [rdi+12]
    mov [chacha_state+28], eax
    mov eax, [rdi+16]
    mov [chacha_state+32], eax
    mov eax, [rdi+20]
    mov [chacha_state+36], eax
    mov eax, [rdi+24]
    mov [chacha_state+40], eax
    mov eax, [rdi+28]
    mov [chacha_state+44], eax

    mov [chacha_state+48], edx
    mov eax, [rsi]
    mov [chacha_state+52], eax
    mov eax, [rsi+4]
    mov [chacha_state+56], eax
    mov eax, [rsi+8]
    mov [chacha_state+60], eax

    lea rsi, [chacha_state]
    lea rdi, [chacha_working]
    mov ecx, 16
.copy_state:
    mov eax, [rsi]
    mov [rdi], eax
    add rsi, 4
    add rdi, 4
    dec ecx
    jnz .copy_state

    mov r15d, 10                    ; 10 double-rounds = 20 rounds

.round_loop:
    ; Column rounds
    mov eax, [chacha_working]       ; a = state[0]
    mov ebx, [chacha_working+16]    ; b = state[4]
    mov ecx, [chacha_working+32]    ; c = state[8]
    mov edx, [chacha_working+48]    ; d = state[12]
    call quarter_round
    mov [chacha_working], eax
    mov [chacha_working+16], ebx
    mov [chacha_working+32], ecx
    mov [chacha_working+48], edx

    ; QR(1, 5, 9, 13)
    mov eax, [chacha_working+4]
    mov ebx, [chacha_working+20]
    mov ecx, [chacha_working+36]
    mov edx, [chacha_working+52]
    call quarter_round
    mov [chacha_working+4], eax
    mov [chacha_working+20], ebx
    mov [chacha_working+36], ecx
    mov [chacha_working+52], edx

    ; QR(2, 6, 10, 14)
    mov eax, [chacha_working+8]
    mov ebx, [chacha_working+24]
    mov ecx, [chacha_working+40]
    mov edx, [chacha_working+56]
    call quarter_round
    mov [chacha_working+8], eax
    mov [chacha_working+24], ebx
    mov [chacha_working+40], ecx
    mov [chacha_working+56], edx

    ; QR(3, 7, 11, 15)
    mov eax, [chacha_working+12]
    mov ebx, [chacha_working+28]
    mov ecx, [chacha_working+44]
    mov edx, [chacha_working+60]
    call quarter_round
    mov [chacha_working+12], eax
    mov [chacha_working+28], ebx
    mov [chacha_working+44], ecx
    mov [chacha_working+60], edx

    ; Diagonal rounds
    mov eax, [chacha_working]
    mov ebx, [chacha_working+20]
    mov ecx, [chacha_working+40]
    mov edx, [chacha_working+60]
    call quarter_round
    mov [chacha_working], eax
    mov [chacha_working+20], ebx
    mov [chacha_working+40], ecx
    mov [chacha_working+60], edx

    ; QR(1, 6, 11, 12)
    mov eax, [chacha_working+4]
    mov ebx, [chacha_working+24]
    mov ecx, [chacha_working+44]
    mov edx, [chacha_working+48]
    call quarter_round
    mov [chacha_working+4], eax
    mov [chacha_working+24], ebx
    mov [chacha_working+44], ecx
    mov [chacha_working+48], edx

    ; QR(2, 7, 8, 13)
    mov eax, [chacha_working+8]
    mov ebx, [chacha_working+28]
    mov ecx, [chacha_working+32]
    mov edx, [chacha_working+52]
    call quarter_round
    mov [chacha_working+8], eax
    mov [chacha_working+28], ebx
    mov [chacha_working+32], ecx
    mov [chacha_working+52], edx

    ; QR(3, 4, 9, 14)
    mov eax, [chacha_working+12]
    mov ebx, [chacha_working+16]
    mov ecx, [chacha_working+36]
    mov edx, [chacha_working+56]
    call quarter_round
    mov [chacha_working+12], eax
    mov [chacha_working+16], ebx
    mov [chacha_working+36], ecx
    mov [chacha_working+56], edx

    dec r15d
    jnz .round_loop

    ; Add initial state back (ChaCha20 finalization)
    lea rsi, [chacha_state]
    lea rdi, [chacha_working]
    lea r8, [chacha_output]
    mov ecx, 16
.add_state:
    mov eax, [rdi]
    add eax, [rsi]
    mov [r8], eax
    add rsi, 4
    add rdi, 4
    add r8, 4
    dec ecx
    jnz .add_state

    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; quarter_round — eax=a, ebx=b, ecx=c, edx=d in/out
quarter_round:
    add eax, ebx
    xor edx, eax
    rol edx, 16

    add ecx, edx
    xor ebx, ecx
    rol ebx, 12

    add eax, ebx
    xor edx, eax
    rol edx, 8

    add ecx, edx
    xor ebx, ecx
    rol ebx, 7

    ret

; chacha20_encrypt(out, in, len, key, nonce, counter) — XOR with keystream
chacha20_encrypt:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    mov rbp, rsp
    sub rsp, 64

    mov [rsp], rdi
    mov [rsp+8], rsi
    mov [rsp+16], rdx
    mov [rsp+24], rcx
    mov [rsp+32], r8
    mov [rsp+40], r9d

.enc_loop:
    mov rax, [rsp+16]
    test rax, rax
    jz .enc_done

    mov rdi, [rsp+24]
    mov rsi, [rsp+32]
    mov edx, [rsp+40]
    call chacha20_block

    mov rcx, [rsp+16]
    cmp rcx, 64
    jbe .xor_partial
    mov rcx, 64
.xor_partial:

    mov rsi, [rsp+8]
    mov rdi, [rsp]
    lea r8, [chacha_output]
    xor r9, r9

.xor_loop:
    cmp r9, rcx
    jge .xor_done
    mov al, [rsi + r9]
    xor al, [r8 + r9]
    mov [rdi + r9], al
    inc r9
    jmp .xor_loop

.xor_done:
    add [rsp], rcx
    add [rsp+8], rcx
    sub [rsp+16], rcx
    inc dword [rsp+40]              ; counter++

    jmp .enc_loop

.enc_done:
    add rsp, 64
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; poly1305_init(rdi=key) — key is r[16] || s[16], r gets clamped
; Extracts r as 5x26-bit limbs with RFC 7539 clamping
poly1305_init:
    push rbx

    ; Extract r into 5 x 26-bit limbs with clamping
    mov eax, [rdi]
    and eax, 0x03ffffff
    mov [poly_r], rax

    mov eax, [rdi+3]
    shr eax, 2
    and eax, 0x03ffff03
    and eax, 0x03ffffff
    mov [poly_r+8], rax

    mov eax, [rdi+6]
    shr eax, 4
    and eax, 0x03ffc0ff
    and eax, 0x03ffffff
    mov [poly_r+16], rax

    mov eax, [rdi+9]
    shr eax, 6
    and eax, 0x03f03fff
    and eax, 0x03ffffff
    mov [poly_r+24], rax

    mov eax, [rdi+12]
    shr eax, 8
    and eax, 0x000fffff
    mov [poly_r+32], rax

    ; Precompute r*5 for each limb (used in reduction)
    mov rax, [poly_r+8]
    imul rax, 5
    mov [poly_r5], rax
    mov rax, [poly_r+16]
    imul rax, 5
    mov [poly_r5+8], rax
    mov rax, [poly_r+24]
    imul rax, 5
    mov [poly_r5+16], rax
    mov rax, [poly_r+32]
    imul rax, 5
    mov [poly_r5+24], rax

    ; Copy s from bytes 16-31
    mov eax, [rdi+16]
    mov [poly_s], eax
    mov eax, [rdi+20]
    mov [poly_s+4], eax
    mov eax, [rdi+24]
    mov [poly_s+8], eax
    mov eax, [rdi+28]
    mov [poly_s+12], eax

    ; Initialize accumulator h to 0
    xor eax, eax
    mov [poly_h], rax
    mov [poly_h+8], rax
    mov [poly_h+16], rax
    mov [poly_h+24], rax
    mov [poly_h+32], rax

    pop rbx
    ret

; poly1305_update(rdi=message, rsi=length) — process message in 16-byte blocks
poly1305_update:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    mov rbp, rsp

    mov r12, rdi                    ; message
    mov r13, rsi                    ; length

.update_loop:
    cmp r13, 0
    jle .update_done

    ; Process up to 16 bytes
    mov rcx, r13
    cmp rcx, 16
    jbe .block_size_ok
    mov rcx, 16
.block_size_ok:
    mov r14, rcx                    ; block size

    ; Convert block to 5 x 26-bit limbs and add to h
    ; For a full 16-byte block, we also add 2^128

    ; Load block into temp (pad with zeros if partial)
    lea rdi, [poly_temp]
    xor eax, eax
    push rcx
    mov rcx, 16
    rep stosb
    pop rcx

    lea rdi, [poly_temp]
    mov rsi, r12
    mov rcx, r14
    rep movsb

    ; If full block, set hibit
    cmp r14, 16
    jne .partial_block
    mov byte [poly_temp + 16], 1    ; hibit at position 128
    jmp .add_to_h

.partial_block:
    ; For partial block, set hibit at position 8*len
    mov byte [poly_temp + r14], 1

.add_to_h:
    ; Extract 5 limbs from temp and add to h
    ; h[0] += bytes[0..3] & 0x3ffffff
    mov eax, [poly_temp]
    and eax, 0x03ffffff
    add [poly_h], rax

    ; h[1] += (bytes[3..6] >> 2) & 0x3ffffff
    mov eax, [poly_temp + 3]
    shr eax, 2
    and eax, 0x03ffffff
    add [poly_h + 8], rax

    ; h[2] += (bytes[6..9] >> 4) & 0x3ffffff
    mov eax, [poly_temp + 6]
    shr eax, 4
    and eax, 0x03ffffff
    add [poly_h + 16], rax

    ; h[3] += (bytes[9..12] >> 6) & 0x3ffffff
    mov eax, [poly_temp + 9]
    shr eax, 6
    and eax, 0x03ffffff
    add [poly_h + 24], rax

    ; h[4] += (bytes[12..16] >> 8) (includes hibit if full block)
    mov eax, [poly_temp + 12]
    shr eax, 8
    movzx ebx, byte [poly_temp + 16]
    shl ebx, 24
    or eax, ebx
    add [poly_h + 32], rax

    ; h = (h * r) mod p
    call poly1305_mulr

    ; Update pointers
    add r12, r14
    sub r13, r14
    jmp .update_loop

.update_done:
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; poly1305_mulr — h = h * r mod (2^130-5), updates poly_h in place
poly1305_mulr:
    push rbx
    push r12
    push r13
    push r14
    push r15

    ; Load h and r
    mov r8, [poly_h]                ; h0
    mov r9, [poly_h+8]              ; h1
    mov r10, [poly_h+16]            ; h2
    mov r11, [poly_h+24]            ; h3
    mov r12, [poly_h+32]            ; h4

    ; Compute d0 = h0*r0 + h1*r4*5 + h2*r3*5 + h3*r2*5 + h4*r1*5
    mov rax, r8
    imul rax, [poly_r]
    mov r13, rax                    ; d0

    mov rax, r9
    imul rax, [poly_r5+24]          ; r4*5
    add r13, rax

    mov rax, r10
    imul rax, [poly_r5+16]          ; r3*5
    add r13, rax

    mov rax, r11
    imul rax, [poly_r5+8]           ; r2*5
    add r13, rax

    mov rax, r12
    imul rax, [poly_r5]             ; r1*5
    add r13, rax

    ; Compute d1 = h0*r1 + h1*r0 + h2*r4*5 + h3*r3*5 + h4*r2*5
    mov rax, r8
    imul rax, [poly_r+8]
    mov r14, rax                    ; d1

    mov rax, r9
    imul rax, [poly_r]
    add r14, rax

    mov rax, r10
    imul rax, [poly_r5+24]
    add r14, rax

    mov rax, r11
    imul rax, [poly_r5+16]
    add r14, rax

    mov rax, r12
    imul rax, [poly_r5+8]
    add r14, rax

    ; Compute d2 = h0*r2 + h1*r1 + h2*r0 + h3*r4*5 + h4*r3*5
    mov rax, r8
    imul rax, [poly_r+16]
    mov r15, rax                    ; d2

    mov rax, r9
    imul rax, [poly_r+8]
    add r15, rax

    mov rax, r10
    imul rax, [poly_r]
    add r15, rax

    mov rax, r11
    imul rax, [poly_r5+24]
    add r15, rax

    mov rax, r12
    imul rax, [poly_r5+16]
    add r15, rax

    ; Compute d3 = h0*r3 + h1*r2 + h2*r1 + h3*r0 + h4*r4*5
    mov rax, r8
    imul rax, [poly_r+24]
    mov rbx, rax                    ; d3

    mov rax, r9
    imul rax, [poly_r+16]
    add rbx, rax

    mov rax, r10
    imul rax, [poly_r+8]
    add rbx, rax

    mov rax, r11
    imul rax, [poly_r]
    add rbx, rax

    mov rax, r12
    imul rax, [poly_r5+24]
    add rbx, rax

    ; Compute d4 = h0*r4 + h1*r3 + h2*r2 + h3*r1 + h4*r0
    mov rax, r8
    imul rax, [poly_r+32]
    mov rcx, rax                    ; d4

    mov rax, r9
    imul rax, [poly_r+24]
    add rcx, rax

    mov rax, r10
    imul rax, [poly_r+16]
    add rcx, rax

    mov rax, r11
    imul rax, [poly_r+8]
    add rcx, rax

    mov rax, r12
    imul rax, [poly_r]
    add rcx, rax

    ; Now d0..d4 in r13, r14, r15, rbx, rcx
    ; Carry propagation
    ; c = d0 >> 26; h0 = d0 & 0x3ffffff
    mov rax, r13
    shr rax, 26
    and r13, 0x3ffffff
    add r14, rax                    ; d1 += c

    mov rax, r14
    shr rax, 26
    and r14, 0x3ffffff
    add r15, rax

    mov rax, r15
    shr rax, 26
    and r15, 0x3ffffff
    add rbx, rax

    mov rax, rbx
    shr rax, 26
    and rbx, 0x3ffffff
    add rcx, rax

    mov rax, rcx
    shr rax, 26
    and rcx, 0x3ffffff
    ; c *= 5 and add back to h0
    imul rax, 5
    add r13, rax

    ; One more carry from h0 if needed
    mov rax, r13
    shr rax, 26
    and r13, 0x3ffffff
    add r14, rax

    ; Store h
    mov [poly_h], r13
    mov [poly_h+8], r14
    mov [poly_h+16], r15
    mov [poly_h+24], rbx
    mov [poly_h+32], rcx

    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; poly1305_final(rdi=output) — finalize accumulator, add s pad, write 16-byte tag
poly1305_final:
    push rbx
    push r12
    push r13
    push r14
    push r15

    mov r15, rdi                    ; output

    ; Full carry chain
    mov r8, [poly_h]
    mov r9, [poly_h+8]
    mov r10, [poly_h+16]
    mov r11, [poly_h+24]
    mov r12, [poly_h+32]

    mov rax, r8
    shr rax, 26
    and r8, 0x3ffffff
    add r9, rax

    mov rax, r9
    shr rax, 26
    and r9, 0x3ffffff
    add r10, rax

    mov rax, r10
    shr rax, 26
    and r10, 0x3ffffff
    add r11, rax

    mov rax, r11
    shr rax, 26
    and r11, 0x3ffffff
    add r12, rax

    mov rax, r12
    shr rax, 26
    and r12, 0x3ffffff
    imul rax, 5
    add r8, rax

    mov rax, r8
    shr rax, 26
    and r8, 0x3ffffff
    add r9, rax

    ; Compute h + 5 and check if >= 2^130
    mov rax, r8
    add rax, 5
    mov rcx, rax
    shr rcx, 26

    mov rax, r9
    add rax, rcx
    mov rcx, rax
    shr rcx, 26

    mov rax, r10
    add rax, rcx
    mov rcx, rax
    shr rcx, 26

    mov rax, r11
    add rax, rcx
    mov rcx, rax
    shr rcx, 26

    mov rax, r12
    add rax, rcx
    shr rax, 26                     ; if this is nonzero, h >= 2^130-5

    ; Conditional subtraction: if h >= p, h = h - p = h + 5 - 2^130
    neg rax                         ; mask: 0 if h < p, -1 if h >= p
    mov rbx, rax
    and rax, 5
    add r8, rax                     ; h0 += 5 if h >= p

    ; Reassemble h into 128 bits
    ; h = h0 | (h1 << 26) | (h2 << 52) | (h3 << 78) | (h4 << 104)
    mov rax, r8
    mov rcx, r9
    shl rcx, 26
    or rax, rcx
    mov r13, rax                    ; low 64 bits (partial)

    mov rax, r9
    shr rax, 38                     ; bits 38+ of h1
    mov rcx, r10
    shl rcx, 52-38
    or rax, rcx
    ; More assembly of bits... this is complex

    ; Simplified: convert 5 x 26-bit to 4 x 32-bit
    mov eax, r8d
    mov ecx, r9d
    shl ecx, 26
    or eax, ecx
    mov r13d, eax                   ; h[0]

    mov eax, r9d
    shr eax, 6
    mov ecx, r10d
    shl ecx, 20
    or eax, ecx
    mov r14d, eax                   ; h[1]

    mov eax, r10d
    shr eax, 12
    mov ecx, r11d
    shl ecx, 14
    or eax, ecx
    mov ebx, eax                    ; h[2]

    mov eax, r11d
    shr eax, 18
    mov ecx, r12d
    shl ecx, 8
    or eax, ecx                     ; h[3]

    ; Add s (mod 2^128)
    add r13d, [poly_s]
    adc r14d, [poly_s+4]
    adc ebx, [poly_s+8]
    adc eax, [poly_s+12]

    ; Store tag (little-endian)
    mov [r15], r13d
    mov [r15+4], r14d
    mov [r15+8], ebx
    mov [r15+12], eax

    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

