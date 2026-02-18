; SHA-256/HMAC/HKDF — FIPS 180-4, RFC 2104/5869
; All multi-byte values big-endian per spec

BITS 64
DEFAULT REL

section .data
align 16

; H0-H7: sqrt fractional parts of first 8 primes
sha256_init_hash:
    dd 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a
    dd 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19

; K[0..63]: cbrt fractional parts of first 64 primes
sha256_k:
    dd 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5
    dd 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5
    dd 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3
    dd 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174
    dd 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc
    dd 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da
    dd 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7
    dd 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967
    dd 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13
    dd 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85
    dd 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3
    dd 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070
    dd 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5
    dd 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3
    dd 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208
    dd 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2

section .bss
align 16
    sha256_ctx_state:  resd 8       ; H[0..7]
    sha256_ctx_count:  resq 1       ; total bits processed
    sha256_ctx_buffer: resb 64      ; partial block buffer
    sha256_ctx_buflen: resd 1       ; bytes in buffer

    ; Message schedule W[0..63]
    sha256_w:          resd 64

section .text
    global sha256_init
    global sha256_update
    global sha256_final
    global sha256_final_keep
    global hmac_sha256
    global hkdf_extract
    global hkdf_expand
    global hkdf_expand_label

; sha256_init — reset state to initial hash values
sha256_init:
    ; Copy initial hash values to context state
    lea rsi, [sha256_init_hash]
    lea rdi, [sha256_ctx_state]
    mov ecx, 8
.copy_init:
    lodsd
    stosd
    dec ecx
    jnz .copy_init

    ; Reset bit count and buffer length
    xor eax, eax
    mov [sha256_ctx_count], rax
    mov [sha256_ctx_buflen], eax
    ret

; sha256_update(rdi=data, rsi=length) — feed data into running hash
sha256_update:
    push rbx
    push r12
    push r13
    push r14
    push rbp
    mov rbp, rsp

    mov r12, rdi                    ; data pointer
    mov r13, rsi                    ; data length

    ; Update bit count
    mov rax, r13
    shl rax, 3
    add [sha256_ctx_count], rax

.update_loop:
    test r13, r13
    jz .update_done

    ; Calculate how much we can copy to buffer
    mov eax, [sha256_ctx_buflen]
    mov r14d, 64
    sub r14d, eax                   ; space remaining in buffer

    ; Copy min(data_remaining, buffer_space) bytes
    mov rbx, r13
    cmp rbx, r14
    jbe .copy_amount_ok
    mov rbx, r14
.copy_amount_ok:

    ; Copy to buffer
    lea rdi, [sha256_ctx_buffer]
    add rdi, rax                    ; offset by current buflen
    mov rsi, r12
    mov rcx, rbx
    rep movsb

    ; Update pointers and counts
    add r12, rbx
    sub r13, rbx
    add [sha256_ctx_buflen], ebx

    ; If buffer is full, process it
    cmp dword [sha256_ctx_buflen], 64
    jne .update_loop

    ; Process the complete block
    lea rdi, [sha256_ctx_buffer]
    call sha256_transform

    mov dword [sha256_ctx_buflen], 0
    jmp .update_loop

.update_done:
    pop rbp
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; sha256_final(rdi=output) — pad, process final block, write 32-byte digest
sha256_final:
    push r12
    push rbp
    mov rbp, rsp

    mov r12, rdi                    ; save output pointer

    ; Append padding byte 0x80
    mov eax, [sha256_ctx_buflen]
    lea rdi, [sha256_ctx_buffer + rax]
    mov byte [rdi], 0x80
    inc eax
    mov [sha256_ctx_buflen], eax

    ; Check if we have room for the 8-byte length field
    cmp eax, 56
    jle .pad_length

    ; Not enough room - pad to 64 bytes and process
    lea rdi, [sha256_ctx_buffer + rax]
    mov rcx, 64
    sub rcx, rax
    xor al, al
    rep stosb

    lea rdi, [sha256_ctx_buffer]
    call sha256_transform

    ; Reset buffer
    lea rdi, [sha256_ctx_buffer]
    mov rcx, 56
    xor al, al
    rep stosb
    jmp .append_length

.pad_length:
    ; Pad with zeros up to byte 56
    lea rdi, [sha256_ctx_buffer + rax]
    mov rcx, 56
    sub rcx, rax
    xor al, al
    rep stosb

.append_length:
    ; Append bit count as big-endian 64-bit integer
    mov rax, [sha256_ctx_count]
    bswap rax
    mov [sha256_ctx_buffer + 56], rax

    ; Process final block
    lea rdi, [sha256_ctx_buffer]
    call sha256_transform

    ; Copy state to output (convert to big-endian)
    mov rdi, r12
    lea rsi, [sha256_ctx_state]
    mov ecx, 8
.copy_output:
    lodsd
    bswap eax
    stosd
    dec ecx
    jnz .copy_output

    pop rbp
    pop r12
    ret

; sha256_transform(rdi=block) — process one 64-byte block, updates sha256_ctx_state
sha256_transform:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    mov rbp, rsp
    sub rsp, 32                     ; working variables a-h

    mov r15, rdi                    ; save block pointer

    ; Prepare message schedule W[0..15] from block (big-endian to native)
    lea rdi, [sha256_w]
    mov rsi, r15
    mov ecx, 16
.load_words:
    lodsd
    bswap eax
    stosd
    dec ecx
    jnz .load_words

    ; Extend W[16..63]
    ; W[i] = σ1(W[i-2]) + W[i-7] + σ0(W[i-15]) + W[i-16]
    ; σ0(x) = ROTR7(x) ^ ROTR18(x) ^ SHR3(x)
    ; σ1(x) = ROTR17(x) ^ ROTR19(x) ^ SHR10(x)
    lea rdi, [sha256_w + 64]        ; W[16]
    mov ecx, 48
.extend_w:
    ; σ0(W[i-15])
    mov eax, [rdi - 60]             ; W[i-15]
    mov ebx, eax
    mov edx, eax
    ror eax, 7
    ror ebx, 18
    shr edx, 3
    xor eax, ebx
    xor eax, edx
    mov r8d, eax                    ; σ0

    ; σ1(W[i-2])
    mov eax, [rdi - 8]              ; W[i-2]
    mov ebx, eax
    mov edx, eax
    ror eax, 17
    ror ebx, 19
    shr edx, 10
    xor eax, ebx
    xor eax, edx                    ; σ1

    ; W[i] = σ1 + W[i-7] + σ0 + W[i-16]
    add eax, [rdi - 28]             ; + W[i-7]
    add eax, r8d                    ; + σ0
    add eax, [rdi - 64]             ; + W[i-16]
    mov [rdi], eax

    add rdi, 4
    dec ecx
    jnz .extend_w

    ; Initialize working variables from current hash state
    lea rsi, [sha256_ctx_state]
    mov eax, [rsi]                  ; a
    mov [rsp], eax
    mov eax, [rsi + 4]              ; b
    mov [rsp + 4], eax
    mov eax, [rsi + 8]              ; c
    mov [rsp + 8], eax
    mov eax, [rsi + 12]             ; d
    mov [rsp + 12], eax
    mov eax, [rsi + 16]             ; e
    mov [rsp + 16], eax
    mov eax, [rsi + 20]             ; f
    mov [rsp + 20], eax
    mov eax, [rsi + 24]             ; g
    mov [rsp + 24], eax
    mov eax, [rsi + 28]             ; h
    mov [rsp + 28], eax

    ; 64 rounds
    lea r12, [sha256_w]
    lea r13, [sha256_k]
    mov r14d, 64

.round_loop:
    ; Load working variables
    mov eax, [rsp]                  ; a
    mov ebx, [rsp + 4]              ; b
    mov ecx, [rsp + 8]              ; c
    mov edx, [rsp + 12]             ; d
    mov r8d, [rsp + 16]             ; e
    mov r9d, [rsp + 20]             ; f
    mov r10d, [rsp + 24]            ; g
    mov r11d, [rsp + 28]            ; h

    ; Σ1(e) = ROTR6(e) ^ ROTR11(e) ^ ROTR25(e)
    push rax
    mov eax, r8d
    mov ebx, r8d
    ror eax, 6
    ror ebx, 11
    xor eax, ebx
    mov ebx, r8d
    ror ebx, 25
    xor eax, ebx
    mov r15d, eax                   ; Σ1
    pop rax
    mov ebx, [rsp + 4]              ; restore b

    ; Ch(e,f,g) = (e AND f) XOR (NOT e AND g)
    mov eax, r8d
    and eax, r9d
    push rbx
    mov ebx, r8d
    not ebx
    and ebx, r10d
    xor eax, ebx
    pop rbx
    ; eax = Ch

    ; T1 = h + Σ1 + Ch + K[i] + W[i]
    add eax, r11d                   ; + h
    add eax, r15d                   ; + Σ1
    add eax, [r13]                  ; + K[i]
    add eax, [r12]                  ; + W[i]
    mov r15d, eax                   ; T1

    ; Σ0(a) = ROTR2(a) ^ ROTR13(a) ^ ROTR22(a)
    mov eax, [rsp]                  ; a
    mov ebx, eax
    mov ecx, eax
    ror eax, 2
    ror ebx, 13
    ror ecx, 22
    xor eax, ebx
    xor eax, ecx
    push rax                        ; save Σ0

    ; Maj(a,b,c) = (a AND b) XOR (a AND c) XOR (b AND c)
    mov eax, [rsp + 8]              ; a (offset by push)
    mov ebx, [rsp + 12]             ; b
    mov ecx, [rsp + 16]             ; c
    mov edx, eax
    and edx, ebx                    ; a AND b
    push rdx
    mov edx, eax
    and edx, ecx                    ; a AND c
    pop rax
    xor eax, edx
    mov edx, ebx
    and edx, ecx                    ; b AND c
    xor eax, edx                    ; Maj

    pop rbx                         ; Σ0
    add eax, ebx                    ; T2 = Σ0 + Maj

    ; Update working variables
    ; h = g
    mov ebx, [rsp + 24]
    mov [rsp + 28], ebx
    ; g = f
    mov ebx, [rsp + 20]
    mov [rsp + 24], ebx
    ; f = e
    mov ebx, [rsp + 16]
    mov [rsp + 20], ebx
    ; e = d + T1
    mov ebx, [rsp + 12]
    add ebx, r15d
    mov [rsp + 16], ebx
    ; d = c
    mov ebx, [rsp + 8]
    mov [rsp + 12], ebx
    ; c = b
    mov ebx, [rsp + 4]
    mov [rsp + 8], ebx
    ; b = a
    mov ebx, [rsp]
    mov [rsp + 4], ebx
    ; a = T1 + T2
    add eax, r15d
    mov [rsp], eax

    add r12, 4
    add r13, 4
    dec r14d
    jnz .round_loop

    ; Add working variables to hash state
    lea rsi, [sha256_ctx_state]
    mov eax, [rsp]
    add [rsi], eax
    mov eax, [rsp + 4]
    add [rsi + 4], eax
    mov eax, [rsp + 8]
    add [rsi + 8], eax
    mov eax, [rsp + 12]
    add [rsi + 12], eax
    mov eax, [rsp + 16]
    add [rsi + 16], eax
    mov eax, [rsp + 20]
    add [rsi + 20], eax
    mov eax, [rsp + 24]
    add [rsi + 24], eax
    mov eax, [rsp + 28]
    add [rsi + 28], eax

    add rsp, 32
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; sha256_hash(rdi=data, rsi=length, rdx=output) — one-shot hash
sha256_hash:
    push r12
    push r13
    push r14

    mov r12, rdi                    ; data
    mov r13, rsi                    ; length
    mov r14, rdx                    ; output

    call sha256_init

    mov rdi, r12
    mov rsi, r13
    call sha256_update

    mov rdi, r14
    call sha256_final

    pop r14
    pop r13
    pop r12
    ret

; hmac_sha256(rdi=key, rsi=key_len, rdx=data, rcx=data_len, r8=output)
; HMAC(K, m) = H((K' ^ opad) || H((K' ^ ipad) || m))
hmac_sha256:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    mov rbp, rsp
    sub rsp, 224                    ; k_prime(64) + i_key_pad(64) + o_key_pad(64) + inner_hash(32)

    mov r12, rdi                    ; key
    mov r13, rsi                    ; key_len
    mov r14, rdx                    ; data
    mov r15, rcx                    ; data_len
    mov rbx, r8                     ; output

    ; Prepare K' (key padded/hashed to 64 bytes)
    lea rdi, [rsp]                  ; k_prime at rsp+0
    mov rcx, 64
    xor al, al
    rep stosb                       ; zero k_prime

    cmp r13, 64
    jg .hash_key

    ; Key <= 64 bytes: copy directly
    lea rdi, [rsp]
    mov rsi, r12
    mov rcx, r13
    rep movsb
    jmp .prepare_pads

.hash_key:
    ; Key > 64 bytes: hash it
    mov rdi, r12
    mov rsi, r13
    lea rdx, [rsp]
    call sha256_hash

.prepare_pads:
    ; Create i_key_pad = k_prime XOR 0x36 (at rsp+64)
    ; Create o_key_pad = k_prime XOR 0x5c (at rsp+128)
    mov rcx, 64
    xor r8, r8
.pad_loop:
    mov al, [rsp + r8]
    mov bl, al
    xor al, 0x36
    mov [rsp + 64 + r8], al         ; i_key_pad
    xor bl, 0x5c
    mov [rsp + 128 + r8], bl        ; o_key_pad
    inc r8
    dec rcx
    jnz .pad_loop

    ; Inner hash: H(i_key_pad || data)
    call sha256_init

    lea rdi, [rsp + 64]             ; i_key_pad
    mov rsi, 64
    call sha256_update

    mov rdi, r14                    ; data
    mov rsi, r15                    ; data_len
    call sha256_update

    lea rdi, [rsp + 192]            ; inner_hash
    call sha256_final

    ; Outer hash: H(o_key_pad || inner_hash)
    call sha256_init

    lea rdi, [rsp + 128]            ; o_key_pad
    mov rsi, 64
    call sha256_update

    lea rdi, [rsp + 192]            ; inner_hash
    mov rsi, 32
    call sha256_update

    mov rdi, rbx                    ; output
    call sha256_final

    add rsp, 224
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; hkdf_extract(rdi=output, rsi=salt, rdx=salt_len, rcx=ikm, r8=ikm_len)
; PRK = HMAC-SHA256(salt, IKM)
hkdf_extract:
    ; Reshuffle to hmac_sha256(rdi=key, rsi=key_len, rdx=data, rcx=data_len, r8=output)
    mov r9, rdi                     ; save output
    mov rdi, rsi                    ; key = salt
    mov rsi, rdx                    ; key_len = salt_len
    mov rdx, rcx                    ; data = ikm
    mov rcx, r8                     ; data_len = ikm_len
    mov r8, r9                      ; output
    jmp hmac_sha256

; hkdf_expand(rdi=prk, rsi=info, rdx=info_len, rcx=output, r8=output_len)
; T(i) = HMAC(PRK, T(i-1) | info | i), output = first output_len bytes
hkdf_expand:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    mov rbp, rsp
    sub rsp, 128                    ; T_prev(32) + temp(64) + scratch

    mov r12, rdi                    ; prk
    mov r13, rsi                    ; info
    mov r14, rdx                    ; info_len
    mov r15, rcx                    ; output
    mov rbx, r8                     ; output_len

    xor r8d, r8d                    ; T_prev_len = 0 (T(0) is empty)
    mov byte [rsp + 96], 0          ; counter = 0

.expand_loop:
    test rbx, rbx
    jle .expand_done

    inc byte [rsp + 96]             ; counter++

    ; Build message: T_prev | info | counter
    lea rdi, [rsp + 32]             ; temp buffer
    xor rcx, rcx

    ; Copy T_prev (if any)
    test r8d, r8d
    jz .no_t_prev
    lea rsi, [rsp]                  ; T_prev
    mov ecx, r8d
    rep movsb
    mov ecx, r8d
.no_t_prev:

    ; Copy info
    push rcx
    mov rsi, r13
    mov rcx, r14
    rep movsb
    pop rcx
    add rcx, r14

    ; Append counter
    mov al, [rsp + 96]
    mov [rsp + 32 + rcx], al
    inc rcx

    ; HMAC(prk, message)
    mov rdi, r12                    ; key = prk
    mov rsi, 32                     ; key_len = 32
    lea rdx, [rsp + 32]             ; data = message
    ; rcx = message length (already set)
    lea r8, [rsp]                   ; output = T_prev (overwrite)
    call hmac_sha256

    mov r8d, 32                     ; T_prev_len = 32

    ; Copy to output
    mov rcx, rbx
    cmp rcx, 32
    jbe .copy_ok
    mov rcx, 32
.copy_ok:
    lea rsi, [rsp]                  ; T
    mov rdi, r15                    ; output
    push rcx
    rep movsb
    pop rcx

    add r15, rcx
    sub rbx, rcx
    jmp .expand_loop

.expand_done:
    add rsp, 128
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; hkdf_expand_label(rdi=output, rsi=secret, rdx=label, rcx=label_len,
;   r8=context, r9=context_len, [stack]=output_len)
; Builds HkdfLabel = uint16(length) | uint8(label_len+6) | "tls13 " | label | uint8(ctx_len) | ctx
hkdf_expand_label:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 128                    ; HkdfLabel buffer at [rsp]

    mov r15, rdi                    ; output
    mov r12, rsi                    ; secret
    mov r13, rdx                    ; label
    mov r14d, ecx                   ; label_len
    mov ebx, [rbp + 16]            ; output_len (first stack arg)

    ; Build HkdfLabel at [rsp]
    lea rdi, [rsp]

    ; uint16 length (big-endian)
    mov eax, ebx
    xchg al, ah
    stosw

    ; uint8 label_len = label_len + 6 ("tls13 ")
    mov eax, r14d
    add eax, 6
    stosb

    ; "tls13 " prefix
    mov byte [rdi], 't'
    mov byte [rdi+1], 'l'
    mov byte [rdi+2], 's'
    mov byte [rdi+3], '1'
    mov byte [rdi+4], '3'
    mov byte [rdi+5], ' '
    add rdi, 6

    ; label
    mov rsi, r13
    mov ecx, r14d
    rep movsb

    ; uint8 context_len
    mov eax, r9d
    stosb
    mov ecx, eax

    ; context
    mov rsi, r8
    rep movsb

    ; Calculate total HkdfLabel length
    lea rax, [rsp]
    sub rdi, rax
    mov rcx, rdi                    ; hkdf_label_len

    ; hkdf_expand(prk, info, info_len, output, output_len)
    mov rdi, r12                    ; prk = secret
    lea rsi, [rsp]                  ; info = HkdfLabel
    mov rdx, rcx                    ; info_len
    mov rcx, r15                    ; output
    mov r8d, ebx                    ; output_len
    call hkdf_expand

    add rsp, 128
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

; sha256_final_keep(rdi=output) — finalize hash but preserve internal state for continued hashing
sha256_final_keep:
    push r12
    push rbp
    mov rbp, rsp
    sub rsp, 112                    ; save area: state(32) + count(8) + buffer(64) + buflen(4) = 108

    mov r12, rdi                    ; output

    ; Save SHA-256 internal state (108 contiguous bytes)
    lea rdi, [rsp]
    lea rsi, [sha256_ctx_state]
    mov rcx, 108
    rep movsb

    ; Finalize to get current hash
    mov rdi, r12
    call sha256_final

    ; Restore internal state so hashing can continue
    lea rdi, [sha256_ctx_state]
    lea rsi, [rsp]
    mov rcx, 108
    rep movsb

    add rsp, 112
    pop rbp
    pop r12
    ret
