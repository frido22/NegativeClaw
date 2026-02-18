; TLS 1.3 — RFC 8446, TLS_CHACHA20_POLY1305_SHA256 + X25519

BITS 64
DEFAULT REL

; TLS record types
TLS_CHANGE_CIPHER_SPEC equ 20
TLS_ALERT              equ 21
TLS_HANDSHAKE          equ 22
TLS_APPLICATION_DATA   equ 23

; Handshake message types
HS_CLIENT_HELLO        equ 1
HS_SERVER_HELLO        equ 2
HS_NEW_SESSION_TICKET  equ 4
HS_ENCRYPTED_EXTENSIONS equ 8
HS_CERTIFICATE         equ 11
HS_CERTIFICATE_VERIFY  equ 15
HS_FINISHED            equ 20

; TLS versions
TLS_1_0                equ 0x0301
TLS_1_2                equ 0x0303
TLS_1_3                equ 0x0304

; Extension types
EXT_SERVER_NAME        equ 0
EXT_SUPPORTED_GROUPS   equ 10
EXT_SIGNATURE_ALGORITHMS equ 13
EXT_SUPPORTED_VERSIONS equ 43
EXT_KEY_SHARE          equ 51

; Cipher suite
CIPHER_CHACHA20_POLY1305 equ 0x1303

; Named groups
X25519_GROUP           equ 29

; Linux syscalls
SYS_READ               equ 0
SYS_WRITE              equ 1
SYS_OPEN               equ 2
SYS_CLOSE              equ 3
SYS_GETRANDOM          equ 318

; Key/IV sizes for ChaCha20-Poly1305
KEY_SIZE               equ 32
IV_SIZE                equ 12
TAG_SIZE               equ 16

section .data
    ; HKDF-Expand-Label strings (length-prefixed)
    label_derived:
        db 7, "derived"
    label_c_hs_traffic:
        db 12, "c hs traffic"
    label_s_hs_traffic:
        db 12, "s hs traffic"
    label_c_ap_traffic:
        db 12, "c ap traffic"
    label_s_ap_traffic:
        db 12, "s ap traffic"
    label_finished:
        db 8, "finished"
    label_key:
        db 3, "key"
    label_iv:
        db 2, "iv"
    ; SHA-256 of empty string (used for early secret derivation)
    empty_hash:
        db 0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14
        db 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24
        db 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c
        db 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55

    ; Zero salt for HKDF-Extract (32 bytes)
    zero_salt:
        times 32 db 0

    ; Zero IKM for master secret derivation
    zero_ikm:
        times 32 db 0

section .bss
    ; TLS connection state
    tls_socket:          resq 1      ; socket fd
    tls_state:           resd 1      ; handshake state machine
    tls_seq_client:      resq 1      ; client record sequence number
    tls_seq_server:      resq 1      ; server record sequence number

    ; Random values
    client_random:       resb 32     ; ClientHello.random
    server_random:       resb 32     ; ServerHello.random

    ; X25519 key exchange
    client_privkey:      resb 32     ; ephemeral private key
    client_pubkey:       resb 32     ; ephemeral public key
    server_pubkey:       resb 32     ; server's public key from key_share
    shared_secret:       resb 32     ; X25519(privkey, server_pubkey)

    ; TLS 1.3 Key Schedule secrets
    early_secret:        resb 32     ; HKDF-Extract(0, 0 or PSK)
    handshake_secret:    resb 32     ; HKDF-Extract(derived, DHE)
    master_secret:       resb 32     ; HKDF-Extract(derived, 0)

    ; Traffic secrets
    client_hs_secret:    resb 32     ; client_handshake_traffic_secret
    server_hs_secret:    resb 32     ; server_handshake_traffic_secret
    client_app_secret:   resb 32     ; client_application_traffic_secret_0
    server_app_secret:   resb 32     ; server_application_traffic_secret_0

    ; Traffic keys for ChaCha20-Poly1305
    client_write_key:    resb 32
    client_write_iv:     resb 12
    server_write_key:    resb 32
    server_write_iv:     resb 12

    ; Transcript hash context (running SHA-256 state)
    ; We store intermediate hash values at key points
    transcript_hash:     resb 32     ; current transcript hash
    hello_hash:          resb 32     ; hash after ClientHello + ServerHello
    hs_finished_hash:    resb 32     ; hash before client Finished

    ; Buffers
    record_buffer:       resb 16640  ; TLS record: 5 header + 16384 max + 256 margin
    handshake_buffer:    resb 4096   ; handshake message assembly
    decrypt_buffer:      resb 16640  ; decryption output
    temp_buffer:         resb 512    ; temporary working space

    ; Session ID (32 bytes for middlebox compatibility)
    session_id:          resb 32
    session_id_len:      resb 1

    ; Finished key cache
    client_finished_key: resb 32
    server_finished_key: resb 32

section .text
    global tls_handshake
    global tls_send
    global tls_recv
    global tls_close

    ; External crypto functions from other modules
    extern sha256_init
    extern sha256_update
    extern sha256_final
    extern sha256_final_keep
    extern hmac_sha256
    extern hkdf_extract
    extern hkdf_expand_label
    extern x25519_keygen
    extern x25519_scalarmult
    extern chacha20_poly1305_encrypt
    extern chacha20_poly1305_decrypt

; tls_handshake(rdi=socket_fd) -> rax=0 success, -1 error
tls_handshake:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    mov rbp, rsp
    sub rsp, 512                    ; local stack space

    ; Save socket
    mov [tls_socket], rdi

    ; Initialize state
    xor eax, eax
    mov [tls_state], eax
    mov [tls_seq_client], rax
    mov [tls_seq_server], rax

    ; ========================================
    ; Step 1: Generate random values
    ; ========================================

    ; Generate client random (32 bytes)
    lea rdi, [client_random]
    mov rsi, 32
    call get_random_bytes
    test rax, rax
    js .handshake_error

    ; Generate X25519 ephemeral keypair
    lea rdi, [client_privkey]
    mov rsi, 32
    call get_random_bytes
    test rax, rax
    js .handshake_error

    ; Clamp privkey and compute pubkey
    lea rdi, [client_privkey]
    lea rsi, [client_pubkey]
    call x25519_keygen

    ; Generate session ID for middlebox compatibility
    lea rdi, [session_id]
    mov rsi, 32
    call get_random_bytes
    mov byte [session_id_len], 32

    ; ========================================
    ; Step 2: Initialize transcript hash
    ; ========================================

    call sha256_init

    ; ========================================
    ; Step 3: Build and send ClientHello
    ; ========================================

    call build_client_hello
    test rax, rax
    js .handshake_error
    mov r12, rax                    ; r12 = ClientHello length

    ; Update transcript with ClientHello (without record header)
    lea rdi, [handshake_buffer]
    mov rsi, r12
    call sha256_update

    ; Send ClientHello as TLS record
    lea rdi, [handshake_buffer]
    mov rsi, r12
    call send_record_plaintext
    test rax, rax
    js .handshake_error

    ; ========================================
    ; Step 4: Receive ServerHello
    ; ========================================

.recv_server_hello:
    call recv_record
    test rax, rax
    js .handshake_error
    mov r13, rax                    ; r13 = record body length

    ; Check record type
    movzx eax, byte [record_buffer]
    cmp al, TLS_HANDSHAKE
    jne .recv_server_hello          ; skip non-handshake (e.g., CCS)

    ; Check handshake type (should be ServerHello = 2)
    movzx eax, byte [record_buffer + 5]
    cmp al, HS_SERVER_HELLO
    jne .handshake_error

    ; Parse ServerHello
    lea rdi, [record_buffer + 5]    ; skip record header
    mov rsi, r13
    call parse_server_hello
    test rax, rax
    js .handshake_error

    ; Update transcript with ServerHello
    lea rdi, [record_buffer + 5]
    mov rsi, r13
    call sha256_update

    ; ========================================
    ; Step 5: Compute shared secret and derive handshake keys
    ; ========================================

    ; shared_secret = X25519(client_privkey, server_pubkey)
    lea rdi, [shared_secret]
    lea rsi, [client_privkey]
    lea rdx, [server_pubkey]
    call x25519_scalarmult

    ; Get transcript hash at this point (ClientHello + ServerHello)
    lea rdi, [hello_hash]
    call sha256_final_keep          ; get hash but keep context

    ; Derive handshake traffic secrets
    lea rdi, [hello_hash]           ; transcript hash
    call derive_handshake_secrets
    test rax, rax
    js .handshake_error

    ; ========================================
    ; Step 6: Receive encrypted handshake messages
    ; ========================================

    ; Now we receive: EncryptedExtensions, Certificate, CertificateVerify, Finished
    ; All encrypted with server_write_key/iv

.recv_encrypted_loop:
    call recv_record
    test rax, rax
    js .handshake_error
    mov r13, rax

    ; Check for Change Cipher Spec (middlebox compatibility - ignore it)
    movzx eax, byte [record_buffer]
    cmp al, TLS_CHANGE_CIPHER_SPEC
    je .recv_encrypted_loop

    ; Should be Application Data (encrypted handshake)
    cmp al, TLS_APPLICATION_DATA
    jne .handshake_error

    ; Decrypt the record
    lea rdi, [decrypt_buffer]       ; output
    lea rsi, [record_buffer]        ; input (full record including header)
    mov rdx, r13                    ; ciphertext length
    mov rcx, 0                      ; use server keys
    call decrypt_record
    test rax, rax
    js .handshake_error
    mov r14, rax                    ; r14 = plaintext length

    ; Get inner content type (last byte of plaintext)
    lea rdi, [decrypt_buffer]
    add rdi, r14
    dec rdi
    movzx eax, byte [rdi]
    cmp al, TLS_HANDSHAKE
    jne .handshake_error
    dec r14                         ; remove content type from length

    ; Process handshake message(s) - there may be multiple
    lea r15, [decrypt_buffer]       ; r15 = current position

.process_hs_messages:
    cmp r14, 4
    jl .recv_encrypted_loop         ; need at least header

    ; Get handshake type
    movzx eax, byte [r15]

    ; Get handshake length (3 bytes big-endian)
    movzx ebx, byte [r15 + 1]
    shl ebx, 16
    movzx ecx, byte [r15 + 2]
    shl ecx, 8
    or ebx, ecx
    movzx ecx, byte [r15 + 3]
    or ebx, ecx                     ; ebx = message length

    lea rcx, [rbx + 4]              ; total message size including header
    cmp rcx, r14
    jg .handshake_error             ; incomplete message

    ; Update transcript with this handshake message
    push rax
    mov rdi, r15
    mov rsi, rcx
    call sha256_update
    lea rcx, [rbx + 4]             ; recompute msg size (rbx is callee-saved)
    pop rax

    ; Handle by type
    cmp al, HS_ENCRYPTED_EXTENSIONS
    je .handle_enc_ext
    cmp al, HS_CERTIFICATE
    je .handle_cert
    cmp al, HS_CERTIFICATE_VERIFY
    je .handle_cert_verify
    cmp al, HS_FINISHED
    je .handle_server_finished

    ; Unknown - skip it
    jmp .skip_hs_message

.handle_enc_ext:
    ; Just accept EncryptedExtensions
    jmp .skip_hs_message

.handle_cert:
    ; We skip certificate validation for minimal implementation
    jmp .skip_hs_message

.handle_cert_verify:
    ; We skip signature verification for minimal implementation
    jmp .skip_hs_message

.skip_hs_message:
    add r15, rcx
    sub r14, rcx
    jmp .process_hs_messages

.handle_server_finished:
    ; Save transcript hash before server Finished (for client Finished computation)
    push rcx
    lea rdi, [hs_finished_hash]
    call sha256_final_keep
    pop rcx

    ; TODO: Verify server Finished MAC (skipped for minimal impl)
    ; The Finished message contains HMAC(server_finished_key, transcript_hash)

    ; Move past server Finished in buffer
    add r15, rcx
    sub r14, rcx

    ; ========================================
    ; Step 7: Send Client Finished
    ; ========================================

    ; Compute client Finished
    call build_client_finished
    mov r12, rax                    ; r12 = Finished message length

    ; Update transcript with client Finished (before sending)
    lea rdi, [handshake_buffer]
    mov rsi, r12
    call sha256_update

    ; Send encrypted client Finished
    lea rdi, [handshake_buffer]
    mov rsi, r12
    mov rdx, TLS_HANDSHAKE          ; inner content type
    call send_record_encrypted
    test rax, rax
    js .handshake_error

    ; ========================================
    ; Step 8: Derive application traffic secrets
    ; ========================================

    ; Get final transcript hash
    lea rdi, [transcript_hash]
    call sha256_final

    ; Derive application traffic secrets
    lea rdi, [transcript_hash]
    call derive_application_secrets
    test rax, rax
    js .handshake_error

    ; Reset sequence numbers for application data
    xor rax, rax
    mov [tls_seq_client], rax
    mov [tls_seq_server], rax

    ; Success!
    xor eax, eax
    jmp .handshake_done

.handshake_error:
    mov eax, -1

.handshake_done:
    add rsp, 512
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; build_client_hello -> rax=message length in handshake_buffer
build_client_hello:
    push rbx
    push r12
    push r13
    push r14
    push rbp
    mov rbp, rsp

    lea rdi, [handshake_buffer]
    mov r12, rdi                    ; r12 = buffer start

    ; Handshake header
    mov byte [rdi], HS_CLIENT_HELLO ; type = 1
    add rdi, 1
    mov r13, rdi                    ; r13 = length field position (3 bytes)
    add rdi, 3

    ; Legacy version: TLS 1.2 (0x0303) for compatibility
    mov byte [rdi], 0x03
    mov byte [rdi + 1], 0x03
    add rdi, 2

    ; Client random (32 bytes)
    lea rsi, [client_random]
    mov rcx, 32
    rep movsb

    ; Session ID (for middlebox compatibility)
    movzx eax, byte [session_id_len]
    stosb
    movzx rcx, al
    test rcx, rcx
    jz .no_session_id
    lea rsi, [session_id]
    rep movsb
.no_session_id:

    ; Cipher suites (2 bytes length + suites)
    mov byte [rdi], 0x00            ; length high byte
    mov byte [rdi + 1], 0x02        ; length = 2
    add rdi, 2
    mov byte [rdi], 0x13            ; TLS_CHACHA20_POLY1305_SHA256 = 0x1303
    mov byte [rdi + 1], 0x03
    add rdi, 2

    ; Compression methods
    mov byte [rdi], 0x01            ; 1 method
    mov byte [rdi + 1], 0x00        ; null compression
    add rdi, 2

    ; Extensions
    mov r14, rdi                    ; r14 = extensions length position
    add rdi, 2                      ; placeholder for extensions length

    ; --- Extension: supported_versions (type 43 = 0x002b) ---
    mov byte [rdi], 0x00            ; type high
    mov byte [rdi + 1], 0x2b        ; type low (43)
    add rdi, 2
    mov byte [rdi], 0x00            ; ext length high
    mov byte [rdi + 1], 0x03        ; ext length = 3
    add rdi, 2
    mov byte [rdi], 0x02            ; versions list length
    mov byte [rdi + 1], 0x03        ; TLS 1.3 = 0x0304
    mov byte [rdi + 2], 0x04
    add rdi, 3

    ; --- Extension: supported_groups (type 10 = 0x000a) ---
    mov byte [rdi], 0x00            ; type high
    mov byte [rdi + 1], 0x0a        ; type low (10)
    add rdi, 2
    mov byte [rdi], 0x00            ; ext length high
    mov byte [rdi + 1], 0x04        ; ext length = 4
    add rdi, 2
    mov byte [rdi], 0x00            ; groups length high
    mov byte [rdi + 1], 0x02        ; groups length = 2
    add rdi, 2
    mov byte [rdi], 0x00            ; x25519 = 0x001d
    mov byte [rdi + 1], 0x1d
    add rdi, 2

    ; --- Extension: signature_algorithms (type 13 = 0x000d) ---
    mov byte [rdi], 0x00            ; type high
    mov byte [rdi + 1], 0x0d        ; type low (13)
    add rdi, 2
    mov byte [rdi], 0x00            ; ext length high
    mov byte [rdi + 1], 0x08        ; ext length = 8
    add rdi, 2
    mov byte [rdi], 0x00            ; algorithms length high
    mov byte [rdi + 1], 0x06        ; algorithms length = 6
    add rdi, 2
    ; ecdsa_secp256r1_sha256 (0x0403)
    mov byte [rdi], 0x04
    mov byte [rdi + 1], 0x03
    add rdi, 2
    ; rsa_pss_rsae_sha256 (0x0804)
    mov byte [rdi], 0x08
    mov byte [rdi + 1], 0x04
    add rdi, 2
    ; rsa_pkcs1_sha256 (0x0401)
    mov byte [rdi], 0x04
    mov byte [rdi + 1], 0x01
    add rdi, 2

    ; --- Extension: key_share (type 51 = 0x0033) ---
    mov byte [rdi], 0x00            ; type high
    mov byte [rdi + 1], 0x33        ; type low (51)
    add rdi, 2
    mov byte [rdi], 0x00            ; ext length high
    mov byte [rdi + 1], 0x26        ; ext length = 38 (2 + 2 + 2 + 32)
    add rdi, 2
    mov byte [rdi], 0x00            ; client_shares length high
    mov byte [rdi + 1], 0x24        ; client_shares length = 36
    add rdi, 2
    mov byte [rdi], 0x00            ; group high (x25519 = 0x001d)
    mov byte [rdi + 1], 0x1d
    add rdi, 2
    mov byte [rdi], 0x00            ; key_exchange length high
    mov byte [rdi + 1], 0x20        ; key_exchange length = 32
    add rdi, 2
    ; Client public key (32 bytes)
    lea rsi, [client_pubkey]
    mov rcx, 32
    rep movsb

    ; Calculate extensions length
    mov rax, rdi
    sub rax, r14
    sub rax, 2                      ; exclude length field itself
    mov byte [r14], ah              ; high byte
    mov byte [r14 + 1], al          ; low byte

    ; Calculate total handshake message length (minus 4-byte header)
    mov rax, rdi
    sub rax, r12
    sub rax, 4
    ; Store 3-byte length in big-endian
    mov byte [r13], 0               ; high byte (always 0 for ClientHello)
    mov ecx, eax
    shr ecx, 8
    mov byte [r13 + 1], cl          ; middle byte
    mov byte [r13 + 2], al          ; low byte

    ; Return total length
    sub rdi, r12
    mov rax, rdi

    pop rbp
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; parse_server_hello(rdi=message, rsi=length) -> rax=0 success, -1 error
parse_server_hello:
    push rbx
    push r12
    push r13
    push r14
    push rbp
    mov rbp, rsp

    mov r12, rdi                    ; r12 = message start
    mov r13, rsi                    ; r13 = length

    ; Check handshake type
    cmp byte [rdi], HS_SERVER_HELLO
    jne .parse_error

    ; Get message length
    movzx eax, byte [rdi + 1]
    shl eax, 16
    movzx ebx, byte [rdi + 2]
    shl ebx, 8
    or eax, ebx
    movzx ebx, byte [rdi + 3]
    or eax, ebx                     ; eax = message body length

    add rdi, 4                      ; skip header

    ; Skip legacy version (2 bytes)
    add rdi, 2

    ; Copy server random (32 bytes)
    lea r14, [server_random]
    mov rcx, 32
.copy_random:
    mov al, [rdi]
    mov [r14], al
    inc rdi
    inc r14
    dec rcx
    jnz .copy_random

    ; Skip legacy session ID
    movzx eax, byte [rdi]
    inc rdi
    add rdi, rax

    ; Skip cipher suite (2 bytes) and compression (1 byte)
    add rdi, 3

    ; Parse extensions length
    movzx ebx, byte [rdi]
    shl ebx, 8
    movzx eax, byte [rdi + 1]
    or ebx, eax                     ; ebx = extensions length
    add rdi, 2

.parse_ext_loop:
    cmp ebx, 4
    jl .parse_done                  ; need at least type + length

    ; Extension type (2 bytes big-endian)
    movzx eax, byte [rdi]
    shl eax, 8
    movzx ecx, byte [rdi + 1]
    or eax, ecx                     ; eax = extension type
    add rdi, 2

    ; Extension length (2 bytes big-endian)
    movzx ecx, byte [rdi]
    shl ecx, 8
    movzx r8d, byte [rdi + 1]
    or ecx, r8d                     ; ecx = extension data length
    add rdi, 2

    sub ebx, 4                      ; consumed type + length
    sub ebx, ecx                    ; will consume data

    ; Check for key_share extension (type 51)
    cmp eax, EXT_KEY_SHARE
    je .found_key_share

    ; Check for supported_versions (type 43)
    cmp eax, EXT_SUPPORTED_VERSIONS
    je .check_version

    ; Skip unknown extension
    add rdi, rcx
    jmp .parse_ext_loop

.check_version:
    ; Should be 0x0304 for TLS 1.3
    cmp byte [rdi], 0x03
    jne .parse_error
    cmp byte [rdi + 1], 0x04
    jne .parse_error
    add rdi, rcx
    jmp .parse_ext_loop

.found_key_share:
    ; Parse KeyShareEntry
    ; group (2 bytes) + key_exchange length (2 bytes) + key_exchange

    ; Check group (should be x25519 = 0x001d)
    cmp byte [rdi], 0x00
    jne .parse_error
    cmp byte [rdi + 1], 0x1d
    jne .parse_error
    add rdi, 2

    ; Key exchange length (should be 32)
    cmp byte [rdi], 0x00
    jne .parse_error
    cmp byte [rdi + 1], 0x20
    jne .parse_error
    add rdi, 2

    ; Copy server public key
    lea r14, [server_pubkey]
    mov rcx, 32
.copy_pubkey:
    mov al, [rdi]
    mov [r14], al
    inc rdi
    inc r14
    dec rcx
    jnz .copy_pubkey

    jmp .parse_done

.parse_done:
    xor eax, eax
    jmp .parse_return

.parse_error:
    mov eax, -1

.parse_return:
    pop rbp
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; derive_handshake_secrets(rdi=transcript_hash) -> rax=0
; Key schedule: early_secret → derived → handshake_secret → traffic secrets → keys/IVs
derive_handshake_secrets:
    push rbx
    push r12
    push r13
    push rbp
    mov rbp, rsp
    sub rsp, 128

    mov r12, rdi                    ; r12 = transcript hash pointer

    ; ========================================
    ; early_secret = HKDF-Extract(salt=0, IKM=0)
    ; ========================================
    lea rdi, [early_secret]         ; output
    lea rsi, [zero_salt]            ; salt (32 zeros)
    mov rdx, 32
    lea rcx, [zero_ikm]             ; IKM (32 zeros, no PSK)
    mov r8, 32
    call hkdf_extract

    ; ========================================
    ; derived1 = Derive-Secret(early_secret, "derived", "")
    ;          = HKDF-Expand-Label(early_secret, "derived", empty_hash, 32)
    ; ========================================
    lea rdi, [rsp]                  ; output: derived1
    lea rsi, [early_secret]         ; secret
    lea rdx, [label_derived + 1]    ; label (skip length byte)
    mov rcx, 7                      ; label length
    lea r8, [empty_hash]            ; context = hash of ""
    mov r9, 32                      ; context length
    push 32                         ; output length
    call hkdf_expand_label
    add rsp, 8

    ; ========================================
    ; handshake_secret = HKDF-Extract(salt=derived1, IKM=DHE)
    ; ========================================
    lea rdi, [handshake_secret]     ; output
    lea rsi, [rsp]                  ; salt = derived1
    mov rdx, 32
    lea rcx, [shared_secret]        ; IKM = X25519 shared secret
    mov r8, 32
    call hkdf_extract

    ; ========================================
    ; client_hs_secret = Derive-Secret(hs_secret, "c hs traffic", transcript)
    ; ========================================
    lea rdi, [client_hs_secret]     ; output
    lea rsi, [handshake_secret]     ; secret
    lea rdx, [label_c_hs_traffic + 1]   ; label
    mov rcx, 12                     ; label length
    mov r8, r12                     ; context = transcript hash
    mov r9, 32                      ; context length
    push 32
    call hkdf_expand_label
    add rsp, 8

    ; ========================================
    ; server_hs_secret = Derive-Secret(hs_secret, "s hs traffic", transcript)
    ; ========================================
    lea rdi, [server_hs_secret]     ; output
    lea rsi, [handshake_secret]     ; secret
    lea rdx, [label_s_hs_traffic + 1]
    mov rcx, 12
    mov r8, r12
    mov r9, 32
    push 32
    call hkdf_expand_label
    add rsp, 8

    ; ========================================
    ; Derive client handshake write key and IV
    ; ========================================

    ; client_write_key = HKDF-Expand-Label(client_hs_secret, "key", "", 32)
    lea rdi, [client_write_key]
    lea rsi, [client_hs_secret]
    lea rdx, [label_key + 1]
    mov rcx, 3
    xor r8, r8                      ; no context
    xor r9, r9
    push 32
    call hkdf_expand_label
    add rsp, 8

    ; client_write_iv = HKDF-Expand-Label(client_hs_secret, "iv", "", 12)
    lea rdi, [client_write_iv]
    lea rsi, [client_hs_secret]
    lea rdx, [label_iv + 1]
    mov rcx, 2
    xor r8, r8
    xor r9, r9
    push 12
    call hkdf_expand_label
    add rsp, 8

    ; ========================================
    ; Derive server handshake write key and IV
    ; ========================================

    lea rdi, [server_write_key]
    lea rsi, [server_hs_secret]
    lea rdx, [label_key + 1]
    mov rcx, 3
    xor r8, r8
    xor r9, r9
    push 32
    call hkdf_expand_label
    add rsp, 8

    lea rdi, [server_write_iv]
    lea rsi, [server_hs_secret]
    lea rdx, [label_iv + 1]
    mov rcx, 2
    xor r8, r8
    xor r9, r9
    push 12
    call hkdf_expand_label
    add rsp, 8

    ; ========================================
    ; Pre-compute finished keys
    ; ========================================

    ; client_finished_key = HKDF-Expand-Label(client_hs_secret, "finished", "", 32)
    lea rdi, [client_finished_key]
    lea rsi, [client_hs_secret]
    lea rdx, [label_finished + 1]
    mov rcx, 8
    xor r8, r8
    xor r9, r9
    push 32
    call hkdf_expand_label
    add rsp, 8

    ; server_finished_key = HKDF-Expand-Label(server_hs_secret, "finished", "", 32)
    lea rdi, [server_finished_key]
    lea rsi, [server_hs_secret]
    lea rdx, [label_finished + 1]
    mov rcx, 8
    xor r8, r8
    xor r9, r9
    push 32
    call hkdf_expand_label
    add rsp, 8

    xor eax, eax

    add rsp, 128
    pop rbp
    pop r13
    pop r12
    pop rbx
    ret

; derive_application_secrets(rdi=transcript_hash) -> rax=0
derive_application_secrets:
    push rbx
    push r12
    push rbp
    mov rbp, rsp
    sub rsp, 64

    mov r12, rdi                    ; r12 = transcript hash pointer

    ; ========================================
    ; derived2 = Derive-Secret(handshake_secret, "derived", "")
    ; ========================================
    lea rdi, [rsp]                  ; output: derived2
    lea rsi, [handshake_secret]
    lea rdx, [label_derived + 1]
    mov rcx, 7
    lea r8, [empty_hash]
    mov r9, 32
    push 32
    call hkdf_expand_label
    add rsp, 8

    ; ========================================
    ; master_secret = HKDF-Extract(salt=derived2, IKM=0)
    ; ========================================
    lea rdi, [master_secret]
    lea rsi, [rsp]                  ; salt = derived2
    mov rdx, 32
    lea rcx, [zero_ikm]
    mov r8, 32
    call hkdf_extract

    ; ========================================
    ; client_app_secret = Derive-Secret(master, "c ap traffic", transcript)
    ; ========================================
    lea rdi, [client_app_secret]
    lea rsi, [master_secret]
    lea rdx, [label_c_ap_traffic + 1]
    mov rcx, 12
    mov r8, r12
    mov r9, 32
    push 32
    call hkdf_expand_label
    add rsp, 8

    ; ========================================
    ; server_app_secret = Derive-Secret(master, "s ap traffic", transcript)
    ; ========================================
    lea rdi, [server_app_secret]
    lea rsi, [master_secret]
    lea rdx, [label_s_ap_traffic + 1]
    mov rcx, 12
    mov r8, r12
    mov r9, 32
    push 32
    call hkdf_expand_label
    add rsp, 8

    ; ========================================
    ; Derive application write keys and IVs
    ; ========================================

    ; Client
    lea rdi, [client_write_key]
    lea rsi, [client_app_secret]
    lea rdx, [label_key + 1]
    mov rcx, 3
    xor r8, r8
    xor r9, r9
    push 32
    call hkdf_expand_label
    add rsp, 8

    lea rdi, [client_write_iv]
    lea rsi, [client_app_secret]
    lea rdx, [label_iv + 1]
    mov rcx, 2
    xor r8, r8
    xor r9, r9
    push 12
    call hkdf_expand_label
    add rsp, 8

    ; Server
    lea rdi, [server_write_key]
    lea rsi, [server_app_secret]
    lea rdx, [label_key + 1]
    mov rcx, 3
    xor r8, r8
    xor r9, r9
    push 32
    call hkdf_expand_label
    add rsp, 8

    lea rdi, [server_write_iv]
    lea rsi, [server_app_secret]
    lea rdx, [label_iv + 1]
    mov rcx, 2
    xor r8, r8
    xor r9, r9
    push 12
    call hkdf_expand_label
    add rsp, 8

    xor eax, eax

    add rsp, 64
    pop rbp
    pop r12
    pop rbx
    ret

; build_client_finished -> rax=message length in handshake_buffer
; Finished = HMAC(finished_key, transcript_hash)
build_client_finished:
    push rbx
    push r12
    push rbp
    mov rbp, rsp
    sub rsp, 64

    lea rdi, [handshake_buffer]

    ; Handshake header
    mov byte [rdi], HS_FINISHED     ; type = 20
    mov byte [rdi + 1], 0           ; length high
    mov byte [rdi + 2], 0           ; length middle
    mov byte [rdi + 3], 32          ; length low = 32 (SHA-256 output)
    add rdi, 4

    ; Get current transcript hash (up to but not including this Finished)
    lea rdi, [rsp]
    call sha256_final_keep

    ; verify_data = HMAC(client_finished_key, transcript_hash)
    lea rdi, [client_finished_key]  ; key
    mov rsi, 32                     ; key length
    lea rdx, [rsp]                  ; data = transcript hash
    mov rcx, 32                     ; data length
    lea r8, [handshake_buffer + 4]  ; output
    call hmac_sha256

    mov eax, 36                     ; 4 header + 32 verify_data

    add rsp, 64
    pop rbp
    pop r12
    pop rbx
    ret

; send_record_plaintext(rdi=data, rsi=length) -> rax=bytes sent or -1
send_record_plaintext:
    push rbx
    push r12
    push r13

    mov r12, rdi                    ; data
    mov r13, rsi                    ; length

    ; Build record header in record_buffer
    lea rdi, [record_buffer]
    mov byte [rdi], TLS_HANDSHAKE   ; content type
    mov byte [rdi + 1], 0x03        ; legacy version TLS 1.0
    mov byte [rdi + 2], 0x01
    mov eax, r13d
    mov byte [rdi + 3], ah          ; length high byte
    mov byte [rdi + 4], al          ; length low byte
    add rdi, 5

    ; Copy data
    mov rsi, r12
    mov rcx, r13
    rep movsb

    ; Send via syscall
    mov rax, SYS_WRITE
    mov rdi, [tls_socket]
    lea rsi, [record_buffer]
    lea rdx, [r13 + 5]
    syscall

    pop r13
    pop r12
    pop rbx
    ret

; send_record_encrypted(rdi=plaintext, rsi=length, rdx=content_type) -> rax=bytes or -1
send_record_encrypted:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    mov rbp, rsp
    sub rsp, 128

    mov r12, rdi                    ; plaintext
    mov r13, rsi                    ; plaintext length
    mov r14, rdx                    ; inner content type

    ; Build inner plaintext: data || content_type
    lea rdi, [rsp]
    mov rsi, r12
    mov rcx, r13
    rep movsb
    mov byte [rdi], r14b            ; append inner content type
    inc rdi
    lea r15, [r13 + 1]              ; r15 = inner plaintext length

    ; Compute nonce: IV XOR (sequence number padded to 12 bytes)
    ; sequence_number is 8 bytes, padded with 4 leading zeros
    lea rdi, [rsp + 80]             ; nonce buffer (12 bytes)
    lea rsi, [client_write_iv]
    mov rcx, 12
    rep movsb

    mov rax, [tls_seq_client]
    ; XOR into last 8 bytes of nonce
    xor [rsp + 80 + 4], rax

    ; Build AAD: record header (5 bytes)
    ; Type = APPLICATION_DATA, Version = 0x0303, Length = ciphertext_len
    lea rdi, [rsp + 64]             ; AAD buffer
    mov byte [rdi], TLS_APPLICATION_DATA
    mov byte [rdi + 1], 0x03
    mov byte [rdi + 2], 0x03
    ; Length = plaintext_len + 1 (content type) + 16 (tag)
    lea eax, [r15 + 16]
    mov byte [rdi + 3], ah
    mov byte [rdi + 4], al

    ; Encrypt: chacha20_poly1305_encrypt(out, in, in_len, aad, aad_len, key, nonce)
    lea rdi, [record_buffer + 5]    ; output (after record header)
    lea rsi, [rsp]                  ; input (inner plaintext)
    mov rdx, r15                    ; input length
    lea rcx, [rsp + 64]             ; AAD
    mov r8, 5                       ; AAD length
    lea r9, [client_write_key]      ; key
    ; nonce on stack
    lea rax, [rsp + 80]
    push rax
    call chacha20_poly1305_encrypt
    add rsp, 8

    test rax, rax
    js .send_enc_error
    mov r13, rax                    ; r13 = ciphertext length (includes tag)

    ; Copy AAD to record header
    lea rsi, [rsp + 64]
    lea rdi, [record_buffer]
    mov rcx, 5
    rep movsb

    ; Increment sequence number
    inc qword [tls_seq_client]

    ; Send record
    mov rax, SYS_WRITE
    mov rdi, [tls_socket]
    lea rsi, [record_buffer]
    lea rdx, [r13 + 5]
    syscall

    jmp .send_enc_done

.send_enc_error:
    mov rax, -1

.send_enc_done:
    add rsp, 128
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; recv_record -> rax=body length or -1, record in record_buffer
recv_record:
    push rbx
    push r12

    ; Read record header (5 bytes)
    mov rax, SYS_READ
    mov rdi, [tls_socket]
    lea rsi, [record_buffer]
    mov rdx, 5
    syscall
    cmp rax, 5
    jl .recv_error

    ; Get record body length (big-endian)
    movzx eax, byte [record_buffer + 3]
    shl eax, 8
    movzx ebx, byte [record_buffer + 4]
    or eax, ebx
    mov r12d, eax                   ; r12 = body length

    ; Sanity check length
    cmp r12d, 16640
    ja .recv_error

    ; Read record body
    xor ebx, ebx                    ; bytes read so far
.recv_body_loop:
    mov rax, SYS_READ
    mov rdi, [tls_socket]
    lea rsi, [record_buffer + 5]
    add rsi, rbx
    mov rdx, r12
    sub rdx, rbx
    syscall
    test rax, rax
    jle .recv_error
    add rbx, rax
    cmp rbx, r12
    jl .recv_body_loop

    mov rax, r12
    jmp .recv_done

.recv_error:
    mov rax, -1

.recv_done:
    pop r12
    pop rbx
    ret

; decrypt_record(rdi=output, rsi=record, rdx=ct_len, rcx=0:server/1:client) -> rax=pt_len or -1
decrypt_record:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    mov rbp, rsp
    sub rsp, 64

    mov r12, rdi                    ; output
    mov r13, rsi                    ; input (full record)
    mov r14, rdx                    ; ciphertext length
    mov r15, rcx                    ; key selector

    ; Compute nonce
    lea rdi, [rsp]
    test r15, r15
    jnz .use_client_iv_dec
    lea rsi, [server_write_iv]
    mov rax, [tls_seq_server]
    jmp .compute_nonce_dec
.use_client_iv_dec:
    lea rsi, [client_write_iv]
    mov rax, [tls_seq_client]
.compute_nonce_dec:
    mov rcx, 12
    rep movsb
    xor [rsp + 4], rax

    ; AAD is the record header (5 bytes)
    ; Already in r13

    ; Select key
    test r15, r15
    jnz .use_client_key_dec
    lea rbx, [server_write_key]
    jmp .do_decrypt
.use_client_key_dec:
    lea rbx, [client_write_key]

.do_decrypt:
    ; Decrypt: chacha20_poly1305_decrypt(out, in, in_len, aad, aad_len, key, nonce)
    mov rdi, r12                    ; output
    lea rsi, [r13 + 5]              ; ciphertext (after header)
    mov rdx, r14                    ; ciphertext length (includes tag)
    mov rcx, r13                    ; AAD = record header
    mov r8, 5                       ; AAD length
    mov r9, rbx                     ; key
    lea rax, [rsp]
    push rax                        ; nonce
    call chacha20_poly1305_decrypt
    add rsp, 8

    test rax, rax
    js .decrypt_error

    ; Increment sequence number
    test r15, r15
    jnz .inc_client_seq
    inc qword [tls_seq_server]
    jmp .decrypt_done
.inc_client_seq:
    inc qword [tls_seq_client]
    jmp .decrypt_done

.decrypt_error:
    mov rax, -1

.decrypt_done:
    add rsp, 64
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; tls_send(rdi=data, rsi=length) -> rax=bytes sent or -1
tls_send:
    push rbx
    push r12
    push r13

    mov r12, rdi
    mov r13, rsi

    ; Use send_record_encrypted with APPLICATION_DATA type
    mov rdi, r12
    mov rsi, r13
    mov rdx, TLS_APPLICATION_DATA
    call send_record_encrypted

    pop r13
    pop r12
    pop rbx
    ret

; tls_recv(rdi=buffer, rsi=max_length) -> rax=bytes received or -1
tls_recv:
    push rbx
    push r12
    push r13
    push rbp
    mov rbp, rsp

    mov r12, rdi                    ; output buffer
    mov r13, rsi                    ; max length

.recv_app_loop:
    ; Receive record
    call recv_record
    test rax, rax
    js .tls_recv_error
    mov rbx, rax

    ; Check record type
    movzx eax, byte [record_buffer]

    ; Skip Change Cipher Spec
    cmp al, TLS_CHANGE_CIPHER_SPEC
    je .recv_app_loop

    ; Should be Application Data
    cmp al, TLS_APPLICATION_DATA
    jne .tls_recv_error

    ; Decrypt
    lea rdi, [decrypt_buffer]
    lea rsi, [record_buffer]
    mov rdx, rbx
    xor rcx, rcx                    ; server keys
    call decrypt_record
    test rax, rax
    js .tls_recv_error

    ; Check inner content type (last byte)
    lea rdi, [decrypt_buffer]
    add rdi, rax
    dec rdi
    movzx ecx, byte [rdi]
    dec rax                         ; remove content type byte

    ; If it's handshake data (like NewSessionTicket), skip it
    cmp cl, TLS_HANDSHAKE
    je .recv_app_loop

    ; If it's an alert, handle it
    cmp cl, TLS_ALERT
    je .tls_recv_error

    ; Should be APPLICATION_DATA
    cmp cl, TLS_APPLICATION_DATA
    jne .tls_recv_error

    ; Copy to output (respecting max length)
    cmp rax, r13
    cmova rax, r13
    mov rbx, rax

    mov rdi, r12
    lea rsi, [decrypt_buffer]
    mov rcx, rbx
    rep movsb

    mov rax, rbx
    jmp .tls_recv_done

.tls_recv_error:
    mov rax, -1

.tls_recv_done:
    pop rbp
    pop r13
    pop r12
    pop rbx
    ret

; tls_close -> rax=0
tls_close:
    ; Send close_notify alert (optional, skipped for minimal implementation)

    ; Close socket
    mov rax, SYS_CLOSE
    mov rdi, [tls_socket]
    syscall

    xor eax, eax
    ret

; get_random_bytes(rdi=buffer, rsi=count) -> rax=0 success, -1 error
get_random_bytes:
    push rbx
    push r12
    push r13

    mov r12, rdi                    ; buffer
    mov r13, rsi                    ; count

    ; Try getrandom syscall first (Linux 3.17+)
    mov rax, SYS_GETRANDOM
    mov rdi, r12
    mov rsi, r13
    xor rdx, rdx                    ; flags = 0
    syscall

    cmp rax, r13
    je .random_success

    ; Fallback: read from /dev/urandom
    mov rax, SYS_OPEN
    lea rdi, [.urandom_path]
    xor rsi, rsi                    ; O_RDONLY
    xor rdx, rdx
    syscall
    test rax, rax
    js .random_error
    mov rbx, rax                    ; fd

    mov rax, SYS_READ
    mov rdi, rbx
    mov rsi, r12
    mov rdx, r13
    syscall
    push rax

    ; Close fd
    mov rax, SYS_CLOSE
    mov rdi, rbx
    syscall

    pop rax
    cmp rax, r13
    jne .random_error

.random_success:
    xor eax, eax
    jmp .random_done

.random_error:
    mov eax, -1

.random_done:
    pop r13
    pop r12
    pop rbx
    ret

.urandom_path:
    db "/dev/urandom", 0

