; NegativeClaw - Minimal AI agent in pure x86-64 assembly
; Target: Linux x86-64, no libc, direct syscalls only

BITS 64
DEFAULT REL

; Syscall numbers
SYS_READ      equ 0
SYS_WRITE     equ 1
SYS_OPEN      equ 2
SYS_CLOSE     equ 3
SYS_SOCKET    equ 41
SYS_CONNECT   equ 42
SYS_SENDTO    equ 44
SYS_RECVFROM  equ 45
SYS_EXIT      equ 60

; Socket constants
AF_INET       equ 2
SOCK_STREAM   equ 1
SOCK_DGRAM    equ 2

; File descriptors
STDIN         equ 0
STDOUT        equ 1

; Buffer sizes
INPUT_BUF_SIZE  equ 4096
OUTPUT_BUF_SIZE equ 65536
HTTP_BUF_SIZE   equ 16384

; DNS
DNS_PORT      equ 53

section .bss
    input_buffer:    resb INPUT_BUF_SIZE
    output_buffer:   resb OUTPUT_BUF_SIZE
    http_buffer:     resb HTTP_BUF_SIZE
    socket_fd:       resq 1
    resolved_ip:     resd 1
    dns_buffer:      resb 512
    dns_server_ip:   resd 1
    api_key_ptr:     resq 1          ; -> ANTHROPIC_API_KEY value in envp
    api_key_len:     resq 1

section .data
    api_host:        db "api.anthropic.com", 0
    api_host_len:    equ $ - api_host - 1
    http_post:       db "POST /v1/messages HTTP/1.1", 13, 10
                     db "Host: api.anthropic.com", 13, 10
                     db "Content-Type: application/json", 13, 10
                     db "x-api-key: "
    http_post_len:   equ $ - http_post

    http_headers2:   db 13, 10
                     db "anthropic-version: 2023-06-01", 13, 10
                     db "Connection: close", 13, 10
                     db "Content-Length: "
    http_headers2_len: equ $ - http_headers2

    ; JSON request body template
    json_prefix:     db '{"model":"claude-sonnet-4-20250514","max_tokens":1024,"messages":[{"role":"user","content":"'
    json_prefix_len: equ $ - json_prefix

    json_suffix:     db '"}]}'
    json_suffix_len: equ $ - json_suffix

    prompt_str:      db "> "
    prompt_len:      equ 2
    newline:         db 10

    fallback_ip:     dd 0x072012_68     ; 104.18.32.7 in network byte order
    default_dns:     dd 0x08080808      ; Google DNS 8.8.8.8
    resolv_conf:     db "/etc/resolv.conf", 0

section .text
    global _start
    extern tls_handshake
    extern tls_send
    extern tls_recv
    extern tls_close

_start:
    ; Load API key from ANTHROPIC_API_KEY env var (exits if missing)
    mov rdi, rsp
    call load_api_key

    mov rax, SYS_WRITE
    mov rdi, STDOUT
    lea rsi, [banner]
    mov rdx, banner_len
    syscall

    call parse_resolv_conf

    lea rdi, [api_host]
    call resolve_hostname
    test rax, rax
    js .use_fallback_ip

    mov [resolved_ip], eax
    jmp .main_loop

.use_fallback_ip:
    mov eax, [fallback_ip]
    mov [resolved_ip], eax

.main_loop:
    mov rax, SYS_WRITE
    mov rdi, STDOUT
    lea rsi, [prompt_str]
    mov rdx, prompt_len
    syscall

    mov rax, SYS_READ
    mov rdi, STDIN
    lea rsi, [input_buffer]
    mov rdx, INPUT_BUF_SIZE - 1
    syscall
    test rax, rax
    jle .exit

    mov r12, rax
    dec r12
    mov byte [input_buffer + r12], 0   ; strip newline, null-terminate
    test r12, r12
    jz .main_loop

    lea rsi, [input_buffer]
    lea rdi, [quit_cmd]
    call strcmp
    test eax, eax
    jz .exit

    lea rdi, [input_buffer]
    mov rsi, r12
    call call_claude_api
    test r13, r13                       ; r13 = response length
    jz .main_loop

    mov rax, SYS_WRITE
    mov rdi, STDOUT
    lea rsi, [output_buffer]
    mov rdx, r13
    syscall

    mov rax, SYS_WRITE
    mov rdi, STDOUT
    lea rsi, [newline]
    mov rdx, 1
    syscall

    jmp .main_loop

.exit:
    mov rax, SYS_EXIT
    xor rdi, rdi
    syscall

; call_claude_api(rdi=message, rsi=length) -> r13=response length in output_buffer
call_claude_api:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r14
    push r15

    mov r14, rdi                    ; message ptr
    mov r15, rsi                    ; message len

    call create_socket
    test rax, rax
    js .api_error
    mov [socket_fd], rax

    mov rdi, [socket_fd]
    call connect_to_api
    test rax, rax
    js .api_error_close

    mov rdi, [socket_fd]
    call tls_handshake
    test rax, rax
    js .api_error_close

    mov rdi, r14
    mov rsi, r15
    call build_http_request
    test rax, rax
    js .api_error_close
    mov r12, rax                    ; request length

    lea rdi, [http_buffer]
    mov rsi, r12
    call tls_send
    test rax, rax
    js .api_error_close

    ; Receive full response (may span multiple TLS records)
    xor r13, r13                    ; total bytes received
.recv_loop:
    lea rdi, [output_buffer + r13]
    mov rsi, OUTPUT_BUF_SIZE
    sub rsi, r13
    jle .recv_done                  ; buffer full
    call tls_recv
    test rax, rax
    jle .recv_done                  ; error/close = end of response
    add r13, rax
    jmp .recv_loop
.recv_done:
    test r13, r13
    jz .api_error_close             ; nothing received

    lea rdi, [output_buffer]
    mov rsi, r13
    call extract_content
    mov r13, rax

    call tls_close

    mov rax, SYS_CLOSE
    mov rdi, [socket_fd]
    syscall

    pop r15
    pop r14
    pop r12
    pop rbx
    pop rbp
    ret

.api_error_close:
    mov rax, SYS_CLOSE
    mov rdi, [socket_fd]
    syscall

.api_error:
    lea rsi, [error_msg]
    lea rdi, [output_buffer]
    mov rcx, error_msg_len
    rep movsb
    mov r13, error_msg_len

    pop r15
    pop r14
    pop r12
    pop rbx
    pop rbp
    ret

; create_socket() -> rax=fd or negative on error
create_socket:
    mov rax, SYS_SOCKET
    mov rdi, AF_INET
    mov rsi, SOCK_STREAM
    xor rdx, rdx
    syscall
    ret

; connect_to_api(rdi=socket_fd) -> rax=0 or negative on error
connect_to_api:
    push rbp
    mov rbp, rsp
    sub rsp, 32

    mov r8, rdi

    ; Build sockaddr_in: AF_INET, port 443, resolved IP
    xor eax, eax
    mov [rsp], rax
    mov [rsp + 8], rax
    mov word [rsp], AF_INET
    mov word [rsp + 2], 0xBB01      ; port 443 network order
    mov eax, [resolved_ip]
    mov [rsp + 4], eax

    mov rax, SYS_CONNECT
    mov rdi, r8
    lea rsi, [rsp]
    mov rdx, 16
    syscall

    leave
    ret

; parse_resolv_conf() -> sets dns_server_ip from /etc/resolv.conf or default
parse_resolv_conf:
    push rbx
    push r12
    push r13

    ; Open /etc/resolv.conf
    mov rax, SYS_OPEN
    lea rdi, [resolv_conf]
    xor rsi, rsi                    ; O_RDONLY
    xor rdx, rdx
    syscall
    test rax, rax
    js .use_default_dns
    mov r12, rax                    ; save fd

    ; Read file
    mov rax, SYS_READ
    mov rdi, r12
    lea rsi, [dns_buffer]
    mov rdx, 512
    syscall
    mov r13, rax                    ; bytes read

    ; Close file
    mov rax, SYS_CLOSE
    mov rdi, r12
    syscall

    ; Search for "nameserver " prefix
    lea rdi, [dns_buffer]

.search_ns:
    cmp r13, 11                     ; need at least "nameserver "
    jl .use_default_dns

    ; Match "nameserver " (11 chars) via 4+4+3 byte comparisons
    mov eax, [rdi]
    cmp eax, 'name'
    jne .next_line
    mov eax, [rdi + 4]
    cmp eax, 'serv'
    jne .next_line
    mov eax, [rdi + 8]
    and eax, 0x00FFFFFF
    cmp eax, 0x002072_65            ; "er "
    jne .next_line

    add rdi, 11
    call parse_ip_address
    test rax, rax
    js .use_default_dns
    mov [dns_server_ip], eax
    jmp .parse_done

.next_line:
    ; Find next line
    mov al, [rdi]
    cmp al, 10
    je .found_newline
    cmp al, 0
    je .use_default_dns
    inc rdi
    dec r13
    jmp .next_line

.found_newline:
    inc rdi
    dec r13
    jmp .search_ns

.use_default_dns:
    mov eax, [default_dns]
    mov [dns_server_ip], eax

.parse_done:
    pop r13
    pop r12
    pop rbx
    ret

; parse_ip_address(rdi=string) -> eax=IP in network byte order, or -1
parse_ip_address:
    push rbx
    push r12

    xor r12d, r12d                  ; result accumulator
    xor ecx, ecx                    ; octet count

.parse_octet:
    xor eax, eax                    ; current octet value
    xor ebx, ebx                    ; digit count

.parse_digit:
    movzx edx, byte [rdi]

    cmp dl, '0'
    jl .end_octet
    cmp dl, '9'
    jg .end_octet

    imul eax, 10
    sub dl, '0'
    add eax, edx
    inc rdi
    inc ebx
    cmp ebx, 3
    jle .parse_digit
    jmp .parse_error

.end_octet:
    cmp eax, 255
    ja .parse_error
    test ebx, ebx
    jz .parse_error

    shl r12d, 8                     ; accumulate octets big-endian
    or r12d, eax
    inc ecx

    cmp dl, '.'
    jne .check_complete
    inc rdi
    cmp ecx, 4
    jl .parse_octet
    jmp .parse_error

.check_complete:
    cmp ecx, 4
    jne .parse_error

    mov eax, r12d
    bswap eax                       ; convert to network byte order

    pop r12
    pop rbx
    ret

.parse_error:
    mov eax, -1
    pop r12
    pop rbx
    ret

; resolve_hostname(rdi=hostname) -> eax=IP network order, or -1
resolve_hostname:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    mov rbp, rsp
    sub rsp, 128

    mov r14, rdi

    mov rax, SYS_SOCKET
    mov rdi, AF_INET
    mov rsi, SOCK_DGRAM
    xor rdx, rdx                    ; UDP socket for DNS
    syscall
    test rax, rax
    js .dns_error
    mov r12, rax

    ; Build DNS query header
    lea rdi, [dns_buffer]
    mov r15, rdi
    rdtsc
    mov [rdi], ax                   ; transaction ID from TSC
    add rdi, 2
    mov word [rdi], 0x0001          ; flags: RD=1
    add rdi, 2
    mov word [rdi], 0x0100          ; QDCOUNT=1 big-endian
    add rdi, 2
    xor eax, eax
    mov [rdi], eax                  ; ANCOUNT, NSCOUNT = 0
    add rdi, 4
    mov [rdi], ax                   ; ARCOUNT = 0
    add rdi, 2

    ; Encode hostname as DNS label sequence
    mov rsi, r14

.encode_label:
    mov r13, rdi                    ; length-byte position
    inc rdi
    xor ecx, ecx
.copy_label:
    mov al, [rsi]
    test al, al
    jz .end_labels
    cmp al, '.'
    je .end_one_label
    mov [rdi], al
    inc rdi
    inc rsi
    inc ecx
    cmp ecx, 63
    jle .copy_label
    jmp .dns_error_close

.end_one_label:
    mov [r13], cl
    inc rsi
    jmp .encode_label

.end_labels:
    mov [r13], cl
    mov byte [rdi], 0               ; root label terminator
    inc rdi
    mov word [rdi], 0x0100          ; QTYPE=A
    add rdi, 2
    mov word [rdi], 0x0100          ; QCLASS=IN
    add rdi, 2

    sub rdi, r15
    mov r13, rdi                    ; query length

    ; Build DNS server sockaddr_in
    lea rdi, [rsp]
    xor eax, eax
    mov [rdi], rax
    mov [rdi + 8], rax
    mov word [rdi], AF_INET
    mov word [rdi + 2], 0x3500      ; port 53 network order
    mov eax, [dns_server_ip]
    mov [rdi + 4], eax

    mov rax, SYS_SENDTO
    mov rdi, r12
    mov rsi, r15
    mov rdx, r13
    xor r10, r10
    lea r8, [rsp]
    mov r9, 16
    syscall
    test rax, rax
    js .dns_error_close

    mov rax, SYS_RECVFROM
    mov rdi, r12
    mov rsi, r15
    mov rdx, 512
    xor r10, r10
    xor r8, r8
    xor r9, r9
    syscall
    test rax, rax
    js .dns_error_close
    mov r13, rax

    mov rax, SYS_CLOSE
    mov rdi, r12
    syscall

    ; Parse DNS response
    lea rdi, [dns_buffer]
    movzx eax, word [rdi + 6]      ; ANCOUNT
    xchg al, ah
    test eax, eax
    jz .dns_error

    add rdi, 12                     ; skip header
.skip_qname:
    movzx eax, byte [rdi]
    test al, al
    jz .qname_done
    cmp al, 0xC0                    ; compression pointer
    jae .skip_ptr
    add rdi, rax
    inc rdi
    jmp .skip_qname
.skip_ptr:
    add rdi, 2
    jmp .parse_answer
.qname_done:
    inc rdi

    add rdi, 4                      ; skip QTYPE + QCLASS

.parse_answer:
    ; Skip answer name (may be compressed)
    movzx eax, byte [rdi]
    cmp al, 0xC0
    jae .skip_ans_ptr
.skip_ans_name:
    test al, al
    jz .ans_name_done
    add rdi, rax
    inc rdi
    movzx eax, byte [rdi]
    jmp .skip_ans_name
.ans_name_done:
    inc rdi
    jmp .check_type
.skip_ans_ptr:
    add rdi, 2

.check_type:
    movzx eax, word [rdi]
    xchg al, ah
    cmp eax, 1                      ; TYPE must be A (IPv4)
    jne .dns_error

    add rdi, 8                      ; skip TYPE(2)+CLASS(2)+TTL(4)

    movzx eax, word [rdi]
    xchg al, ah
    cmp eax, 4                      ; RDLENGTH must be 4 (IPv4)
    jne .dns_error
    add rdi, 2

    mov eax, [rdi]                  ; IP already in network byte order

    add rsp, 128
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

.dns_error_close:
    mov rax, SYS_CLOSE
    mov rdi, r12
    syscall

.dns_error:
    mov eax, -1
    add rsp, 128
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; load_api_key(rdi=stack_base) — find ANTHROPIC_API_KEY in envp or exit
load_api_key:
    push r12
    push r13

    ; envp = past argc + argv[] + NULL terminator
    mov rax, [rdi]                  ; argc
    lea r12, [rdi + 8*rax + 16]    ; envp start

.scan_env:
    mov r13, [r12]
    test r13, r13                   ; NULL = end of envp
    jz .key_missing

    ; Compare "ANTHROPIC_API_KEY=" prefix
    mov rdi, r13
    lea rsi, [env_key_prefix]
    mov ecx, env_key_pfx_len
.cmp_prefix:
    mov al, [rdi]
    cmp al, [rsi]
    jne .next_env
    inc rdi
    inc rsi
    dec ecx
    jnz .cmp_prefix

    ; Match — rdi points past '='
    mov [api_key_ptr], rdi
    xor ecx, ecx
.key_strlen:
    cmp byte [rdi + rcx], 0
    je .key_found
    inc ecx
    jmp .key_strlen

.key_found:
    mov [api_key_len], rcx
    pop r13
    pop r12
    ret

.next_env:
    add r12, 8
    jmp .scan_env

.key_missing:
    mov rax, SYS_WRITE
    mov rdi, STDOUT
    lea rsi, [key_error_msg]
    mov rdx, key_error_len
    syscall
    mov rax, SYS_EXIT
    mov rdi, 1
    syscall

; build_http_request(rdi=msg, rsi=len) -> rax=total length in http_buffer, or -1 if too large
build_http_request:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13
    push r14

    mov r12, rdi
    mov r13, rsi

    ; Guard: worst case = ~400 (headers+json) + 2*msg_len (all chars escaped)
    lea rax, [r13 * 2 + 400]
    cmp rax, HTTP_BUF_SIZE
    jae .request_too_large

    lea rdi, [http_buffer]
    mov r14, rdi

    ; Assemble headers: POST line, API key, version, content-length
    lea rsi, [http_post]
    mov rcx, http_post_len
    rep movsb
    mov rsi, [api_key_ptr]
    mov rcx, [api_key_len]
    rep movsb
    lea rsi, [http_headers2]
    mov rcx, http_headers2_len
    rep movsb

    ; Count extra bytes from JSON escaping (each ", \, LF, CR adds 1 byte)
    mov rsi, r12
    mov rcx, r13
    xor eax, eax
.count_esc:
    test rcx, rcx
    jz .esc_done
    mov dl, [rsi]
    inc rsi
    dec rcx
    cmp dl, '"'
    je .esc_inc
    cmp dl, '\'
    je .esc_inc
    cmp dl, 10
    je .esc_inc
    cmp dl, 13
    je .esc_inc
    jmp .count_esc
.esc_inc:
    inc eax
    jmp .count_esc
.esc_done:
    ; Body length = json_prefix + (raw_len + escape_extras) + json_suffix
    add rax, r13
    add rax, json_prefix_len
    add rax, json_suffix_len
    mov rbx, rax
    push rdi
    call int_to_ascii               ; write content-length digits
    pop rsi
    mov rdi, rsi
    add rdi, rax

    ; End of headers (double CRLF)
    mov byte [rdi], 13
    mov byte [rdi + 1], 10
    mov byte [rdi + 2], 13
    mov byte [rdi + 3], 10
    add rdi, 4

    lea rsi, [json_prefix]
    mov rcx, json_prefix_len
    rep movsb

    ; Copy message with JSON escape handling
    mov rsi, r12
    mov rcx, r13
.copy_message:
    test rcx, rcx
    jz .message_done
    lodsb

    cmp al, '"'
    je .escape_quote
    cmp al, '\'
    je .escape_backslash
    cmp al, 10
    je .escape_newline
    cmp al, 13
    je .escape_cr

    stosb
    dec rcx
    jmp .copy_message

.escape_quote:
    mov byte [rdi], '\'
    mov byte [rdi + 1], '"'
    add rdi, 2
    dec rcx
    jmp .copy_message

.escape_backslash:
    mov byte [rdi], '\'
    mov byte [rdi + 1], '\'
    add rdi, 2
    dec rcx
    jmp .copy_message

.escape_newline:
    mov byte [rdi], '\'
    mov byte [rdi + 1], 'n'
    add rdi, 2
    dec rcx
    jmp .copy_message

.escape_cr:
    mov byte [rdi], '\'
    mov byte [rdi + 1], 'r'
    add rdi, 2
    dec rcx
    jmp .copy_message

.message_done:
    lea rsi, [json_suffix]
    mov rcx, json_suffix_len
    rep movsb

    sub rdi, r14
    mov rax, rdi
    jmp .build_done

.request_too_large:
    mov rax, -1

.build_done:
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

; strcmp(rsi, rdi) -> eax=0 if equal
strcmp:
    push rcx
.loop:
    mov al, [rsi]
    mov cl, [rdi]
    cmp al, cl
    jne .not_equal
    test al, al
    jz .equal
    inc rsi
    inc rdi
    jmp .loop
.equal:
    xor eax, eax
    pop rcx
    ret
.not_equal:
    mov eax, 1
    pop rcx
    ret

; int_to_ascii(rax=number, rdi=buffer) -> rax=digits written
int_to_ascii:
    push rbx
    push rcx
    push rdx
    push rdi

    mov rbx, rax
    mov rcx, 10
    xor r8d, r8d

    test rbx, rbx
    jnz .convert
    mov byte [rdi], '0'
    mov rax, 1
    jmp .done

.convert:
    mov r9, rdi
.count_loop:
    xor rdx, rdx
    div rcx
    push rdx
    inc r8d
    test rax, rax
    jnz .count_loop

    mov rcx, r8
.write_loop:
    pop rax
    add al, '0'
    stosb
    dec rcx
    jnz .write_loop

    mov rax, r8

.done:
    add rsp, 8                      ; discard saved rdi
    pop rdx
    pop rcx
    pop rbx
    ret

; extract_content(rdi=buffer, rsi=length) -> rax=content length at buffer start
extract_content:
    push rbx
    push r12
    push r13

    mov r12, rdi
    mov r13, rsi

    ; Skip HTTP headers (find \r\n\r\n)
.find_body:
    cmp r13, 4
    jl .not_found

    mov eax, [rdi]
    cmp eax, 0x0A0D0A0D
    je .found_body
    inc rdi
    dec r13
    jmp .find_body

.found_body:
    add rdi, 4
    sub r13, 4                      ; account for skipped \r\n\r\n

    ; Search for "text":" in content array (Claude API response)
.search_text:
    cmp r13, 8
    jl .try_message

    mov eax, [rdi]
    cmp eax, '"tex'
    jne .try_content_inline
    mov eax, [rdi + 4]
    and eax, 0x00FFFFFF
    cmp eax, 0x00223A74             ; t":"
    jne .try_content_inline

    add rdi, 7
    jmp .extract

.try_content_inline:
    inc rdi
    dec r13
    jmp .search_text

.try_message:
    ; Fallback: try "message":" field (API error responses)
    mov rdi, r12
    mov r13, rsi

.search_message:
    cmp r13, 11
    jl .not_found

    mov rax, [rdi]
    mov rcx, '"message'
    cmp rax, rcx
    jne .next_message
    mov ax, [rdi + 8]
    cmp ax, '":'
    jne .next_message
    cmp byte [rdi + 10], '"'
    jne .next_message

    add rdi, 11
    jmp .extract

.next_message:
    inc rdi
    dec r13
    jmp .search_message

.extract:
    ; Copy content until closing quote, handling escape sequences
    mov rsi, rdi
    mov rdi, r12
    xor rax, rax

.copy_content:
    mov cl, [rsi]
    test cl, cl
    jz .done_extract
    cmp cl, '"'
    je .done_extract

    cmp cl, '\'
    jne .store_char

    inc rsi
    mov cl, [rsi]
    cmp cl, 'n'
    jne .check_other_escape
    mov cl, 10
    jmp .store_char

.check_other_escape:
    cmp cl, 'r'
    jne .check_tab
    mov cl, 13
    jmp .store_char

.check_tab:
    cmp cl, 't'
    jne .store_char
    mov cl, 9

.store_char:
    mov [rdi], cl
    inc rdi
    inc rsi
    inc rax
    jmp .copy_content

.not_found:
    lea rsi, [parse_error]
    mov rdi, r12
    mov rcx, parse_error_len
    rep movsb
    mov rax, parse_error_len
    jmp .return

.done_extract:
.return:
    pop r13
    pop r12
    pop rbx
    ret

section .data
    banner:          db "NegativeClaw v0.1 - Minimal AI Agent", 10
                     db "Type your message or 'quit' to exit", 10, 10
    banner_len:      equ $ - banner

    quit_cmd:        db "quit", 0

    error_msg:       db "Error: API call failed"
    error_msg_len:   equ $ - error_msg

    parse_error:     db "Error: Could not parse response"
    parse_error_len: equ $ - parse_error

    env_key_prefix:  db "ANTHROPIC_API_KEY="
    env_key_pfx_len: equ $ - env_key_prefix

    key_error_msg:   db "Error: set ANTHROPIC_API_KEY environment variable", 10
    key_error_len:   equ $ - key_error_msg
