import os
import lief
import json
import argparse
from keystone import Ks, KS_ARCH_ARM, KS_ARCH_ARM64, KS_ARCH_MIPS, KS_ARCH_MIPS64, KS_ARCH_X86, KS_MODE_32, KS_MODE_64, KS_MODE_ARM


def find_binaries(directory):
    binaries = []
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            if is_binary(file_path):
                binaries.append(file_path)
    return binaries


def is_binary(file_path):
    with open(file_path, 'rb') as file:
        header = file.read(4)
        return header[:4] == b'\x7fELF' or header[:2] == b'MZ'


def find_functions(binary):
    functions = []
    for function in binary.symbols:
        if function.type == lief.ELF.SYMBOL_TYPES.FUNC:
            functions.append((function.name, function.value))
    return functions


def instrument_binary(binary_path, ip, msg_port, exec_port):
    binary = lief.parse(binary_path)
    functions = find_functions(binary)
    arch = binary.header.machine_type

    cli_functions = ["execl", "execle", "execlp", "execv", "execvp", "execvpe", "system", "popen"]

    for function_name, function_addr in functions:
        section = binary.get_section(".text")
        code = section.content

        function_start = function_addr
        calls_cli_function = False
        for insn in binary.get_section(".text").instructions:
            if insn.symbol and insn.symbol.name in cli_functions and function_addr <= insn.address < function_addr + len(code):
                calls_cli_function = True
                break

        ks = None
        reach_code = None
        exec_code = None

        if arch == lief.ELF.ARCH.x86:
            ks = Ks(KS_ARCH_X86, KS_MODE_32)
            if calls_cli_function:
                reach_code = generate_socket_code_x86_32(ip, msg_port, f"SINK <FILE>{binary.name}</FILE><NAME>{function_name}</NAME>")
            else:
                reach_code = generate_socket_code_x86_32(ip, msg_port, f"INTERMEDIATE <FILE>{binary.name}</FILE><NAME>{function_name}</NAME>")
            exec_code = generate_exec_socket_code_x86_32(ip, exec_port)
        elif arch == lief.ELF.ARCH.x86_64:
            ks = Ks(KS_ARCH_X86, KS_MODE_64)
            if calls_cli_function:
                reach_code = generate_socket_code_x86_64(ip, msg_port, f"SINK <FILE>{binary.name}</FILE><NAME>{function_name}</NAME>")
            else:
                reach_code = generate_socket_code_x86_64(ip, msg_port, f"INTERMEDIATE <FILE>{binary.name}</FILE><NAME>{function_name}</NAME>")
            exec_code = generate_exec_socket_code_x86_64(ip, exec_port)
        elif arch == lief.ELF.ARCH.ARM:
            ks = Ks(KS_ARCH_ARM, KS_MODE_ARM)
            if calls_cli_function:
                reach_code = generate_socket_code_arm(ip, msg_port, f"SINK <FILE>{binary.name}</FILE><NAME>{function_name}</NAME>")
            else:
                reach_code = generate_socket_code_arm(ip, msg_port, f"INTERMEDIATE <FILE>{binary.name}</FILE><NAME>{function_name}</NAME>")
            exec_code = generate_exec_socket_code_arm(ip, exec_port)
        elif arch == lief.ELF.ARCH.AARCH64:
            ks = Ks(KS_ARCH_ARM64, KS_MODE_64)
            if calls_cli_function:
                reach_code = generate_socket_code_arm64(ip, msg_port, f"SINK <FILE>{binary.name}</FILE><NAME>{function_name}</NAME>")
            else:
                reach_code = generate_socket_code_arm64(ip, msg_port, f"INTERMEDIATE <FILE>{binary.name}</FILE><NAME>{function_name}</NAME>")
            exec_code = generate_exec_socket_code_arm64(ip, exec_port)
        elif arch == lief.ELF.ARCH.MIPS:
            ks = Ks(KS_ARCH_MIPS, KS_MODE_32)
            if calls_cli_function:
                reach_code = generate_socket_code_mips_32(ip, msg_port, f"SINK <FILE>{binary.name}</FILE><NAME>{function_name}</NAME>")
            else:
                reach_code = generate_socket_code_mips_32(ip, msg_port, f"INTERMEDIATE <FILE>{binary.name}</FILE><NAME>{function_name}</NAME>")
            exec_code = generate_exec_socket_code_mips_32(ip, exec_port)
        elif arch == lief.ELF.ARCH.MIPS64:
            ks = Ks(KS_ARCH_MIPS64, KS_MODE_64)
            if calls_cli_function:
                reach_code = generate_socket_code_mips_64(ip, msg_port, f"SINK <FILE>{binary.name}</FILE><NAME>{function_name}</NAME>")
            else:
                reach_code = generate_socket_code_mips_64(ip, msg_port, f"INTERMEDIATE <FILE>{binary.name}</FILE><NAME>{function_name}</NAME>")
            exec_code = generate_exec_socket_code_mips_64(ip, exec_port)
        else:
            raise ValueError("Unsupported architecture")

        reach_bytes, _ = ks.asm(reach_code)
        exec_bytes, _ = ks.asm(exec_code)

        code = code[:function_start] + bytes(reach_bytes) + code[function_start:]

        if calls_cli_function:
            for insn in binary.get_section(".text").instructions:
                if insn.symbol and insn.symbol.name in cli_functions and function_addr <= insn.address < function_addr + len(code):
                    call_addr = insn.address
                    call_end = call_addr + len(insn.bytes)
                    code = code[:call_end] + bytes(exec_bytes) + code[call_end:]

        section.content = code
    
    output_path = binary_path + ".instrumented"
    binary.write(output_path)


def generate_socket_code_x86_32(ip, port, message):
    ip_hex = ''.join([hex(int(x))[2:].zfill(2) for x in ip.split('.')])
    port_hex = hex(port)[2:].zfill(4)
    ip_port_hex = port_hex + ip_hex

    return f"""
    ; Setup socket
    push 0
    push 1
    push 2
    mov eax, 0x66       ; socketcall
    mov ebx, 1          ; SYS_SOCKET
    int 0x80

    mov esi, eax        ; Save socket fd

    ; Connect to remote server
    push 0
    push 0x{ip_port_hex[8:]}
    push 0x{ip_port_hex[:8]}
    mov ecx, esp
    push 16
    push ecx
    push esi
    mov eax, 0x66       ; socketcall
    mov ebx, 3          ; SYS_CONNECT
    int 0x80

    ; Send message
    mov edx, payload_len
    mov ecx, payload
    mov ebx, esi
    mov eax, 4          ; send
    int 0x80

    ; Close socket
    mov eax, 6          ; close
    mov ebx, esi
    int 0x80

    ; Continue with original code

    payload:
    db "{message}", 0
    payload_len:
    db $ - payload
    """


def generate_exec_socket_code_x86_32(ip, port):
    ip_hex = ''.join([hex(int(x))[2:].zfill(2) for x in ip.split('.')])
    port_hex = hex(port)[2:].zfill(4)
    ip_port_hex = port_hex + ip_hex

    return f"""
    ; Setup socket for exec output
    push 0
    push 1
    push 2
    mov eax, 0x66       ; socketcall
    mov ebx, 1          ; SYS_SOCKET
    int 0x80

    mov esi, eax        ; Save socket fd

    ; Connect to remote server
    push 0
    push 0x{ip_port_hex[8:]}
    push 0x{ip_port_hex[:8]}
    mov ecx, esp
    push 16
    push ecx
    push esi
    mov eax, 0x66       ; socketcall
    mov ebx, 3          ; SYS_CONNECT
    int 0x80

    ; Create pipe
    mov eax, 0x2a       ; pipe
    lea ebx, [pipefd]
    int 0x80

    ; Duplicate pipe write end to stdout
    mov eax, 0x3f       ; dup2
    mov ebx, [pipefd+4] ; pipe write end
    mov ecx, 1          ; stdout
    int 0x80

    ; Duplicate pipe write end to stderr
    mov eax, 0x3f       ; dup2
    mov ebx, [pipefd+4] ; pipe write end
    mov ecx, 2          ; stderr
    int 0x80

    ; Call original exec function (placeholder)
    ; exec call

    ; Read from pipe and send to socket
    read_loop:
        mov eax, 3        ; read
        mov ebx, [pipefd] ; pipe read end
        lea ecx, [buffer]
        mov edx, 1024
        int 0x80

        test eax, eax
        jz end_read

        mov ebx, esi
        lea ecx, [buffer]
        mov edx, eax
        mov eax, 4        ; send
        int 0x80

        jmp read_loop

    end_read:

    ; Close pipe ends
    mov eax, 6          ; close
    mov ebx, [pipefd]
    int 0x80

    mov eax, 6          ; close
    mov ebx, [pipefd+4]
    int 0x80

    ; Close socket
    mov eax, 6          ; close
    mov ebx, esi
    int 0x80

    ; Continue with original code

    buffer:
    times 1024 db 0
    pipefd:
    times 2 dd 0
    """


def generate_socket_code_x86_64(ip, port, message):
    ip_hex = ''.join([hex(int(x))[2:].zfill(2) for x in ip.split('.')])
    port_hex = hex(port)[2:].zfill(4)
    ip_port_hex = port_hex + ip_hex

    return f"""
    ; Setup socket
    mov rax, 41       ; socket(AF_INET, SOCK_STREAM, IPPROTO_IP)
    xor rdi, rdi      ; AF_INET
    mov rsi, 1        ; SOCK_STREAM
    xor rdx, rdx      ; IPPROTO_IP
    syscall

    mov rdi, rax      ; Save socket fd

    ; Connect to remote server
    sub rsp, 16
    mov rsi, rsp
    mov dword ptr [rsi], 0x{ip_port_hex[:8]}    ; IP and port part 1
    mov dword ptr [rsi+4], 0x{ip_port_hex[8:]}  ; IP and port part 2
    mov rax, 42       ; connect(socket, sockaddr, sizeof(sockaddr))
    mov rdx, 16       ; sizeof(sockaddr)
    syscall

    ; Send message
    lea rsi, [rel payload]
    mov rdx, payload_len
    xor r10, r10
    mov rax, 44       ; send(socket, buffer, length, flags)
    syscall

    ; Close socket
    mov rdi, rax
    mov rax, 3        ; close
    syscall

    ; Continue with original code

    payload:
    db "{message}", 0
    payload_len:
    db $ - payload
    """


def generate_exec_socket_code_x86_64(ip, port):
    ip_hex = ''.join([hex(int(x))[2:].zfill(2) for x in ip.split('.')])
    port_hex = hex(port)[2:].zfill(4)
    ip_port_hex = port_hex + ip_hex

    return f"""
    ; Setup socket for exec output
    mov rax, 41       ; socket(AF_INET, SOCK_STREAM, IPPROTO_IP)
    xor rdi, rdi      ; AF_INET
    mov rsi, 1        ; SOCK_STREAM
    xor rdx, rdx      ; IPPROTO_IP
    syscall

    mov rdi, rax      ; Save socket fd

    ; Connect to remote server
    sub rsp, 16
    mov rsi, rsp
    mov dword ptr [rsi], 0x{ip_port_hex[:8]}    ; IP and port part 1
    mov dword ptr [rsi+4], 0x{ip_port_hex[8:]}  ; IP and port part 2
    mov rax, 42       ; connect(socket, sockaddr, sizeof(sockaddr))
    mov rdx, 16       ; sizeof(sockaddr)
    syscall

    ; Create pipe
    mov rax, 22       ; syscall for pipe
    lea rdi, [rel pipefd]
    syscall

    ; Duplicate pipe write end to stdout
    mov rdi, [rel pipefd+4] ; pipe write end
    mov rsi, 1        ; stdout
    mov rax, 33       ; syscall for dup2
    syscall

    ; Duplicate pipe write end to stderr
    mov rdi, [rel pipefd+4] ; pipe write end
    mov rsi, 2        ; stderr
    mov rax, 33       ; syscall for dup2
    syscall

    ; Call original exec function (placeholder)
    ; exec call

    ; Read from pipe and send to socket
    read_loop:
        mov rdi, [rel pipefd] ; pipe read end
        mov rax, 0    ; syscall for read
        lea rsi, [rel buffer]
        mov rdx, 1024
        syscall

        test rax, rax
        jz end_read

        mov rdi, [rel socket_fd]
        mov rsi, rsp
        mov rdx, rax
        mov rax, 44   ; syscall for send
        syscall

        jmp read_loop

    end_read:

    ; Close pipe ends
    mov rdi, [rel pipefd]
    mov rax, 3        ; syscall for close
    syscall

    mov rdi, [rel pipefd+4]
    mov rax, 3        ; syscall for close
    syscall

    ; Close socket
    mov rdi, rax
    mov rax, 3        ; close
    syscall

    ; Continue with original code

    buffer:
    times 1024 db 0
    pipefd:
    times 2 db 0
    socket_fd:
    dq 0
    """
    

def generate_socket_code_arm(ip, port, message):
    ip_hex = ''.join([hex(int(x))[2:].zfill(2) for x in ip.split('.')])
    port_hex = hex(port)[2:].zfill(4)
    ip_port_hex = port_hex + ip_hex

    return f"""
    ; Setup socket
    mov r7, #281       ; socket(AF_INET, SOCK_STREAM, IPPROTO_IP)
    mov r0, #2         ; AF_INET
    mov r1, #1         ; SOCK_STREAM
    mov r2, #0         ; IPPROTO_IP
    svc #0

    mov r4, r0         ; Save socket fd

    ; Connect to remote server
    sub sp, sp, #16
    ldr r1, =0x{ip_port_hex[:8]}  ; IP and port part 1
    str r1, [sp]
    ldr r1, =0x{ip_port_hex[8:]}  ; IP and port part 2
    str r1, [sp, #4]
    mov r2, #16
    mov r7, #283       ; connect(socket, sockaddr, sizeof(sockaddr))
    mov r0, r4
    add r1, sp, #0
    svc #0

    ; Send message
    ldr r1, =payload
    mov r2, #payload_len
    mov r7, #292       ; send(socket, buffer, length, flags)
    mov r0, r4
    mov r3, #0
    svc #0

    ; Close socket
    mov r7, #6         ; close
    mov r0, r4
    svc #0

    ; Continue with original code

    payload:
    .ascii "{message}"
    payload_len = . - payload
    """


def generate_exec_socket_code_arm(ip, port):
    ip_hex = ''.join([hex(int(x))[2:].zfill(2) for x in ip.split('.')])
    port_hex = hex(port)[2:].zfill(4)
    ip_port_hex = port_hex + ip_hex

    return f"""
    ; Setup socket for exec output
    mov r7, #281       ; socket(AF_INET, SOCK_STREAM, IPPROTO_IP)
    mov r0, #2         ; AF_INET
    mov r1, #1         ; SOCK_STREAM
    mov r2, #0         ; IPPROTO_IP
    svc #0

    mov r4, r0         ; Save socket fd

    ; Connect to remote server
    sub sp, sp, #16
    ldr r1, =0x{ip_port_hex[:8]}  ; IP and port part 1
    str r1, [sp]
    ldr r1, =0x{ip_port_hex[8:]}  ; IP and port part 2
    str r1, [sp, #4]
    mov r2, #16
    mov r7, #283       ; connect(socket, sockaddr, sizeof(sockaddr))
    mov r0, r4
    add r1, sp, #0
    svc #0

    ; Create pipe
    mov r7, #331       ; syscall for pipe
    ldr r0, =pipefd
    svc #0

    ; Duplicate pipe write end to stdout
    ldr r0, =pipefd+4  ; pipe write end
    mov r1, #1         ; stdout
    mov r7, #63        ; syscall for dup2
    svc #0

    ; Duplicate pipe write end to stderr
    ldr r0, =pipefd+4  ; pipe write end
    mov r1, #2         ; stderr
    mov r7, #63        ; syscall for dup2
    svc #0

    ; Call original exec function (placeholder)
    ; exec call

    ; Read from pipe and send to socket
    read_loop:
        ldr r0, =pipefd  ; pipe read end
        mov r1, sp
        mov r2, #1024
        mov r7, #3        ; syscall for read
        svc #0

        cmp r0, #0
        beq end_read

        mov r0, r4
        mov r1, sp
        mov r2, r0
        mov r3, #0
        mov r7, #292      ; syscall for send
        svc #0

        b read_loop

    end_read:

    ; Close pipe ends
    ldr r0, =pipefd
    mov r7, #6         ; syscall for close
    svc #0

    ldr r0, =pipefd+4
    mov r7, #6         ; syscall for close
    svc #0

    ; Close socket
    mov r7, #6         ; syscall for close
    mov r0, r4
    svc #0

    ; Continue with original code

    .data
    .align 4
    pipefd:
    .word 0, 0
    """


def generate_socket_code_arm64(ip, port, message):
    ip_hex = ''.join([hex(int(x))[2:].zfill(2) for x in ip.split('.')])
    port_hex = hex(port)[2:].zfill(4)
    ip_port_hex = port_hex + ip_hex

    return f"""
    ; Setup socket
    mov x8, 198       ; socket(AF_INET, SOCK_STREAM, IPPROTO_IP)
    mov x0, 2         ; AF_INET
    mov x1, 1         ; SOCK_STREAM
    mov x2, 0         ; IPPROTO_IP
    svc 0

    mov x19, x0       ; Save socket fd

    ; Connect to remote server
    sub sp, sp, #16
    ldr x1, =0x{ip_port_hex[:8]}  ; IP and port part 1
    str x1, [sp]
    ldr x1, =0x{ip_port_hex[8:]}  ; IP and port part 2
    str x1, [sp, #8]
    mov x2, 16
    mov x8, 203       ; connect(socket, sockaddr, sizeof(sockaddr))
    mov x0, x19
    add x1, sp, 0
    svc 0

    ; Send message
    ldr x1, =payload
    mov x2, payload_len
    mov x8, 206       ; send(socket, buffer, length, flags)
    mov x0, x19
    mov x3, 0
    svc 0

    ; Close socket
    mov x8, 57        ; close
    mov x0, x19
    svc 0

    ; Continue with original code

    payload:
    .ascii "{message}"
    payload_len = . - payload
    """


def generate_exec_socket_code_arm64(ip, port):
    ip_hex = ''.join([hex(int(x))[2:].zfill(2) for x in ip.split('.')])
    port_hex = hex(port)[2:].zfill(4)
    ip_port_hex = port_hex + ip_hex

    return f"""
    ; Setup socket for exec output
    mov x8, 198       ; socket(AF_INET, SOCK_STREAM, IPPROTO_IP)
    mov x0, 2         ; AF_INET
    mov x1, 1         ; SOCK_STREAM
    mov x2, 0         ; IPPROTO_IP
    svc 0

    mov x19, x0       ; Save socket fd

    ; Connect to remote server
    sub sp, sp, #16
    ldr x1, =0x{ip_port_hex[:8]}  ; IP and port part 1
    str x1, [sp]
    ldr x1, =0x{ip_port_hex[8:]}  ; IP and port part 2
    str x1, [sp, #8]
    mov x2, 16
    mov x8, 203       ; connect(socket, sockaddr, sizeof(sockaddr))
    mov x0, x19
    add x1, sp, 0
    svc 0

    ; Create pipe
    mov x8, 22        ; syscall for pipe
    adr x0, pipefd
    svc 0

    ; Duplicate pipe write end to stdout
    adr x0, pipefd+8  ; pipe write end
    mov x1, 1         ; stdout
    mov x8, 63        ; syscall for dup2
    svc 0

    ; Duplicate pipe write end to stderr
    adr x0, pipefd+8  ; pipe write end
    mov x1, 2         ; stderr
    mov x8, 63        ; syscall for dup2
    svc 0

    ; Call original exec function (placeholder)
    ; exec call

    ; Read from pipe and send to socket
    read_loop:
        adr x0, pipefd  ; pipe read end
        mov x1, sp
        mov x2, 1024
        mov x8, 63       ; syscall for read
        svc 0

        cmp x0, 0
        beq end_read

        mov x0, x19
        mov x1, sp
        mov x2, x0
        mov x3, 0
        mov x8, 206      ; syscall for send
        svc 0

        b read_loop

    end_read:

    ; Close pipe ends
    adr x0, pipefd
    mov x8, 57        ; syscall for close
    svc 0

    adr x0, pipefd+8
    mov x8, 57        ; syscall for close
    svc 0

    ; Close socket
    mov x8, 57        ; syscall for close
    mov x0, x19
    svc 0

    ; Continue with original code

    .data
    .align 8
    pipefd:
    .8byte 0, 0
    """


def generate_socket_code_mips_32(ip, port, message):
    ip_hex = ''.join([hex(int(x))[2:].zfill(2) for x in ip.split('.')])
    port_hex = hex(port)[2:].zfill(4)
    ip_port_hex = port_hex + ip_hex

    return f"""
    ; Setup socket
    li $v0, 4184        ; socket(AF_INET, SOCK_STREAM, IPPROTO_IP)
    li $a0, 2          ; AF_INET
    li $a1, 1          ; SOCK_STREAM
    li $a2, 0          ; IPPROTO_IP
    syscall

    move $s0, $v0      ; Save socket fd

    ; Connect to remote server
    addiu $sp, $sp, -16
    lui $t0, 0x{ip_port_hex[:4]}
    ori $t0, 0x{ip_port_hex[4:8]}
    sw $t0, 0($sp)
    lui $t1, 0x{ip_port_hex[8:12]}
    ori $t1, 0x{ip_port_hex[12:16]}
    sw $t1, 4($sp)
    li $a2, 16
    li $v0, 4186       ; connect(socket, sockaddr, sizeof(sockaddr))
    move $a0, $s0
    move $a1, $sp
    syscall

    ; Send message
    la $a1, payload
    li $a2, payload_len
    li $v0, 4194       ; send(socket, buffer, length, flags)
    move $a0, $s0
    li $a3, 0
    syscall

    ; Close socket
    li $v0, 4006       ; close
    move $a0, $s0
    syscall

    ; Continue with original code

    payload:
    .asciiz "{message}"
    payload_len = . - payload
    """


def generate_exec_socket_code_mips_32(ip, port):
    ip_hex = ''.join([hex(int(x))[2:].zfill(2) for x in ip.split('.')])
    port_hex = hex(port)[2:].zfill(4)
    ip_port_hex = port_hex + ip_hex

    return f"""
    ; Setup socket for exec output
    li $v0, 4184        ; socket(AF_INET, SOCK_STREAM, IPPROTO_IP)
    li $a0, 2          ; AF_INET
    li $a1, 1          ; SOCK_STREAM
    li $a2, 0          ; IPPROTO_IP
    syscall

    move $s0, $v0      ; Save socket fd

    ; Connect to remote server
    addiu $sp, $sp, -16
    lui $t0, 0x{ip_port_hex[:4]}
    ori $t0, 0x{ip_port_hex[4:8]}
    sw $t0, 0($sp)
    lui $t1, 0x{ip_port_hex[8:12]}
    ori $t1, 0x{ip_port_hex[12:16]}
    sw $t1, 4($sp)
    li $a2, 16
    li $v0, 4186       ; connect(socket, sockaddr, sizeof(sockaddr))
    move $a0, $s0
    move $a1, $sp
    syscall

    ; Create pipe
    li $v0, 4045       ; syscall for pipe
    la $a0, pipefd
    syscall

    ; Duplicate pipe write end to stdout
    lw $a0, pipefd+4   ; pipe write end
    li $a1, 1          ; stdout
    li $v0, 4055       ; syscall for dup2
    syscall

    ; Duplicate pipe write end to stderr
    lw $a0, pipefd+4   ; pipe write end
    li $a1, 2          ; stderr
    li $v0, 4055       ; syscall for dup2
    syscall

    ; Call original exec function (placeholder)
    ; exec call

    ; Read from pipe and send to socket
    read_loop:
        lw $a0, pipefd  ; pipe read end
        move $a1, $sp
        li $a2, 1024
        li $v0, 4003    ; syscall for read
        syscall

        beq $v0, $zero, end_read

        move $a0, $s0
        move $a1, $sp
        move $a2, $v0
        li $a3, 0
        li $v0, 4194    ; syscall for send
        syscall

        b read_loop

    end_read:

    ; Close pipe ends
    lw $a0, pipefd
    li $v0, 4006       ; syscall for close
    syscall

    lw $a0, pipefd+4
    li $v0, 4006       ; syscall for close
    syscall

    ; Close socket
    li $v0, 4006       ; syscall for close
    move $a0, $s0
    syscall

    ; Continue with original code

    .data
    .align 4
    pipefd:
    .word 0, 0
    """


def generate_socket_code_mips_64(ip, port, message):
    ip_hex = ''.join([hex(int(x))[2:].zfill(2) for x in ip.split('.')])
    port_hex = hex(port)[2:].zfill(4)
    ip_port_hex = port_hex + ip_hex

    return f"""
    ; Setup socket
    li $v0, 5054        ; socket(AF_INET, SOCK_STREAM, IPPROTO_IP)
    li $a0, 2          ; AF_INET
    li $a1, 1          ; SOCK_STREAM
    li $a2, 0          ; IPPROTO_IP
    syscall

    move $s0, $v0      ; Save socket fd

    ; Connect to remote server
    daddiu $sp, $sp, -24
    lui $t0, 0x{ip_port_hex[:4]}
    ori $t0, 0x{ip_port_hex[4:8]}
    sd $t0, 0($sp)
    lui $t1, 0x{ip_port_hex[8:12]}
    ori $t1, 0x{ip_port_hex[12:16]}
    sd $t1, 8($sp)
    li $a2, 16
    li $v0, 5056       ; connect(socket, sockaddr, sizeof(sockaddr))
    move $a0, $s0
    move $a1, $sp
    syscall

    ; Send message
    la $a1, payload
    li $a2, payload_len
    li $v0, 5064       ; send(socket, buffer, length, flags)
    move $a0, $s0
    li $a3, 0
    syscall

    ; Close socket
    li $v0, 5008       ; close
    move $a0, $s0
    syscall

    ; Continue with original code

    payload:
    .asciiz "{message}"
    payload_len = . - payload
    """


def generate_exec_socket_code_mips_64(ip, port):
    ip_hex = ''.join([hex(int(x))[2:].zfill(2) for x in ip.split('.')])
    port_hex = hex(port)[2:].zfill(4)
    ip_port_hex = port_hex + ip_hex

    return f"""
    ; Setup socket for exec output
    li $v0, 5054        ; socket(AF_INET, SOCK_STREAM, IPPROTO_IP)
    li $a0, 2          ; AF_INET
    li $a1, 1          ; SOCK_STREAM
    li $a2, 0          ; IPPROTO_IP
    syscall

    move $s0, $v0      ; Save socket fd

    ; Connect to remote server
    daddiu $sp, $sp, -24
    lui $t0, 0x{ip_port_hex[:4]}
    ori $t0, 0x{ip_port_hex[4:8]}
    sd $t0, 0($sp)
    lui $t1, 0x{ip_port_hex[8:12]}
    ori $t1, 0x{ip_port_hex[12:16]}
    sd $t1, 8($sp)
    li $a2, 16
    li $v0, 5056       ; connect(socket, sockaddr, sizeof(sockaddr))
    move $a0, $s0
    move $a1, $sp
    syscall

    ; Create pipe
    li $v0, 5029       ; syscall for pipe
    la $a0, pipefd
    syscall

    ; Duplicate pipe write end to stdout
    ld $a0, pipefd+8   ; pipe write end
    li $a1, 1          ; stdout
    li $v0, 5039       ; syscall for dup2
    syscall

    ; Duplicate pipe write end to stderr
    ld $a0, pipefd+8   ; pipe write end
    li $a1, 2          ; stderr
    li $v0, 5039       ; syscall for dup2
    syscall

    ; Call original exec function (placeholder)
    ; exec call

    ; Read from pipe and send to socket
    read_loop:
        ld $a0, pipefd  ; pipe read end
        move $a1, $sp
        li $a2, 1024
        li $v0, 5003    ; syscall for read
        syscall

        beq $v0, $zero, end_read

        move $a0, $s0
        move $a1, $sp
        move $a2, $v0
        li $a3, 0
        li $v0, 5064    ; syscall for send
        syscall

        b read_loop

    end_read:

    ; Close pipe ends
    ld $a0, pipefd
    li $v0, 5008       ; syscall for close
    syscall

    ld $a0, pipefd+8
    li $v0, 5008       ; syscall for close
    syscall

    ; Close socket
    li $v0, 5008       ; syscall for close
    move $a0, $s0
    syscall

    ; Continue with original code

    .data
    .align 8
    pipefd:
    .dword 0, 0
    """


def main(directory, ip, msg_port, exec_port):
    binaries = find_binaries(directory)
    for binary_path in binaries:
        instrument_binary(binary_path, ip, msg_port, exec_port)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-cf", type=str, help="Configuration File")
    args = parser.parse_args()
    
    with open(args.cf, "r") as f:
        conf = json.load(f)
            
    directory = conf["firmware_root_path"]
    ip = conf["ip_address"]
    msg_port = conf["visitor_port"]
    exec_port = conf["exec_port"]
    main(directory, ip, msg_port, exec_port)
