; [nzfat] default bootsector w/ custom message.
; This is free and unencumbered software released into the public domain. For more information: https://unlicense.org
[BITS 16]

mov ah, 0x0E
xor bx, bx
mov cx, 0xCAFE ; Will be patched to be the message length
mov si, 0xBABE ; Will be patched to be the message offset

next_character:
mov al, byte [si]
int 0x10
inc si
dec cx
jnz short next_character ; We don't need to patch this as its relative

cli
hlt
