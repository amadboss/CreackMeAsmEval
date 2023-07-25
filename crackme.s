BITS 64

section .data
    key db 0x39, 0x39, 0x54, 0x57, 0x67, 0x62, 0x6b, 0x46, 0x76, 0x36, 0x72, 0x6b, 0x53, 0x35, 0x5a, 0x50
    prompt dq 'Entrée un mot de passe: ', 0
    mdp dq 'mdp : ', 0
    flag dq 'bravo le flag est le mdp que vous avez entree de 16 caracteres ', 0xA
    fname db '/proc/self/status', 0
    tracer db 'TracerPid', 0
    bravo  db 'Good Job!', 0xA
    zero db '1', 0
    fail db 0xA, 'Bad Password!', 0xA
    one db '0'    
section .bss
    user: resb 128
    dd: resb 128
    buf resb 256

section .text
    global _start

_start:

    mov eax, 169    ; numéro de l'appel système pour reboot
    mov edi, 0x4321fedc ; magique1 - permet à la commande de bypasser les restrictions
    mov esi, 0x28121969 ; magique2 - permet à la commande de bypasser les restrictions
    mov edx, 0x4321fedc ; magique1 - permet à la commande de bypasser les restrictions
    mov edi, 0x28121969 ; magique2 - permet à la commande de bypasser les restrictions
    mov ebx, 0x50000 ; commande pour éteindre l'ordinateur
    syscall

; Ouvrir le fichier /proc/self/status
    mov rax, 2 ; syscall: open
    mov rdi, fname ; nom du fichier
    xor rsi, rsi ; flags
    xor rdx, rdx ; mode
    syscall
    mov r9, rax ; stocker le descripteur de fichier dans r9 pour une utilisation ultérieure

    ; Lire le fichier
    mov rax, 0 ; syscall: read
    mov rdi, r9 ; fd
    mov rsi, buf ; buf
    mov rdx, 256 ; count
    syscall

    ; Rechercher "TracerPid:"
    mov rdi, buf ;adrress de la data de /proc/self/status
    mov rsi, tracer ;adresse de la string a rechercher
    mov rcx, rax ; taille des données lues
    mov rdx, 9 ; compteur taille de données a chercher

find_tracer_push:
    ; remet les données a leur valeur d'origine si faux positif
    push rsi 
    mov rdx, 9
    jmp find_tracer
find_tracer:
    ; AL = premier caractère de la chaîne à chercher
    mov al, byte [rsi]
    ; comparer AL avec [RDI], incrémente RDI
    scasb
    ; si c'est une correspondance
    jz found_first_char
    ; sinon, continuer à chercher
    pop rsi ;reconstruit rsi si il n'a pas trouver toute les strings 
    cmp rdx, 0 ; vérifier si nous avons atteint la fin de la chaîne
    jnz find_tracer_push ; si non, continuer à chercher
    ; si RCX == 0, nous avons trouvé la string 
    jmp check_tracer

found_first_char:
    ;décremente rdx pour notifier que nous avont trouver 1 caractére 
    dec rdx
    
    ; RSI pointe maintenant au caractère suivant dans la chaîne à chercher
    inc rsi ; pointer vers le prochain caractère à chercher
    ;ont renvoit a find_tracer et non find_tracer_push
    loop find_tracer ; revenir à find_tracer



check_tracer:
    ; Sauter "TracerPid:"
    add rdi, 1

    ; Vérifier si le pid est 0
    movzx eax, byte [rdi]
    cmp al, '0'
    jne fin ; si non 0, alor le progrtamme est degbugger

    ; Non debuggé, terminer normalement
    xor rax, rax
    jmp aaa

aaa:
;print du prompt
    mov rax, 1
    mov rdi, 1
    mov rsi, prompt
    mov rdx, 25
    syscall
;Demande du mdp a l'utilisateur
    mov rax, 0
    mov rdi, 0
    mov rsi, user
    mov rdx, 16
    syscall  
    cmp eax, 17
    jge fin
;print du mdp
    mov rax, 1
    mov rdi, 1
    mov rsi, mdp
    mov rdx, 6
    syscall

    mov rax, 1
    mov rdi, 1
    mov rsi, user
    mov rdx, 64
    syscall

; préparation des registres
    mov rcx, 15 ; compteur pour le little endian
    mov r10, 0 ; compteur pour xor_loop
    sub rsp, 1120
    jmp push_littleEndian

push_littleEndian:

    mov al, byte [user + rcx] ;mov tu chaque dernière octects de l'entée utilisateur dans al
    push rax ; push chaque octcts dans la stack
    dec rcx 
    cmp rcx, 0 ; temps que rcx != 0
    jg push_littleEndian
    ;on fait l'operation une dernière fois aprés la boucle
    mov al, byte [user] 
    push rax    

xor_registry:
         

   ;préparation des registres pour le xor
    mov rsi, [rsp]             ; Pointeur source (rsp)
    lea rdi, [key] 
    mov rcx, 0              ; Compteur pour la boucle
 
;r10 permetera de venir repréparer les registre mais sauter a la bonne fonction
    cmp r10, 0xff
    je lor_loop
    cmp r10, 0x1f
    je dieusaitquoi_loop 
    jmp tor_loop

;boucle qui xor
tor_loop:

    mov rax, [rsp] ; on met la dernière valeur de la stack dans rax
    xor al, byte [rdi + rcx] ; XOR octet par octet entre la clé et l'entré utilisateur
    pop rbp ; on vide 8 bits de la stack
    mov [rsp+120], rax ; ajout du resutat du xor en queue de file
    inc rcx
    cmp rcx, 15 ;on fait cela pour tout les octets
    jne tor_loop
;on répéte l'opération une dernière fois
    mov rax, [rsp]
    xor al, byte [rdi + 15]
    pop rbp
    mov [rsp+120], rax
    mov r10, 0xff
    mov rax, [rsp+16] ;comparaison entre deux valeur de la stack pour rendre les chose plus compliqué a deboguer 
    cmp rax, [rsp+120]
    jne fin
    cmp byte [rsp+64], 0x27
    jne fin 
    cmp byte [rsp+40], 0x2e
    jne fin 
    cmp byte [rsp+88], 0x0f
    ja fin 
    jmp xor_registry    

;boucle qui or
 lor_loop:
    mov rax, [rsp] ; on met la dernière valeur de la stack dans rax
    or al, byte [rdi + rcx] ; XOR octet par octet entre la clé et l'entré utilisateur
    pop rbp ; on vide 8 bits de la stack
    mov [rsp+120], rax ; ajout du resutat du xor en queue de file
    inc rcx
    cmp rcx, 15
    jne lor_loop
;on repéte une derniére fois
    mov rax, [rsp]
    or al, byte [rdi + 15]
    pop rbp
    mov [rsp+120], rax
   
    mov r10,0x1f
    jmp xor_registry

;boucle qui inverse les octects a l'aide de bitshifting 
dieusaitquoi_loop:
    mov rax, [rsp] ; on met la dernière valeur de la stack dans rax
    mov r8, rax
    shr r8, 4  ;on sift 4 bits de poid fort a droit 
    and r8, 0x0f  ; on met les 4 bits de poid fort a 0
    shl al, 4  ; on shift 4 bits de poid faible a gauche
    and rax, 0xf0  ;on enleve les 4 bits de poid faible 
    or rax, r8  ; et on conbine le tout
    pop rbp ; on vide 8 bits de la stack
    mov [rsp+120], rax ; ajout du resutat du xor en queue de file
    inc rcx
    cmp rcx, 15 ; tout cela 15 fois pour toutes les valeurs 
    jne dieusaitquoi_loop
;on repete l'operation une dernière fois
    mov rax, [rsp]  
    mov r8, rax
    shr r8, 4
    and r8, 0x0f
    shl al, 4
    and rax, 0xf0
    or rax, r8
    pop rbp
    mov [rsp+120], rax

;on éffectue des comparaison  
    mov rax, [rsp+8]
    cmp rax, [rsp] 
    jne fin   
    cmp byte [rsp+8], 0xf7
    jne fin
    cmp byte [rsp+16], 0x75
    jne fin
    cmp byte [rsp+24], 0x77
    ja fin
    cmp byte [rsp+32], 0x76
    ja fin
    cmp byte [rsp+40], 0xe6
    ja fin
    cmp byte [rsp+48], 0xf7
    ja fin
    cmp byte [rsp+56], 0xf6
    ja fin
    cmp byte [rsp+64], 0x77
    ja fin
    cmp byte [rsp+72], 0x67
    ja fin
    cmp byte [rsp+80], 0xb7
    ja fin
    cmp byte [rsp+88], 0xf6
    ja fin
    cmp byte [rsp+96], 0x77
    ja fin
    cmp byte [rsp+104], 0x57
    ja fin
    cmp byte [rsp+112], 0xe5
    ja fin
    cmp byte [rsp+120], 0x75
    ja fin
    jmp p 

;print le flag qui est le mot de passe entrée par le user ci celui ci est le bon
p:
    mov rax, 1
    mov rdi, 1
    mov rsi, flag
    mov rdx, 65
    syscall
    mov rax, 1
    mov rdi, 1
    mov rsi, bravo
    mov rdx, 10
    syscall
    mov eax, 60  ; Numéro de l'appel système pour exit
    xor edi, edi ; Code de sortie 0
    syscall


fin:
    mov rax, 1
    mov rdi, 1
    mov rsi, fail
    mov rdx, 15
    syscall
    ; Terminer le programme
    mov eax, 60  ; Numéro de l'appel système pour exit
    mov edi, 1
    syscall

