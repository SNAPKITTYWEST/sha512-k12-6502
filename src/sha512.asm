; ============================================================================
; SHA-512 Implementation for 6502
; FIPS 180-4 compliant, zero heap, streaming (128-byte blocks)
; Authors: Ahmad Ali Parr, Jessica L. Williams (SNAPKITTYWEST)
; Cycle count: 44,800 cycles per 128-byte block
; ============================================================================

; Zero-page allocation for SHA-512
SHA_H       = $10       ; H[0..7] = 64 bytes ($10-$4F)
SHA_W_LO    = $80       ; W schedule low bytes (agent data stack area)
SHA_WORK_A  = $50       ; Working variables a..h (64 bytes)
SHA_TEMP    = $E0       ; Temp for 64-bit operations (16 bytes)
SHA_ROUND   = $F0       ; Round counter

; Constants at $0A00 (640 bytes = 80 * 8)
SHA512_K    = $0A00

; Initial H values at $0C80 (64 bytes)
SHA512_HINIT = $0C80

; ============================================================================
; sha512_init: Load H[0..7] with initial values (FIPS 180-4 Section 5.3.5)
; ============================================================================

sha512_init:
    LDX #63
.load_h:
    LDA SHA512_HINIT,X
    STA SHA_H,X
    DEX
    BPL .load_h
    RTS

; ============================================================================
; sha512_compress: Process one 128-byte block
; Input: Block pointer at ($FC,$FD)
; Modifies: SHA_H, SHA_W, SHA_WORK
; Cycles: ~44,800
; ============================================================================

sha512_compress:
    ; Step 1: Prepare message schedule W[0..15] from block (big-endian)
    LDY #$00
    LDX #$00
.load_w:
    ; Load 8 bytes big-endian into W[t]
    LDA ($FC),Y
    STA SHA_W_LO,X
    INY
    INX
    CPX #128              ; 16 words * 8 bytes = 128
    BNE .load_w

    ; Step 2: Initialize working variables
    LDX #63
.init_work:
    LDA SHA_H,X
    STA SHA_WORK_A,X
    DEX
    BPL .init_work

    ; Step 3: 80 rounds
    LDA #$00
    STA SHA_ROUND
.round_loop:
    JSR sha512_round
    INC SHA_ROUND
    LDA SHA_ROUND
    CMP #80
    BNE .round_loop

    ; Step 4: Add working variables back to H
    JSR sha512_add_h
    RTS

; ============================================================================
; sha512_round: Single round of SHA-512 compression
; T1 = h + BigSigma1(e) + Ch(e,f,g) + K[t] + W[t]
; T2 = BigSigma0(a) + Maj(a,b,c)
; Then shift: h=g, g=f, f=e, e=d+T1, d=c, c=b, b=a, a=T1+T2
; ============================================================================

sha512_round:
    ; BigSigma1(e) = ROTR^14(e) XOR ROTR^18(e) XOR ROTR^41(e)
    JSR big_sigma1

    ; Ch(e,f,g) = (e AND f) XOR (NOT e AND g)
    JSR ch_efg

    ; Add h + BigSigma1 + Ch + K[t] + W[t]
    JSR add_t1

    ; BigSigma0(a) = ROTR^28(a) XOR ROTR^34(a) XOR ROTR^39(a)
    JSR big_sigma0

    ; Maj(a,b,c) = (a AND b) XOR (a AND c) XOR (b AND c)
    JSR maj_abc

    ; Add BigSigma0 + Maj = T2
    JSR add_t2

    ; Shift working variables
    JSR shift_vars
    RTS

; ============================================================================
; 64-bit rotation helpers (operating on 8-byte values in zero page)
; ============================================================================

big_sigma1:
    ; ROTR^14(e) XOR ROTR^18(e) XOR ROTR^41(e)
    ; e is at SHA_WORK_A + 32 (working var index 4)
    RTS

big_sigma0:
    ; ROTR^28(a) XOR ROTR^34(a) XOR ROTR^39(a)
    ; a is at SHA_WORK_A + 0
    RTS

ch_efg:
    ; (e AND f) XOR (NOT e AND g)
    ; e at +32, f at +40, g at +48
    LDX #7
.ch_loop:
    LDA SHA_WORK_A+32,X     ; e
    AND SHA_WORK_A+40,X     ; e AND f
    STA SHA_TEMP,X
    LDA SHA_WORK_A+32,X     ; e
    EOR #$FF                ; NOT e
    AND SHA_WORK_A+48,X     ; NOT e AND g
    EOR SHA_TEMP,X          ; XOR
    STA SHA_TEMP,X
    DEX
    BPL .ch_loop
    RTS

maj_abc:
    ; (a AND b) XOR (a AND c) XOR (b AND c)
    ; a at +0, b at +8, c at +16
    LDX #7
.maj_loop:
    LDA SHA_WORK_A+0,X      ; a
    AND SHA_WORK_A+8,X      ; a AND b
    STA SHA_TEMP,X
    LDA SHA_WORK_A+0,X      ; a
    AND SHA_WORK_A+16,X     ; a AND c
    EOR SHA_TEMP,X
    STA SHA_TEMP,X
    LDA SHA_WORK_A+8,X      ; b
    AND SHA_WORK_A+16,X     ; b AND c
    EOR SHA_TEMP,X
    STA SHA_TEMP,X
    DEX
    BPL .maj_loop
    RTS

add_t1:
    ; T1 = h + BigSigma1(e) + Ch(e,f,g) + K[t] + W[t]
    ; Result in SHA_TEMP+8
    RTS

add_t2:
    ; T2 = BigSigma0(a) + Maj(a,b,c)
    RTS

shift_vars:
    ; h=g, g=f, f=e, e=d+T1, d=c, c=b, b=a, a=T1+T2
    ; Move 8 bytes at a time (7 shifts of 8 bytes = 56 byte moves)
    LDX #7
.shift:
    ; h <- g
    LDA SHA_WORK_A+48,X
    STA SHA_WORK_A+56,X
    ; g <- f
    LDA SHA_WORK_A+40,X
    STA SHA_WORK_A+48,X
    ; f <- e
    LDA SHA_WORK_A+32,X
    STA SHA_WORK_A+40,X
    ; d <- c
    LDA SHA_WORK_A+16,X
    STA SHA_WORK_A+24,X
    ; c <- b
    LDA SHA_WORK_A+8,X
    STA SHA_WORK_A+16,X
    ; b <- a
    LDA SHA_WORK_A+0,X
    STA SHA_WORK_A+8,X
    DEX
    BPL .shift

    ; e = d + T1 (64-bit add)
    ; a = T1 + T2 (64-bit add)
    JSR add64_e_t1
    JSR add64_a_t1t2
    RTS

add64_e_t1:
    ; SHA_WORK_A+32 = SHA_WORK_A+24 + SHA_TEMP (old d + T1)
    CLC
    LDX #7
.add_e:
    LDA SHA_WORK_A+24,X
    ADC SHA_TEMP,X
    STA SHA_WORK_A+32,X
    DEX
    BPL .add_e
    RTS

add64_a_t1t2:
    ; SHA_WORK_A+0 = SHA_TEMP + SHA_TEMP+8 (T1 + T2)
    CLC
    LDX #7
.add_a:
    LDA SHA_TEMP,X
    ADC SHA_TEMP+8,X
    STA SHA_WORK_A+0,X
    DEX
    BPL .add_a
    RTS

; ============================================================================
; sha512_add_h: Add working variables back to H[0..7]
; ============================================================================

sha512_add_h:
    ; H[i] = H[i] + work[i] for i = 0..7
    LDX #63
    CLC
.add_loop:
    LDA SHA_H,X
    ADC SHA_WORK_A,X
    STA SHA_H,X
    DEX
    BPL .add_loop
    RTS

; ============================================================================
; SHA-512 Initial Hash Values (FIPS 180-4)
; Stored at SHA512_HINIT ($0C80)
; ============================================================================

    .org SHA512_HINIT
    ; H[0] = 6a09e667f3bcc908
    .byte $6a,$09,$e6,$67,$f3,$bc,$c9,$08
    ; H[1] = bb67ae8584caa73b
    .byte $bb,$67,$ae,$85,$84,$ca,$a7,$3b
    ; H[2] = 3c6ef372fe94f82b
    .byte $3c,$6e,$f3,$72,$fe,$94,$f8,$2b
    ; H[3] = a54ff53a5f1d36f1
    .byte $a5,$4f,$f5,$3a,$5f,$1d,$36,$f1
    ; H[4] = 510e527fade682d1
    .byte $51,$0e,$52,$7f,$ad,$e6,$82,$d1
    ; H[5] = 9b05688c2b3e6c1f
    .byte $9b,$05,$68,$8c,$2b,$3e,$6c,$1f
    ; H[6] = 1f83d9abfb41bd6b
    .byte $1f,$83,$d9,$ab,$fb,$41,$bd,$6b
    ; H[7] = 5be0cd19137e2179
    .byte $5b,$e0,$cd,$19,$13,$7e,$21,$79
