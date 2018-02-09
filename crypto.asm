; $7F50D0 - $7F50FF - Block Cypher Parameters
; $7F5100 - $7F51FF - Block Cypher Buffer
!ADD = "CLC : ADC"
!SUB = "SEC : SBC"
!BLT = "BCC"
!BGE = "BCS"

!v = "$7F5100"
!n = "$04"
!MXResult = "$08"
!dpScratch = "$08"
!keyBase = "$7F50D0"

!y = "$7F50E0"
!z = "$7F50E4"
!sum = "$7F50E8"

!p = "$7F50EC"
!rounds = "$06"
!e = "$7F50F0"

!upperScratch = "$7F50F2"

CryptoDelta:
dd $9e3779b9

;Todo: these are now simple enough that they should be changed to a non-looping macro, with the lops unrolled
macro LSR32(value,k)
	LDX.w <k>
	
	?loop:
	CLC
	LDA.b <value>+2 : ROR : STA.b <value>+2 ; do top part
	LDA.b <value> : ROR : STA.b <value> ; do bottom part
	; ROR handles the carry from the uper byte for us
	
	DEX
	CPX.w #$0000 : BNE ?loop
endmacro

macro ASL32(value,k)
	LDX.w <k>
	
	?loop:
	CLC
	LDA.b <value> : ROL : STA.b <value> ; do bottom part
	LDA.b <value>+2 : ROL : STA.b <value>+2 ; do top part
	
	DEX
	CPX.w #$0000 : BNE ?loop
endmacro



CryptoMX:
	PHX
	
	;; upperScratch = (z>>5 ^ y <<2)
	LDA !z : STA !dpScratch
	LDA !z+2 : STA !dpScratch+2
	%LSR32(!dpScratch,#$05)
	
	LDA !y : STA !dpScratch+4
	LDA !y+2 : STA !dpScratch+6
	%ASL32(!dpScratch+4,#$02)
	
	LDA !dpScratch : EOR !dpScratch+4 : STA !upperScratch
	LDA !dpScratch+2 : EOR !dpScratch+6 : STA !upperScratch+2
	
	;================================
	; upperscratch2 = (y>>3^z<<4)
	
	LDA !z : STA !dpScratch
	LDA !z+2 : STA !dpScratch+2
	%ASL32(!dpScratch,#$04)
	
	LDA !y : STA !dpScratch+4
	LDA !y+2 : STA !dpScratch+6
	%LSR32(!dpScratch,#$03)
	
	LDA !dpScratch : EOR !dpScratch+4 : STA !upperScratch+4
	LDA !dpScratch+2 : EOR !dpScratch+6 : STA !upperScratch+6
	
	;================================
	; uppserscratch = upperscratch + upperscratch2 ( == (z>>5^y<<2) + (y>>3^z<<4) )
    
	LDA !upperScratch : !ADD !upperScratch+4 : STA !upperScratch
	LDA !upperScratch+2 : ADC !upperScratch+6 : STA !upperScratch+2
	
	;================================
	; dpscratch = sum^y
    
	LDA !sum : EOR !y : STA !dpScratch
	LDA !sum+2 : EOR !y+2 : STA !dpScratch+2
	
	;================================
	; dpscratch2 =  (k[p&3^e]^z)
    
	LDA !p : AND.w #$0003 : EOR !e : ASL #2 : TAX ; put (p&3)^e into X
	LDA !keyBase, X : EOR !z : STA !dpScratch+4
	LDA !keyBase+2, X : EOR !z+2 : STA !dpScratch+6
	
	;================================
	; upperscratch2 =  dpscratch + dpscratch2 (== (sum^y) + (k[p&3^e]^z))
    
	LDA !dpScratch : EOR !dpScratch+4 : STA !upperScratch+4
	LDA !dpScratch+2 : EOR !dpScratch+6 : STA !upperScratch+6
	
	;================================
	; MXResult = uppserscratch ^ upperscratch2
    
	LDA !upperScratch : EOR !upperScratch+4 : STA !MXResult
	LDA !upperScratch+2 : EOR !upperScratch+6 : STA !MXResult+2
	PLX
RTS

;todo: should Bank to  to be 7F for the duration of this to save a cycle on every read or write (need to add .w)

XXTEA_Decode:
	PHP
		SEP #$20 ; set 8-bit accumulator
		
		; search for lookup table index to avoid division and multiplication
		LDX.b #0
		-
			LDA.l .n_lookup, X
			CMP.b !n : !BGE +
			INX
			BRA -
		+
		; rounds = 6 + 52/n;
		LDA.l .round_counts, X : STA !rounds : STZ !rounds+1
        
		REP #$20 ; set 16-bit accumulator
		
		; sum = rounds*DELTA;
		TXA : ASL #2 : TAX
		LDA.l .initial_sums, X : STA !sum
		LDA.l .initial_sums+2, X : STA !sum+2
		
		; y = v[0];
		LDA !v : STA !y
		LDA !v+2 : STA !y+2
		---
			LDA !sum : LSR #2 : AND.w #$0003 : STA !e ; e = (sum >> 2) & 3;
			
			LDA !n : AND.w #$00FF : STA !p : BRA +; for (p=n-1; p>0; p--) {
			--
				; z = v[p-1];
				DEC : ASL #2 : TAX
				LDA !v, X : STA !z
				LDA !v+2, X : STA !z+2
				
				; y = v[p] -= MX;
				JSR CryptoMX
				LDA !p : ASL #2 : TAX
				LDA !v, X : !SUB !MXResult : STA !v, X : STA !y
				LDA !v+2, X : SBC !MXResult+2 : STA !v+2, X : STA !y+2
				
			+ : LDA !p : DEC : STA !p : BNE -- ; }
			
			; z = v[n-1];
			LDA !n : AND.w #$00FF : DEC : ASL #2 : TAX
			LDA !v, X : STA !z
			LDA !v+2, X : STA !z+2
			
			; y = v[0] -= MX;
			JSR CryptoMX
			LDA !v : !SUB !MXResult : STA !v : STA !y
			LDA !v+2 : SBC !MXResult+2 : STA !v+2 : STA !y+2
			
			; sum -= DELTA;
			LDA !sum : !SUB CryptoDelta : STA !sum
			LDA !sum+2 : !SUB CryptoDelta+2 : STA !sum+2
			
		DEC !rounds : BEQ + : BRL --- : + ; } while (--rounds);
	PLP
RTL

; Optimization notes: comment any values from these tables that correspond to values of n not in use
.n_lookup
db 52 ; n > 52
db 26 ; n is 27 to 52
db 17 ; n is 18 to 26
db 13 ; n is 14 to 17
db 10 ; n is 11 to 13
db 8  ; n is 9 to 10
db 7  ; n is 8
db 6  ; n is 7
db 5  ; n is 6
db 4  ; n is 5
db 3  ; n is 4
db 2  ; n is 3
db 1  ; n is 2
db 0  ; n is 1

.round_counts
db 6  ; n > 52
db 7  ; n is 27 to 52
db 8  ; n is 18 to 26
db 9  ; n is 14 to 17
db 10 ; n is 11 to 13
db 11 ; n is 9 to 10
db 12 ; n is 8
db 13 ; n is 7
db 14 ; n is 6
db 16 ; n is 5
db 19 ; n is 4
db 23 ; n is 3
db 32 ; n is 2
db 58 ; n is 1

.initial_sums
dd 6*$9e3779b9  ; n > 52
dd 7*$9e3779b9  ; n is 27 to 52
dd 8*$9e3779b9  ; n is 18 to 26
dd 9*$9e3779b9  ; n is 14 to 17
dd 10*$9e3779b9 ; n is 11 to 13
dd 11*$9e3779b9 ; n is 9 to 10
dd 12*$9e3779b9 ; n is 8
dd 13*$9e3779b9 ; n is 7
dd 14*$9e3779b9 ; n is 6
dd 16*$9e3779b9 ; n is 5
dd 19*$9e3779b9 ; n is 4
dd 23*$9e3779b9 ; n is 3
dd 32*$9e3779b9 ; n is 2
dd 58*$9e3779b9 ; n is 1

;void btea(uint32_t *v, int n, uint32_t const key[4]) {
;  uint32_t y, z, sum;
;  unsigned p, rounds, e;

;  } else if (n < -1) {  /* Decoding Part */
;    n = -n;
;    rounds = 6 + 52/n;
;    sum = rounds*DELTA;
;    y = v[0];
;    do {
;      e = (sum >> 2) & 3;
;      for (p=n-1; p>0; p--) {
;        z = v[p-1];
;        y = v[p] -= MX;
;      }
;      z = v[n-1];
;      y = v[0] -= MX;
;      sum -= DELTA;
;    } while (--rounds);
;  }


;BTEA will encode or decode n words as a single block where n > 1
;
;v is the n word data vector
;k is the 4 word key
;n is negative for decoding
;if n is zero result is 1 and no coding or decoding takes place, otherwise the result is zero
;assumes 32 bit 'long' and same endian coding and decoding
;#include <stdint.h>
;#define DELTA 0x9e3779b9
;#define MX ((((z>>5)^(y<<2)) + ((y>>3)^(z<<4))) ^ ((sum^y) + (key[(p&3)^e] ^ z)))
;
;void btea(uint32_t *v, int n, uint32_t const key[4]) {
;  uint32_t y, z, sum;
;  unsigned p, rounds, e;
;  if (n > 1) {          /* Coding Part */
;    rounds = 6 + 52/n;
;    sum = 0;
;    z = v[n-1];
;    do {
;      sum += DELTA;
;      e = (sum >> 2) & 3;
;      for (p=0; p<n-1; p++) {
;        y = v[p+1]; 
;        z = v[p] += MX;
;      }
;      y = v[0];
;      z = v[n-1] += MX;
;    } while (--rounds);
;  } else if (n < -1) {  /* Decoding Part */
;    n = -n;
;    rounds = 6 + 52/n;
;    sum = rounds*DELTA;
;    y = v[0];
;    do {
;      e = (sum >> 2) & 3;
;      for (p=n-1; p>0; p--) {
;        z = v[p-1];
;        y = v[p] -= MX;
;      }
;      z = v[n-1];
;      y = v[0] -= MX;
;      sum -= DELTA;
;    } while (--rounds);
;  }
;}