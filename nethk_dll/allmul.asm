; The code below was taken from http://uefi.blogspot.ru/2010/02/why-why-do-i-get-unresolved-externals.html
; allmul - 64-bit signed multiplication support function. 



.586
.MODEL FLAT, C
.CODE

;
; FUNCTION NAME.
; _allmul
;
; FUNCTIONAL DESCRIPTION.
; This function is called by the Microsoft Visual C/C++ compiler for 32-
; bit executables to multiply two 64-bit integers and returning a 64-bit
; result. The X86 processors have only a 32-bit multiply instruction, 
; thus the necessity for a library support function.
;
; The operands are divided into two 32-bit quantities. You can imagine 
; that this works like simple 2-digit x 2-digit multiplication, except
; that each digit is 32-bits wide.
;
;   AB
; x CD
; ----
;   DB
;  DA0
;  CB0
; CA00
; ----
; RRRR
;
; You notice that the 3rd and 4th columns never will be used because the
; are the part of the result that is > 64-bits.
;
; R[0:31] = DB[0:31]
; R[32:63] = DB[32:63] + DA[0:31] + CB[0:31]
;
; There is a short cut, if both A and C are 0, then we can use the simple
; 32-bit instruction.
;
;
; ENTRY PARAMETERS.
;    multiplicand - Right-hand operator (CD)
;    multiplier - Left-hand operator (AB)
;
; EXIT PARAMETERS.
;    EDX:EAX - Result.
;


_allmul PROC NEAR USES ESI, multiplicand:QWORD, multiplier:QWORD

 MA EQU DWORD PTR multiplier [4]
 MB EQU DWORD PTR multiplier
 MC EQU DWORD PTR multiplicand [4]
 MD EQU DWORD PTR multiplicand

 mov eax, MA
 mov ecx, MC
 or  ecx, eax    ; both zero?
 mov ecx, MD
 .if zero?      ; yes, use shortcut.
   mov eax, MB
   mul ecx      ; EDX:EAX = DB[0:63].
 .else
   mov eax, MA
   mul ecx      ; EDX:EAX = DA[0:63].
   mov esi, eax ; ESI = DA[0:31].

   mov eax, MB 
   mul MC       ; EDX:EAX = CB[0:63]
   add esi, eax ; ESI = DA[0:31] + CB[0:31]


   mov eax, MB
   mul ecx      ; EDX:EAX = BD[0:63]
   add edx, esi ; EDX = DA[0:31] + CB[0:31] + DB[31:63]
                ; EAX = DB[0:31]
 .endif


 ret 16 ; callee clears the stack.
_allmul ENDP


 END