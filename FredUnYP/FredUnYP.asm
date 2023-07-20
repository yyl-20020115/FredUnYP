.586
.model flat,stdcall
option casemap:none

;--------------------
; Include Files
;--------------------

include c:\masm32\include\windows.inc
include c:\masm32\include\kernel32.inc
include c:\masm32\include\user32.inc
include c:\masm32\include\comdlg32.inc

;---------------------
; Include Libraries
;---------------------

includelib c:\masm32\lib\kernel32.lib
includelib c:\masm32\lib\user32.lib
includelib c:\masm32\lib\comdlg32.lib

WndProc PROTO :DWORD,:DWORD,:DWORD,:DWORD

.const
ID_GEN       equ 201
ID_EXIT      equ 202

.data
dialogname db "unpacker",0
TitleBar db "stan4oo`s unpacker for yP 1.03",0
strFilterA db "ExEcutable Files",0,"*.exe",0,0
NameOfObject db "unpack",0
Texterror db "There was an error while unpacking that file!",0
Captionerror db "Error detected!",0
SuccessfullText db "File Unpacked Successfull!!!",0
SuccessfullCaption db "Success!",0
AboutText db " This is lame unpacker for Yoda Protector Version 1.0b.",13
	  db " Enjoy!",13
	  db " If you have any suggestions or reports of bugs",13
	  db " wrote me a mail at : stanko_popov@abv.bg",13 
	  db " Greetz:",13
	  db "   * Pumqara",13
	  db "   * Jeux",13
	  db "   * FrostyKid",13
	  db "   * kRio",0
AboutCaption db "About",0	  
NotPackedText db "This File is not Packed with Yoda Protector!",0
NotPackedCaption db "Failure...",0
SelectFileText db "It would be more funny if you select a file!",0
.data?
;DWORDS
hInstance HINSTANCE ?
FileHandle HINSTANCE ?
FileSizeA HINSTANCE ?
allocatedmem HINSTANCE ?
readbytes HINSTANCE ?
allocatedmem2 HINSTANCE ?
VOffset HINSTANCE ?
SaveResult HINSTANCE ?
SizeOfImage HINSTANCE ?
allocatedmem3 HINSTANCE ?
SectionAlignment HINSTANCE ?
UnpackedFileHandle HINSTANCE ?
ReturnValue HINSTANCE ?
NextDescriptor HINSTANCE ?
SizeOfSection HINSTANCE ?
ImageBase HINSTANCE ?
ROffset HINSTANCE ?
Pointer1 HINSTANCE ?
Pointer2 HINSTANCE ?
Pointer3 HINSTANCE ?
Pointer4 HINSTANCE ?
Pointer5 HINSTANCE ?
;buffers

PathNameBuff db 256 dup(?)
FileNameBuff db 100 dup(?)
bufFileName db 512 dup(?)
PathOfUnpackedFile db 0FFh dup(?)
EmptyBufFileName db 512 dup(?)
;Structures:
	ofnA OPENFILENAME <>

.code
start:
invoke GetModuleHandle,NULL
mov hInstance,eax
invoke DialogBoxParam,hInstance,offset dialogname,NULL,offset WndProc,NULL

WndProc proc hWin:DWORD,uMsg:DWORD,wParam:DWORD,lParam:DWORD
pushad
.if uMsg == 110h
	invoke LoadIconA,hInstance,500
 	invoke SendMessage,hWin,WM_SETICON,1,eax

.endif
.if uMsg == WM_COMMAND
	.if wParam == 203
		invoke MessageBox,hWin,offset AboutText,offset AboutCaption,40h
		jmp exitt
	.endif
	.if wParam == 204
		mov ecx,offset TitleBar
	      	mov ofnA.lpstrTitle,ecx
	      	mov ofnA.lStructSize,SIZEOF ofnA
	      	mov  ofnA.lpstrFilter, OFFSET strFilterA
	      	mov  ofnA.lpstrFile, OFFSET bufFileName
	      	mov  ofnA.nMaxFile,512
	      	mov  ofnA.Flags, OFN_FILEMUSTEXIST or \
	                             OFN_PATHMUSTEXIST or OFN_LONGNAMES or\
	                             OFN_EXPLORER or OFN_HIDEREADONLY
	      	invoke GetOpenFileName, ADDR ofnA
		cmp eax,0
		je exitt
		invoke SetDlgItemText,hWin,101,offset bufFileName
		invoke SetDlgItemText,hWin,102,offset bufFileName
		jmp exitt
.endif
	.if wParam == 201
		invoke GetDlgItemText,hWin,101,offset EmptyBufFileName,100
		cmp eax,0
		jne ThereIsFileSelected
		invoke MessageBox,NULL,offset SelectFileText,offset NotPackedCaption,40h
		jmp exitt
		ThereIsFileSelected:
		enter 0,0
		invoke CreateFile,offset bufFileName,GENERIC_READ or GENERIC_WRITE,FILE_SHARE_READ or FILE_SHARE_WRITE,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL
		cmp eax,-1
		je ThereIsError
		mov FileHandle,eax
		invoke GetFileSize,FileHandle,NULL
		mov FileSizeA,eax
		invoke VirtualAlloc,NULL,FileSizeA,MEM_COMMIT,PAGE_READWRITE
		mov dword ptr ds:[allocatedmem],eax
		invoke ReadFile,FileHandle,allocatedmem,FileSizeA,offset readbytes,NULL
		invoke CloseHandle,FileHandle
;======================
; End Of Store VOffset
;======================

		mov eax,dword ptr ds:[allocatedmem]
		ADD eax,DWORD PTR DS:[eax+3Ch]           ; find PeHeader
		MOV ESI,eax                              ; ESI == StartOfPeHeader
		mov edi,eax
		ADD ESI,0F8h                             ; find first secion ESI points to the first section
	        xor ecx,ecx
		mov cx,word ptr ds:[edi+6h]            ; ecx == NumberOfSections
		dec ecx
		mov eax,28h                              ; eax == SizeOfSectionHeader
		imul eax,ecx                             ; eax == SizeOfSectionHeader * (NumberOfSections - 1)
		add esi,eax                              ; esi points last Section Header
		mov eax,dword ptr ds:[esi+0Ch]           ; eax == ROffset of yP section
		mov dword ptr ds:[VOffset],eax
		mov eax,dword ptr ds:[esi+14h]
		mov dword ptr ds:[ROffset],eax

;======================
; End Of Store VOffset
;======================
		call CheckRoutine
		test eax,eax
		jne itspacked
		leave
		invoke MessageBox,hWin,offset NotPackedText,offset NotPackedCaption,40h
		jmp exitt
		itspacked:
		call LoadFile
;==========================
; Start of Allocate Memory
;==========================

		mov eax,dword ptr ds:[allocatedmem]
		mov edx,eax
		add edx,dword ptr ds:[edx+3Ch]
		xor ecx,ecx
		mov cx,word ptr ds:[edx+6]
		dec ecx
		add edx,0F8h
		mov eax,28h
		imul eax,ecx
		add edx,eax
		mov ecx,dword ptr ds:[edx+8]
		add ecx,4
		invoke LocalAlloc,LMEM_ZEROINIT,ecx
		mov dword ptr ds:[allocatedmem2],eax
;=======================
; Start Of GetImageBase
;=======================

		mov eax,dword ptr ds:[allocatedmem]
		add eax,dword ptr ds:[eax+3Ch]
		mov eax,dword ptr ds:[eax+34h]
		mov dword ptr ds:[ImageBase],eax
		
;=====================
; End Of GetImageBase
;=====================


		mov eax,dword ptr ds:[VOffset]
		push eax
		mov eax,dword ptr ds:[esi+8h]
		mov dword ptr ds:[SizeOfSection],eax
		;mov dword ptr ds:[esi],6E617473h
		;mov dword ptr ds:[esi+4],006F6F34h
		pop eax
		add eax,dword ptr ds:[allocatedmem]
		add eax,303h
		mov ecx,64h
		mov esi,eax
		mov edi,dword ptr ds:[allocatedmem2]
		rep movsb
		mov ecx,2194h                      ; ECX == number of bytes to decrypt(subs from endaddress beginaddress)
		mov EDX,dword ptr ds:[allocatedmem]
		add edx,dword ptr ds:[VOffset]
		add EDX,367h
		mov EDI,EDX
		mov ESI,EDX
		XOR EAX,EAX
		mov edx,dword ptr ds:[allocatedmem2]
		add edx,64h
		mov dword ptr ds:[edx],0C3h                              ; EAX == 0h
		call dword ptr ds:[allocatedmem2]
		
;==============================
; Start of Decrypting Sections
;==============================

		mov eax,dword ptr ds:[allocatedmem]
		add eax,dword ptr ds:[VOffset]
		add eax,3A2h
		mov ecx,64h
		mov esi,eax
		mov edi,dword ptr ds:[allocatedmem2]
		rep movsb
		mov edx,dword ptr ds:[allocatedmem2]
		add edx,64h
		mov dword ptr ds:[edx],0C3h
		mov ecx,1A8h
		mov edi,dword ptr ds:[allocatedmem]
		add edi,dword ptr ds:[VOffset]
		add edi,60h
		call dword ptr ds:[allocatedmem2]
		mov ecx,036h
		mov eax,dword ptr ds:[allocatedmem]
		add eax,dword ptr ds:[VOffset]
		add eax,0BEDh
		mov esi,eax
		mov edi,dword ptr ds:[allocatedmem2]
		rep movsb
		mov ecx,0CCh
		mov eax,dword ptr ds:[allocatedmem]
		add eax,dword ptr ds:[VOffset]
		add eax,240Fh
		mov edi,eax
		mov esi,eax
		call dword ptr ds:[allocatedmem2]
		call CopySectionNames
		mov eax,dword ptr ds:[allocatedmem]
		call decryptsections
		mov eax,dword ptr ds:[allocatedmem]
		call decryptsections2
;============================
; End of Decrypting Sections
;============================
		
;============================
; Start of Imports Rebuilding
;============================
		push eax
		mov eax,dword ptr ds:[VOffset]
		mov dword ptr ds:[NextDescriptor],eax
		pop eax
		mov edx,offset allocatedmem
		mov edi,dword ptr ds:[edx]
		ADD EDI,DWORD PTR DS:[EDI+3Ch]           ; find StartOfPeHeader
		MOV EBX,DWORD PTR DS:[EDI+0C0h]          ; EBX == RVA of TLSTable
		CMP EBX,0                                ; is there a TLSTable ?
		JE notlstable                            ; if no jmp
		ADD EBX,DWORD PTR DS:[edx]               ; NOTEPAD_.00400000
		MOV EAX,DWORD PTR DS:[EBX+8]
		sub eax,dword ptr ds:[ImageBase]
		add eax,dword ptr ds:[allocatedmem]
		MOV DWORD PTR DS:[EAX],0
		notlstable:
		mov edx,dword ptr ds:[allocatedmem]
		add edx,dword ptr ds:[VOffset]
		add edx,2127h
		LEA ESI,DWORD PTR DS:[EDX]               ; ESI == this address
		PUSH EBX                                 ; push EBX
		mov ebx,dword ptr ds:[allocatedmem]
		add ebx,dword ptr ds:[VOffset]
		add ebx,2403h
		TEST DWORD PTR DS:[EBX],20h              ; test flags
		JE justdontdothat                        ; if not available jmp
		PUSH ESI                                 ; push ESI
		mov ebx,dword ptr ds:[allocatedmem2]
		add ebx,4
		LEA EDI,DWORD PTR DS:[EBX]               ; EDI == pointer to cleared buffer
		XOR ECX,ECX                              ; ECX == 0
		calculateagain2:
		CMP DWORD PTR DS:[ESI+4],0               ; Is it NULL ?
		JE endcalculate                          ; if so jmp
		MOV EDX,DWORD PTR DS:[ESI+4]             ; EDX == Value
		mov ebx,offset allocatedmem
		ADD EDX,DWORD PTR DS:[EBX]               ; EDX == Image Base + Value
		calculateagain:
		CMP DWORD PTR DS:[EDX],0                 ; is there a byte ?
		JE endbla1                               ; if not jmp
		INC ECX                                  ; inc counter
		ADD EDX,4                                ; EDX points to next dword
		JMP calculateagain
		endbla1:
		ADD ESI,0Ch                               ; ESI := ESI + 0Ch
		JMP calculateagain2
		endcalculate:
		XOR EDX,EDX                              ; EDX == 0
		MOV EAX,5                                ; EAX == 5
		MUL ECX                                  ; EAX == EAX mul ECX
		PUSH EAX                                 ; uBytes // number of bytes to allocate
		PUSH 0                                   ; uFlags // allocation attributes
		CALL LocalAlloc                          ; call LocalAlloc
		OR EAX,EAX                               ; API success ?
		JNZ continueexecution                    ; if yes jmp
		ADD ESP,4
		jmp exitt
		continueexecution:
		MOV DWORD PTR DS:[EDI],EAX               ; save allocatedmem into cleared buffer
		MOV DWORD PTR DS:[EDI+4],EAX             ; save it again
		POP ESI                                  ; pop ESI
justdontdothat:
		POP EBX                                  ; EBX == RVA of TLSTable
;==========================================
; Start of Getting Base Address of Library
;==========================================
decryptnextDLL:
		CMP DWORD PTR DS:[ESI+4],0
		JE thereisnoDLL                          ; if not jmp
		MOV EBX,DWORD PTR DS:[ESI]               ; EBX == Value
		pushad
		mov eax,dword ptr ds:[allocatedmem]
		add eax,dword ptr ds:[NextDescriptor]
		add eax,8
		mov dword ptr ds:[eax],0FFFFFFFFh
		add eax,4h
		mov dword ptr ds:[eax],ebx
		mov ebx,dword ptr ds:[esi+4]
		add eax,4
		mov dword ptr ds:[eax],ebx
		mov ebx,dword ptr ds:[esi+8]
		sub eax,10h
		mov dword ptr ds:[eax],ebx
		add eax,14h
		sub eax,dword ptr ds:[allocatedmem]
		mov dword ptr ds:[NextDescriptor],eax
		popad
		mov edx,offset allocatedmem
		ADD EBX,DWORD PTR DS:[EDX]               ; EBX == Image Base + Value
		MOV EAX,EBX                              ; EAX == EBX == RVA
		CALL DecryptName                         ; decrypts Name of DLL
		PUSH EBX                                 ; push Name of DLL
		call LoadLibrary
		TEST EAX,EAX                             ; API success ?
		JE noAPIsuccess                          ; jmp if not
		PUSH EDX                                 
		PUSH EAX                                 ; push base address of DLL
		POP EBX                                  ; EBX == base address of DLL
		POP EDX                                  ; SHELL32.#345
		MOV ECX,DWORD PTR DS:[ESI+8]             ; ECX == VA
		OR ECX,ECX                               ; ECX == 0 ?
		JNZ jmpit                                ; if not jmp
		MOV ECX,DWORD PTR DS:[ESI+4]
		jmpit:
		PUSH EBX                                 ; push base address of DLL
		mov ebx,offset allocatedmem
		ADD ECX,DWORD PTR DS:[EBX]               ; ECX == Pointer to buffer
		MOV EDX,DWORD PTR DS:[ESI+4]             ; EDX == VA
		ADD EDX,DWORD PTR DS:[EBX]               ; EDX == pointer == RVA
		POP EBX                                  ; EBX == base address of DLL
;===============================
; Start of Getting Thunk of API
;===============================
		goanddecryptnextAPI:
		CMP DWORD PTR DS:[ECX],0                 ; is there anything ?
		JE gotothenextDLL                        ; if no jmp
		TEST DWORD PTR DS:[ECX],80000000h        ; test last bit
		JNZ dosomethingwrong                     ; jmp if not available
		MOV EAX,DWORD PTR DS:[ECX]               ; EAX == VA stored in the table
		ADD EAX,2                                ; EAX == VA + 2
		PUSH EBX                                 ; push base address of DLL
		mov ebx,offset allocatedmem
		ADD EAX,DWORD PTR DS:[EBX]               ; EAX == RVA a pointer to buffer
		POP EBX                                  ; EBX == base address of DLL
		PUSH EAX                                 ; push pointer to encrypted string
		CALL DecryptName                         ; decrypts the Name
		POP EAX                                  ; EAX == pointer to decrypted Name Of API
		MOV EDI,EAX                              ; EDI == pointer to Name Of API
		PUSH EDX                                 ; push address
		PUSH ECX                                 ; push pointer to buffer
		PUSH EAX                                 ; push Pointer to Name of API
		PUSH EBX                                 ; push base address of DLL
		CALL GetProcAddress                      ; call GetProcAddress
		OR EAX,EAX                               ; API success ?
		JNZ thereisnoerror                       ; jmp if yes
		POP ECX                                  ; NOTEPAD_.004061B0
		POP EDX                                  ; NOTEPAD_.004061B0
		JMP noAPIsuccess
		thereisnoerror:
		POP ECX                                  ; ECX == pointer to buffer
		POP EDX                                  ; EDX == address
		PUSH EDX                                 ; push address
		PUSHAD                                   ; save all registers
		POPAD                                    ; restores all registers
		POP EDX                                  ; EDX == pointer to buffer where thunk to api will be stored
		;MOV DWORD PTR DS:[EDX],EAX               ; stores thunk to API
		JMP jmpthere5              ; jmps
dosomethingwrong:
		PUSH EDX                                 ; NOTEPAD_.004063F0
		PUSH ECX                                 ; NOTEPAD_.0040F32C
		MOV EAX,DWORD PTR DS:[ECX]
		SUB EAX,80000000h
		PUSH EAX                                 ; SHELL32.ShellExecuteA
		PUSH EBX                                 ; SHELL32.#345
		CALL DWORD PTR DS:[EDX]             ; SHELL32.ShellExecuteA
		TEST EAX,EAX                             ; SHELL32.ShellExecuteA
		JE noAPIsuccess
		POP ECX                                  ; NOTEPAD_.004061B0
		POP EDX                                  ; NOTEPAD_.004061B0
		MOV DWORD PTR DS:[EDX],EAX               ; SHELL32.ShellExecuteA
		jmpthere5:
		ADD ECX,4                                ; ECX points to the next dword
		ADD EDX,4                                ; EDX points to the next dword
		JMP goanddecryptnextAPI                  ; jmps
		
;=============================
; END of Getting thunk of API
;=============================
gotothenextDLL:
		ADD ESI,0Ch
		JMP decryptnextDLL
		
;============================
; End of Imports Rebuilding
;============================
thereisnoDLL:
		XOR EAX,EAX                              ; EAX == 0
		INC EAX                                  ; EAX == 1
		noAPIsuccess:
		CMP EAX,1                                ; EAX == ?
		JE successfullrebuilding                 ; jmps
		ThereIsError:
		invoke MessageBox,NULL,offset Texterror,offset Captionerror,40h
		jmp exitt
		successfullrebuilding:
		call FindPatchOEP
		call FixSectionHeaders
		call FixTlsTable
		call ClearRenameSection
		call WriteFileInDirectory
		popad
		pushad
		invoke MessageBox,hWin,offset SuccessfullText,offset SuccessfullCaption,40h
		jmp exitt
		.elseif wParam == ID_EXIT

   invoke ExitProcess,0   
  .endif 
 .elseif uMsg == WM_CLOSE
    invoke ExitProcess,0
    
.endif
exitt:
	popad	
	xor eax, eax
	ret
WriteFileInDirectory:
		mov eax,dword ptr ds:[esp]
		mov dword ptr ds:[ReturnValue],eax
		leave
		popad
		pushad
		invoke GetDlgItemText,hWin,102,offset PathOfUnpackedFile,0FFh
		invoke CreateFile,offset PathOfUnpackedFile,GENERIC_READ or GENERIC_WRITE,FILE_SHARE_READ or FILE_SHARE_WRITE,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL
		mov UnpackedFileHandle,eax
		invoke WriteFile,UnpackedFileHandle,allocatedmem,SizeOfImage,offset readbytes,NULL
		invoke CloseHandle,UnpackedFileHandle
		;invoke VirtualFree,allocatedmem,SizeOfImage,
		mov eax,dword ptr ds:[ReturnValue]
		sub esp,4
		mov dword ptr ds:[esp],eax
		retn
WndProc endp
DecryptName:
		PUSH ESI                                 ; push ESI
		PUSH EDI                                 ; push pointer to cleared buffer
		MOV ESI,EAX                              ; ESI == StartOfDecrypting
		MOV EDI,EAX                              ; EDI == StartOfDecrypting
		decryptagain2:
		LODS BYTE PTR DS:[ESI]                   ; loads byte to decrypt
		ROR AL,4                                 ; decrypt byte
		STOS BYTE PTR ES:[EDI]                   ; stores decrypted byte
		CMP BYTE PTR DS:[EDI],0                  ; end of decryption ?
		JNZ decryptagain2                         ; if no jmp
		POP EDI                                  ; restore EDI
		POP ESI                                  ; restore ESI
		RETN                                     ; ret



decryptsections:
		call CopyPolyDecryption
		MOV EDI,EAX                             ; NOTEPAD.00400000
		ADD EDI,DWORD PTR DS:[EDI+3Ch]
		MOV ESI,EDI                              ; NOTEPAD.0040000C
		ADD ESI,0F8h
		XOR EDX,EDX
godecryptagainsections:
		PUSH EDX
		PUSH EAX                                 ; NOTEPAD.00400000
		CMP DWORD PTR DS:[ESI],7865742Eh
		JE decrypttextsection
		CMP DWORD PTR DS:[ESI],45444F43h
		JE decrypttextsection
		CMP DWORD PTR DS:[ESI],7461642Eh
		JE decryptdatasection
		CMP DWORD PTR DS:[ESI],41544144h
		JE decryptdatasection
		CMP DWORD PTR DS:[ESI],535342h
		JE decryptbsssection
		CMP DWORD PTR DS:[ESI],6164722Eh
		JE decryptbsssection
		CMP DWORD PTR DS:[ESI],6164692Eh
		JE decryptidatasection
		CMP DWORD PTR DS:[ESI],6164652Eh
		JNZ nodecryptsection
		PUSH EDX
		mov edx,dword ptr ds:[allocatedmem]
		add edx,dword ptr ds:[VOffset]
		add edx,2403h
		TEST DWORD PTR DS:[EDX],80h
		POP EDX                                  ; NOTEPAD.00400000
		JE decryptedatasection
		nodecryptsection:
		JMP decryptnextsection2
		
decryptbsssection:
		CMP DWORD PTR DS:[ESI+14h],0
		JE decryptnextsection2
		CMP DWORD PTR DS:[ESI+10h],0
		JE decryptnextsection2
		PUSHAD
		PUSH ECX
		PUSH EBX                                 ; NOTEPAD.0041043F
		MOV ECX,DWORD PTR DS:[ESI+10h]
		XOR EBX,EBX                              ; NOTEPAD.0041043F
		MOV ESI,DWORD PTR DS:[ESI+0Ch]
		ADD ESI,EAX                              ; NOTEPAD.00400000
		MOV EDI,ESI
		CALL dword ptr ds:[Pointer3]
		POP EBX                                  ; NOTEPAD.00400000
		POP ECX                                  ; NOTEPAD.00400000
		
decryptnextsection:		
		POPAD
decryptnextsection2:
		ADD ESI,28h
		POP EAX                                  ; NOTEPAD.0040000C
		POP EDX                                  ; NOTEPAD.0040000C
		INC EDX                                  ; NOTEPAD.0040F185
		CMP DX,WORD PTR DS:[EDI+6]
		JNZ godecryptagainsections
		RETN



decryptdatasection:
		CMP DWORD PTR DS:[ESI+14h],0
		JE decryptnextsection2
		CMP DWORD PTR DS:[ESI+10h],0
		JE decryptnextsection2
		PUSHAD
		PUSH ECX
		PUSH EBX                                 ; NOTEPAD.0041043F
		MOV ECX,DWORD PTR DS:[ESI+10h]
		XOR EBX,EBX                              ; NOTEPAD.0041043F
		MOV ESI,DWORD PTR DS:[ESI+0Ch]
		ADD ESI,EAX
		MOV EDI,ESI                              ; NOTEPAD.00400000
		CALL dword ptr ds:[Pointer2]
		POP EBX                                  ; NOTEPAD.00400000
		POP ECX                                  ; NOTEPAD.00400000
		jmp decryptnextsection
decrypttextsection:
		CMP DWORD PTR DS:[ESI+14h],0
		JE decryptnextsection2
		CMP DWORD PTR DS:[ESI+10h],0
		JE decryptnextsection2
		PUSHAD
		PUSH ECX
		PUSH EBX                                 ; NOTEPAD.0041043F
		MOV ECX,DWORD PTR DS:[ESI+10h]
		XOR EBX,EBX                              ; NOTEPAD.0041043F
		MOV ESI,DWORD PTR DS:[ESI+0Ch]
		ADD ESI,EAX                              ; NOTEPAD.00400000
		MOV EDI,ESI
		CALL dword ptr ds:[Pointer1]
		POP EBX                                  ; NOTEPAD.00400000
		POP ECX                                  ; NOTEPAD.00400000
		jmp decryptnextsection


decryptidatasection:
		CMP DWORD PTR DS:[ESI+14h],0
		JE decryptnextsection2
		CMP DWORD PTR DS:[ESI+10h],0
		JE decryptnextsection2
		PUSHAD
		PUSH ECX
		PUSH EBX                                 ; NOTEPAD.0041043F
		MOV ECX,DWORD PTR DS:[ESI+10h]
		XOR EBX,EBX                              ; NOTEPAD.0041043F
		MOV ESI,DWORD PTR DS:[ESI+0Ch]
		ADD ESI,EAX
		MOV EDI,ESI                              ; NOTEPAD.00400000
		CALL dword ptr ds:[Pointer4]
		POP EBX                                  ; NOTEPAD.00400000
		POP ECX                                  ; NOTEPAD.00400000
		jmp decryptnextsection

decryptedatasection:
		CMP DWORD PTR DS:[ESI+14h],0
		JE decryptnextsection2
		CMP DWORD PTR DS:[ESI+10h],0
		JE decryptnextsection2
		PUSHAD
		PUSH ECX
		PUSH EBX                                 ; NOTEPAD.0041043F
		MOV ECX,DWORD PTR DS:[ESI+10h]
		XOR EBX,EBX                              ; NOTEPAD.0041043F
		MOV ESI,DWORD PTR DS:[ESI+0Ch]
		ADD ESI,EAX                              ; NOTEPAD.00400000
		MOV EDI,ESI
		CALL dword ptr ds:[Pointer5]
		POP EBX                                  ; NOTEPAD.00400000
		POP ECX                                  ; NOTEPAD.00400000
		jmp decryptnextsection
		







decryptsections2:
		MOV EDI,EAX                              ; EDI == Image Base
		ADD EDI,DWORD PTR DS:[EDI+3Ch]           ; finds StartOfPeHeader
		MOV ESI,EDI                              ; ESI == StartOfPeHeader
		ADD ESI,0F8h                             ; ESI == StartOfSectionHeader (points to first Section)
		XOR EDX,EDX                              ; EDX == 0
		goagain:
		PUSH EDX                                 ; NOTEPAD_.0040F318
		PUSH EAX                                 ; push Image Base
		CMP DWORD PTR DS:[ESI],7865742Eh         ; .text Section ?
		JE textcodesection                       ; if so jmp
		CMP DWORD PTR DS:[ESI],45444F43h         ; CODE Section ?
		JE textcodesection                       ; if so jmp
		CMP DWORD PTR DS:[ESI],7461642Eh         ; .data section
		JE datasection                           ; if so jmp
		CMP DWORD PTR DS:[ESI],41544144h         ; DATA Section ?
		JE datasection                           ; if so jmp
		CMP DWORD PTR DS:[ESI],535342h           ; BSS Section ?
		JE bsssection
		CMP DWORD PTR DS:[ESI],6164722Eh
		JE rdasection
		CMP DWORD PTR DS:[ESI],6164692Eh
		JE idatasection
		CMP DWORD PTR DS:[ESI],6164652Eh
		JE  edatasection                           ; if so jmp
		CMP DWORD PTR DS:[ESI],7273722Eh         ; .rsrc Section ?
		JE resourcesection                       ; if so jmp
		JMP gotonextsection
		textcodesection:
		mov edx,dword ptr ds:[allocatedmem]
		add edx,dword ptr ds:[VOffset]
		add edx,24B3h
		MOV ECX,DWORD PTR DS:[EDX]               ; ECX == ROffset
		push edx
		mov edx,dword ptr ds:[allocatedmem2]
		MOV DWORD PTR DS:[edx],ECX               ; stores ROffset
		pop edx
		JMP godecrypt
		datasection:
		mov edx,dword ptr ds:[allocatedmem]
		add edx,dword ptr ds:[VOffset]
		add edx,24B7h
		mov ecx,dword ptr ds:[edx]
		mov edx,dword ptr ds:[allocatedmem2]
		MOV DWORD PTR DS:[edx],ECX                             
		JMP godecrypt
		bsssection:
		mov edx,dword ptr ds:[allocatedmem]
		add edx,dword ptr ds:[VOffset]
		add edx,24BBh
		MOV ECX,DWORD PTR DS:[EDX]               ; NOTEPAD_.00400000
		push edx
		mov edx,dword ptr ds:[allocatedmem2]
		MOV DWORD PTR DS:[edx],ECX               ; stores ROffset
		pop edx
		JMP godecrypt
		rdasection:
		mov edx,dword ptr ds:[allocatedmem]
		add edx,dword ptr ds:[VOffset]
		add edx,24BFh
		MOV ECX,DWORD PTR DS:[EDX]
		mov edx,dword ptr ds:[allocatedmem2]
		MOV DWORD PTR DS:[EDX],ECX
		JMP godecrypt
		idatasection:
		mov edx,dword ptr ds:[allocatedmem]
		add edx,dword ptr ds:[VOffset]
		add edx,24C3h
		MOV ECX,DWORD PTR DS:[EDX]
		mov edx,dword ptr ds:[allocatedmem2]
		MOV DWORD PTR DS:[EDX],ECX
		JMP godecrypt
		edatasection:
		mov edx,dword ptr ds:[allocatedmem]
		add edx,dword ptr ds:[VOffset]
		add edx,2403h
		TEST DWORD PTR DS:[EDX],80h
		JNZ gotonextsection
		mov edx,dword ptr ds:[allocatedmem]
		add edx,dword ptr ds:[VOffset]
		add edx,24C7h
		MOV ECX,DWORD PTR DS:[EDX]               ; NOTEPAD.00400000
		mov edx,dword ptr ds:[allocatedmem2]
		MOV DWORD PTR DS:[EDX],ECX
		JMP godecrypt


		resourcesection:
		mov edx,dword ptr ds:[allocatedmem]
		add edx,dword ptr ds:[VOffset]
		add edx,2403h
		TEST DWORD PTR DS:[EDX],40h              ; test flags
		JE nodecrypt                             ; if available jmp
		mov edx,dword ptr ds:[allocatedmem]
		add edx,dword ptr ds:[VOffset]
		add edx,24CFh
		MOV ECX,DWORD PTR DS:[EDX]               ; NOTEPAD_.00400000
		mov edx,dword ptr ds:[allocatedmem2]
		MOV DWORD PTR DS:[edx],ECX               ; stores ROffset
		JMP godecrypt
		nodecrypt:
		JMP gotonextsection 
		godecrypt:
		CMP DWORD PTR DS:[ESI+14h],0             ; ROffset == 0
		JE gotonextsection                       ; if so jmp
		CMP DWORD PTR DS:[ESI+10h],0             ; RSize == 0
		JE gotonextsection                       ; if so jmp
		PUSHAD                                   ; saves all registers
		MOV ECX,DWORD PTR DS:[ESI+10h]           ; ECX == RSize
		mov edx,dword ptr ds:[allocatedmem]
		add edx,dword ptr ds:[VOffset]
		add edx,251Fh
		MOV DWORD PTR DS:[EDX],ECX               ; stores RSize
		MOV ESI,DWORD PTR DS:[ESI+0Ch]           ; ESI == VOffset
		ADD ESI,EAX                              ; ESI == Image Base + VOffset == StartOfSection
		mov edx,dword ptr ds:[allocatedmem2]
		add edx,4
		LEA EDI,DWORD PTR DS:[EDX]               ; EDI == this address
		PUSH ECX                                 ; push VOffset
		PUSH ESI                                 ; ESI == StartOfSection
		PUSH EDI                                 ; EDI == pointer to NumberOfBytesRead
		CALL copybytes                           ; copies bytes
		ADD ESP,0Ch                              ; pops values
		MOV EAX,0                                ; EAX == 0
		PUSH EAX                                 ; push NULL
		mov edx,dword ptr ds:[allocatedmem2]
		LEA EAX,DWORD PTR DS:[EDX]               ; EAX contains this address
		PUSH EAX                                 ; push address
		PUSH ESI                                 ; push StartOfSection
		mov edx,dword ptr ds:[allocatedmem]
		add edx,dword ptr ds:[VOffset]
		add edx,251Fh
		LEA EAX,DWORD PTR DS:[EDX]               ; EAX == this address
		PUSH EAX                                 ; push address RSize
		PUSH EDI                                 ; push address
		CALL decryptbytes                        ; decrypts section
		ADD ESP,0Ch                              ; pops values
		MOV ESI,EDI                              ; ESI == EDI == decrypted section
		MOV EAX,0                                ; EAX == 0
		PUSH EAX                                 ; push NULL
		PUSH ECX                                 ; push RSize
		PUSH EDI                                 ; push decrypted buffer
		CALL clearbuffer                         ; clears buffer
		ADD ESP,0Ch
		POPAD                                    ; pops all registers
		gotonextsection:
		ADD ESI,28h                              ; ESI points to the next section header
		POP EAX                                  ; EAX == Image Base
		POP EDX                                  ; EDX == number of sections decrypted
		INC EDX                                  ; inc counter
		CMP DX,WORD PTR DS:[EDI+6]               ; all sections decrypted ?
		JNZ goagain                              ; if not jmp
		RETN                                     ; else ret
copybytes:
		PUSH EBP                                 ; makes stack frame
		MOV EBP,ESP                              ; saves ESP in EBP
		PUSH ECX                                 ; save VOffset
		PUSH EAX                                 ; save Image Base
		PUSH ESI                                 ; save StartOfSection
		PUSH EDI                                 ; save Pointer to NumberOfBytesRead
		MOV EDI,DWORD PTR SS:[EBP+8]             ; EDI == pointer to NumberOfBytesRead
		MOV ESI,DWORD PTR SS:[EBP+0Ch]           ; ESI == StartOfSection
		MOV ECX,DWORD PTR SS:[EBP+10h]           ; ECX == VOffset
		XOR EAX,EAX                              ; EAX == 0
		copyagain:
		LODS BYTE PTR DS:[ESI]                   ; loads a byte from Section
		STOS BYTE PTR ES:[EDI]                   ; stores a byte
		LOOPD copyagain                          ; loop
		POP EDI                                  ; EDI == pointer to buffer of decrypted bytes
		POP ESI                                  ; ESI == StartOfSection
		POP EAX                                  ; EAX == Image Base
		POP ECX                                  ; ECX == RSize
		MOV ESP,EBP                              ; ESP == EBP
		POP EBP                                  ; EBP == Delta Offset
		RETN                                     ; ret

decryptbytes:
		PUSH EBP                                 ; save EBP == Delta Offset
		PUSH EDI                                 ; save EDI
		PUSH ESI                                 ; save ESI == StartOfSection
		PUSH EBX                                 ; save EBX == 1
		PUSH ECX                                 ; save ECX == RSize
		PUSH EDX                                 ; save EDX == decrypted bytes
		SUB ESP,0Ch                              ; makes stack space
		CLD                                      ; clears direction flag
		MOV ESI,DWORD PTR SS:[ESP+28h]           ; ESI == address
		MOV EDI,DWORD PTR SS:[ESP+30h]           ; EDI == StartOfSection
		MOV EBP,3                                ; EBP == 3
		LEA EAX,DWORD PTR DS:[ESI-3]             ; EAX == address
		ADD EAX,DWORD PTR SS:[ESP+2Ch]           ; EAX == address + address
		MOV DWORD PTR SS:[ESP+4],0FFFFFFFFh      ; save EAX
		MOV EAX,EDI                              ; EAX == StartOfSection
		LEA EDX,DWORD PTR SS:[ESP+34h]           ; EDX == pointer to address
		ADD EAX,DWORD PTR DS:[EDX]               ; EAX == StartOfSection + address
		MOV DWORD PTR SS:[ESP],0FFFFFFFFh        ; saves calculated address
		XOR EAX,EAX                              ; EAX == 0
		XOR EBX,EBX                              ; EBX == 0
		LODS BYTE PTR DS:[ESI]                   ; loads a byte from the buffer
		CMP AL,11h                               ; byte <= 11
		JBE jmpiflower                           ; jmp if so
		SUB AL,0Eh                               ; AL sub 0Eh
		JMP jmpthere                             ; jmps
		againoragain:
		ADD EAX,0FFh
		LEA EDX,DWORD PTR DS:[ESI+EAX+12h]
		CMP DWORD PTR SS:[ESP+4],EDX             ; NOTEPAD_.0040F626
		JB jmpattheend
		jmpagain:
		MOV BL,BYTE PTR DS:[ESI]
		INC ESI                                  ; NOTEPAD_.00401000
		OR BL,BL
		JE againoragain
		LEA EAX,DWORD PTR DS:[EAX+EBX+15h]
		JMP jmpthere
		LEA ESI,DWORD PTR DS:[ESI]
		jmptherea:
		CMP DWORD PTR SS:[ESP+4],ESI             ; NOTEPAD_.00401000
		JB jmpattheend
		MOV AL,BYTE PTR DS:[ESI]
		INC ESI                                  
		jmpiflower:
		CMP AL,10h
		JNB jmpiflower2
		OR AL,AL
		JE jmpagain
		ADD EAX,6
		jmpthere:
		LEA EDX,DWORD PTR DS:[EDI+EAX-3]         ; EDX == calculated address
		CMP DWORD PTR SS:[ESP],EDX               ; cmps two addresses
		JB  jmpattheend2                         ; jmp if below
		LEA EDX,DWORD PTR DS:[ESI+EAX-3]         ; EDX == address
		CMP DWORD PTR SS:[ESP+4],EDX             ; cmps with second address
		JB jmpattheend                           ; jmp if below
		MOV ECX,EAX                              ; EAX == ECX
		XOR EAX,EBP
		SHR ECX,2
		AND EAX,EBP
		repeatagain2:
		MOV EDX,DWORD PTR DS:[ESI]               
		ADD ESI,4
		MOV DWORD PTR DS:[EDI],EDX               
		ADD EDI,4
		DEC ECX
		JNZ repeatagain2
		SUB ESI,EAX                              ; NOTEPAD_.0040F626
		SUB EDI,EAX                              ; NOTEPAD_.0040F626
		MOV AL,BYTE PTR DS:[ESI]
		INC ESI                                  ; NOTEPAD_.00401000
		CMP AL,10h
		JNB jmpiflower2
		LEA EDX,DWORD PTR DS:[EDI+3]
		CMP DWORD PTR SS:[ESP],EDX               ; NOTEPAD_.0040F626
		JB jmpattheend2
		SHR EAX,2
		MOV BL,BYTE PTR DS:[ESI]
		LEA EDX,DWORD PTR DS:[EDI-801h]
		LEA EAX,DWORD PTR DS:[EAX+EBX*4]
		INC ESI                                  ; NOTEPAD_.00401000
		SUB EDX,EAX                              ; NOTEPAD_.0040F626
		CMP EDX,DWORD PTR SS:[ESP+30h]
		JB jmpattheend3
		MOV ECX,DWORD PTR DS:[EDX]
		MOV DWORD PTR DS:[EDI],ECX
		ADD EDI,EBP
		JMP there2
		MOV ESI,ESI  
		jmpiflower2:
		CMP AL,40h
		JB jmpiflower3
		MOV ECX,EAX                              ; NOTEPAD_.0040F626
		SHR EAX,2
		LEA EDX,DWORD PTR DS:[EDI-1]
		AND EAX,7
		MOV BL,BYTE PTR DS:[ESI]
		SHR ECX,5
		LEA EAX,DWORD PTR DS:[EAX+EBX*8]
		INC ESI                                  ; NOTEPAD_.00401000
		SUB EDX,EAX                              ; NOTEPAD_.0040F626
		ADD ECX,4
		CMP EAX,EBP
		JNB thereandthere
		JMP hereandhere
		tamtam:
		ADD EAX,0FFh
		LEA EDX,DWORD PTR DS:[ESI+3]
		CMP DWORD PTR SS:[ESP+4],EDX             ; NOTEPAD_.0040F626
		JB jmpattheend
		againbla:
		MOV BL,BYTE PTR DS:[ESI]
		INC ESI                                  ; NOTEPAD_.00401000
		OR BL,BL
		JE tamtam
		LEA ECX,DWORD PTR DS:[EAX+EBX+24h]
		XOR EAX,EAX                              ; NOTEPAD_.0040F626
		JMP thereandhere
		NOP
		jmpiflower3:
		CMP AL,20h
		JB tamtamdam
		AND EAX,1Fh
		JE againbla
		LEA ECX,DWORD PTR DS:[EAX+5]
		thereandhere:
		MOV AX,WORD PTR DS:[ESI]
		LEA EDX,DWORD PTR DS:[EDI-1]
		SHR EAX,2
		ADD ESI,2
		SUB EDX,EAX                              ; NOTEPAD_.0040F626
		CMP EAX,EBP
		JB hereandhere
		thereandthere:
		CMP EDX,DWORD PTR SS:[ESP+30h]
		JB jmpattheend3
		LEA EAX,DWORD PTR DS:[EDI+ECX-3]
		SHR ECX,2
		CMP DWORD PTR SS:[ESP],EAX               ; NOTEPAD_.0040F626
		JB jmpattheend2
		dadata:
		MOV EBX,DWORD PTR DS:[EDX]
		ADD EDX,4
		MOV DWORD PTR DS:[EDI],EBX
		ADD EDI,4
		DEC ECX
		JNZ dadata
		MOV EDI,EAX                              ; NOTEPAD_.0040F626
		XOR EBX,EBX
		there2:
		MOV AL,BYTE PTR DS:[ESI-2]
		AND EAX,EBP
		JE jmptherea
		LEA EDX,DWORD PTR DS:[EDI+EAX]
		CMP DWORD PTR SS:[ESP],EDX               ; NOTEPAD_.0040F626
		JB jmpattheend2
		LEA EDX,DWORD PTR DS:[ESI+EAX]
		CMP DWORD PTR SS:[ESP+4],EDX             ; NOTEPAD_.0040F626
		JB jmpattheend
		MOV EDX,DWORD PTR DS:[ESI]               ; NOTEPAD_.00400012
		ADD ESI,EAX                              ; NOTEPAD_.0040F626
		MOV DWORD PTR DS:[EDI],EDX               ; NOTEPAD_.0040F626
		ADD EDI,EAX                              ; NOTEPAD_.0040F626
		MOV AL,BYTE PTR DS:[ESI]
		INC ESI                                  ; NOTEPAD_.00401000
		JMP jmpiflower2
		LEA ESI,DWORD PTR DS:[ESI]
		hereandhere:
		CMP EDX,DWORD PTR SS:[ESP+30h]
		JB jmpattheend3
		LEA EAX,DWORD PTR DS:[EDI+ECX-3]
		CMP DWORD PTR SS:[ESP],EAX               ; NOTEPAD_.0040F626
		JB jmpattheend2
		XCHG EDX,ESI                             ; NOTEPAD_.00401000
		SUB ECX,EBP
		REP MOVSB 
		MOV ESI,EDX                              ; NOTEPAD_.0040F626
		JMP there2
		blabla3:
		ADD ECX,0FFh
		LEA EDX,DWORD PTR DS:[ESI+3]
		CMP DWORD PTR SS:[ESP+4],EDX             ; NOTEPAD_.0040F626
		JB jmpattheend
		bla4:
		MOV BL,BYTE PTR DS:[ESI]
		INC ESI                                  ; NOTEPAD_.00401000
		OR BL,BL
		JE blabla3
		LEA ECX,DWORD PTR DS:[EBX+ECX+0Ch]
		JMP datada
		LEA ESI,DWORD PTR DS:[ESI]
		tamtamdam:
		CMP AL,10h
		JB tatatada
		MOV ECX,EAX                              ; NOTEPAD_.0040F626
		AND EAX,8
		SHL EAX,0Dh
		AND ECX,7
		JE bla4
		ADD ECX,5
		datada:
		MOV AX,WORD PTR DS:[ESI]
		ADD ESI,2
		LEA EDX,DWORD PTR DS:[EDI+0FFFFC000h]
		SHR EAX,2
		JE thereda
		SUB EDX,EAX                              ; NOTEPAD_.0040F626
		JMP thereandthere
		LEA ESI,DWORD PTR DS:[ESI]
		tatatada:
		LEA EDX,DWORD PTR DS:[EDI+2]
		CMP DWORD PTR SS:[ESP],EDX               ; NOTEPAD_.0040F626
		JB jmpattheend2
		SHR EAX,2
		MOV BL,BYTE PTR DS:[ESI]
		LEA EDX,DWORD PTR DS:[EDI-1]
		LEA EAX,DWORD PTR DS:[EAX+EBX*4]
		INC ESI                                  ; NOTEPAD_.00401000
		SUB EDX,EAX                              ; NOTEPAD_.0040F626
		CMP EDX,DWORD PTR SS:[ESP+30h]
		JB jmpattheend3
		MOV AL,BYTE PTR DS:[EDX]
		MOV BYTE PTR DS:[EDI],AL
		MOV BL,BYTE PTR DS:[EDX+1]
		MOV BYTE PTR DS:[EDI+1],BL
		ADD EDI,2
		JMP there2
		thereda:
		CMP ECX,6
		SETNE AL
		CMP EDI,DWORD PTR SS:[ESP]               ; NOTEPAD_.0040ED0A
		JA jmpattheend2
		MOV EDX,DWORD PTR SS:[ESP+28h]
		ADD EDX,DWORD PTR SS:[ESP+2Ch]            ; NOTEPAD_.0040F636
		CMP ESI,EDX                              ; NOTEPAD_.0040F626
		JA jmpattheend
		JB jmpattheend4
		dadathere:
		SUB EDI,DWORD PTR SS:[ESP+30h]
		LEA EDX,DWORD PTR SS:[ESP+34h]
		MOV DWORD PTR DS:[EDX],EDI               ; NOTEPAD_.0040F63A
		NEG EAX                                  ; NOTEPAD_.0040F626
		ADD ESP,0Ch
		POP EDX                                  ; NOTEPAD_.0040ED0A
		POP ECX                                  ; NOTEPAD_.0040ED0A
		POP EBX                                  ; NOTEPAD_.0040ED0A
		POP ESI                                  ; NOTEPAD_.0040ED0A
		POP EDI                                  ; NOTEPAD_.0040ED0A
		POP EBP                                  ; NOTEPAD_.0040ED0A
		RETN 8
		MOV EAX,1
		JMP dadathere
		jmpattheend4:
		MOV EAX,8
		JMP dadathere
		jmpattheend:
		MOV EAX,4
		JMP dadathere
		jmpattheend2:
		MOV EAX,5
		JMP dadathere
		jmpattheend3:
		MOV EAX,6
		JMP dadathere
		

clearbuffer:
		PUSH EBP                                 ; makes stack frame
		MOV EBP,ESP                              ; save ESP in EBP
		PUSH ECX                                 ; save RSize
		PUSH EBX                                 ; save 1
		PUSH ESI                                 ; save decrypted buffer
		PUSH EDI                                 ; save decrypted buffer
		MOV ESI,DWORD PTR SS:[EBP+8]             ; ESI == decrypted buffer
		MOV ECX,DWORD PTR SS:[EBP+0Ch]           ; ECX == RSize
		MOV EBX,DWORD PTR SS:[EBP+10h]           ; EBX == 0
		maafakaaa:
		MOV BYTE PTR DS:[ESI],BL                 ; clears buffer
		INC ESI                                  ; ESI points to next byte
		LOOPD maafakaaa                          ; loop
		POP EDI                                  ; EDI == cleared buffer
		POP ESI                                  ; ESI == cleared buffer
		POP EBX                                  ; EBX == 1
		POP ECX                                  ; ECX == RSize
		MOV ESP,EBP                              ; release stack frame
		POP EBP                                  ; EBP == Delta Offset
		RETN                                     ; ret

LoadFile:
		pushad
		mov eax,dword ptr ds:[allocatedmem]
		add eax,dword ptr ds:[eax+3Ch]
		mov eax,dword ptr ds:[eax+50h]
		mov dword ptr ds:[SizeOfImage],eax
		invoke VirtualAlloc,NULL,SizeOfImage,MEM_COMMIT,PAGE_READWRITE
		mov dword ptr ds:[allocatedmem3],eax
		mov eax,dword ptr ds:[allocatedmem]
		add eax,dword ptr ds:[eax+3Ch]
		mov eax,dword ptr ds:[eax+54h]
		mov ecx,eax
		mov esi,dword ptr ds:[allocatedmem]
		mov edi,dword ptr ds:[allocatedmem3]
		copyHeaders:
		lodsb
		stosb
		loop copyHeaders
		mov eax,dword ptr ds:[allocatedmem]
		add eax,dword ptr ds:[eax+3Ch]
		xor ecx,ecx
		mov cx,word ptr ds:[eax+6]
		add eax,0F8h
		gotothenextsection:
		push ecx
		push eax
		mov edx,dword ptr ds:[eax+0Ch]
		add edx,dword ptr ds:[allocatedmem3]
		mov ecx,dword ptr ds:[eax+10h]
		mov ebx,dword ptr ds:[eax+14h]
		add ebx,dword ptr ds:[allocatedmem]
		mov esi,ebx
		mov edi,edx
		test ecx,ecx
		je noRSize
		storesectionagain:
		lodsb
		stosb
		loop storesectionagain
		noRSize:
		pop eax
		pop ecx
		add eax,28h
		loop gotothenextsection
		mov eax,dword ptr ds:[allocatedmem3]
		mov dword ptr ds:[allocatedmem],eax
		popad
		retn

FindPatchOEP:
;=======================
; Start of FindPatchOEP
;=======================
		mov edx,dword ptr ds:[allocatedmem]
		add edx,dword ptr ds:[VOffset]
		add edx,2403h
		TEST DWORD PTR DS:[EDX],80h
		JNZ NoMaskingOEP
		mov edx,dword ptr ds:[allocatedmem]
		add edx,dword ptr ds:[VOffset]
		add edx,24AFh
		MOV EAX,DWORD PTR DS:[EDX]
		ROR EAX,10h
		XOR EAX,64616E65h
		NoMaskingOEP:
		mov edx,dword ptr ds:[allocatedmem]
		add edx,dword ptr ds:[edx+3Ch]
		add edx,28h
		mov dword ptr ds:[edx],eax
		retn
		
;=====================
; End of FindPatchOEP
;=====================
FixSectionHeaders:
		mov eax,dword ptr ds:[allocatedmem]
		add eax,dword ptr ds:[eax+3Ch]
		xor ecx,ecx
		mov cx,word ptr ds:[eax+6]
		add eax,0F8h
		push eax
;===============================
; Start of Get SectionAlignment
;===============================
		mov eax,dword ptr ds:[allocatedmem]
		add eax,dword ptr ds:[eax+03Ch]
		mov ebx,dword ptr ds:[eax+38h]
		mov dword ptr ds:[SectionAlignment],ebx
;===============================
; Start of Get SectionAlignment
;===============================
		pop eax
		FixHeaderAgain:
		push ecx
		push eax
		mov eax,dword ptr ds:[eax+8h]
		mov ecx,dword ptr ds:[SectionAlignment]
		xor edx,edx
		div ecx
		inc eax
		mov ecx,dword ptr ds:[SectionAlignment]
		imul eax,ecx
		mov ecx,eax
		pop eax
		mov dword ptr ds:[eax+08h],ecx
		mov dword ptr ds:[eax+10h],ecx
		pop ecx
		mov edx,dword ptr ds:[eax+0Ch]
		mov dword ptr ds:[eax+14h],edx
		add eax,28h
		loop FixHeaderAgain
		retn
;=============================
; Start Of ClearRenameSection
;=============================

ClearRenameSection:
		mov eax,dword ptr ds:[VOffset]
		mov ecx,dword ptr ds:[NextDescriptor]
		sub ecx,eax
		mov eax,dword ptr ds:[SizeOfSection]
		sub eax,ecx
		mov ecx,eax
		mov eax,dword ptr ds:[allocatedmem]
		add eax,dword ptr ds:[NextDescriptor]
		mov esi,eax
		mov edi,eax
		ClearSectionAgain:
		lodsb
		mov eax,0
		stosb
		loop ClearSectionAgain
		retn
		
;===========================
; End Of ClearRenameSection
;===========================

;=======================
; Start Of Fix TlsTable
;=======================
FixTlsTable:
		mov eax,dword ptr ds:[allocatedmem]
		add eax,dword ptr ds:[VOffset]
		add eax,24FBh
		mov esi,eax
		mov eax,dword ptr ds:[allocatedmem]
		add eax,dword ptr ds:[eax+3Ch]
		xor ecx,ecx
		mov cx,word ptr ds:[eax+6]
		add eax,0F8h
		gocheckagain:
		cmp dword ptr ds:[eax],'adr.'
		je goFixTls
		add eax,28h
		loop gocheckagain
		jmp notlstofix
		goFixTls:
		mov eax,dword ptr ds:[eax+0Ch]
		add eax,dword ptr ds:[allocatedmem]
		mov edi,eax
		mov ecx,dword ptr ds:[allocatedmem]
		add ecx,dword ptr ds:[ecx+3Ch]
		mov ebx,edi
		mov edx,dword ptr ds:[allocatedmem]
		sub ebx,edx
		mov edx,dword ptr ds:[ecx+0C0h]
		test edx,edx
		je notlstofix
		mov dword ptr ds:[ecx+0C0h],ebx
		mov ecx,dword ptr ds:[ecx+0C4h]
		test ecx,ecx
		je notlstofix
		xor eax,eax
		storeTlsTable:
		lodsb
		stosb
		loop storeTlsTable
		notlstofix:
		ret
;=====================
; End Of Fix TlsTable
;=====================
;===========================
; Start Of CopySectionNames
;===========================
CopySectionNames:
		MOV EDI,dword ptr ds:[allocatedmem]                             ; NOTEPAD.00400000
		ADD EDI,DWORD PTR DS:[EDI+3Ch]
		MOV ESI,EDI                              ; NOTEPAD.00400104
		ADD ESI,0F8h
		mov edx,dword ptr ds:[allocatedmem]
		add edx,dword ptr ds:[VOffset]
		add edx,240Fh
		MOV EBX,EDX
		XOR EDX,EDX
		GoDecryptSectionNameAgain:
		PUSH EDX
		PUSH ECX
		PUSH EAX                                 ; NOTEPAD.00400000
		PUSH ESI                                 ; NOTEPAD.0041040F
		PUSH EDI                                 ; NOTEPAD.00400104
		MOV EDI,ESI                              ; NOTEPAD.0041040F
		MOV ESI,EBX                              ; NOTEPAD.0041040F
		MOV ECX,8
		DecryptNameAgain:
		LODS BYTE PTR DS:[ESI]
		STOS BYTE PTR ES:[EDI]
		LOOPD DecryptNameAgain
		POP EDI                                  ; NOTEPAD.0040000C
		POP ESI                                  ; NOTEPAD.0040000C
		POP EAX                                  ; NOTEPAD.0040000C
		POP ECX                                  ; NOTEPAD.0040000C
		POP EDX                                  ; NOTEPAD.0040000C
		ADD EBX,8
		ADD ESI,28h
		INC EDX
		CMP DX,WORD PTR DS:[EDI+6]
		JNZ GoDecryptSectionNameAgain
		RETN
		
;=========================
; End Of CopySectionNames
;=========================


;=======================
; Start Of CheckRoutine
;=======================
CheckRoutine:
		mov eax,dword ptr ds:[allocatedmem]
		add eax,dword ptr ds:[eax+3Ch]
		xor ecx,ecx
		mov cx,word ptr ds:[eax+6]
		add eax,0F8h
		mov EDX,dword ptr ds:[allocatedmem]
		add edx,dword ptr ds:[ROffset]
		add EDX,303h
		cmp byte ptr ds:[EDX],0ACh
		jne notpacked
		mov eax,1
		jmp endCheckRoutine
		notpacked:
		mov eax,0
		endCheckRoutine:
		ret
;=====================
; End Of CheckRoutine
;=====================

;=============================
; Start of CopyPolyDecryption
;=============================
CopyPolyDecryption:
		pushad
		mov eax,dword ptr ds:[allocatedmem]
		add eax,dword ptr ds:[VOffset]
		add eax,0F39h                            ;textsection
		mov ecx,35h
		mov esi,eax
		mov edi,dword ptr ds:[allocatedmem2]
		mov dword ptr ds:[Pointer1],edi
		rep movsb
		mov eax,dword ptr ds:[allocatedmem]
		add eax,dword ptr ds:[VOffset]
		add eax,11A0h                             ; datasection
		mov ecx,35h
		mov esi,eax
		mov dword ptr ds:[Pointer2],edi
		rep movsb
		mov eax,dword ptr ds:[allocatedmem]
		add eax,dword ptr ds:[VOffset]
		add eax,0D2Eh                                ; bss section
		mov ecx,35h
		mov esi,eax
		mov dword ptr ds:[Pointer3],edi
		rep movsb
		mov eax,dword ptr ds:[allocatedmem]
		add eax,dword ptr ds:[VOffset]
		add eax,152Dh                               ; idatasection
		mov ecx,35h
		mov esi,eax
		mov dword ptr ds:[Pointer4],edi
		rep movsb
		mov eax,dword ptr ds:[allocatedmem]
		add eax,dword ptr ds:[VOffset]
		add eax,15DEh                                ; edatasection
		mov ecx,35h
		mov esi,eax
		mov dword ptr ds:[Pointer5],edi
		rep movsb
		popad
		retn
;===========================
; End of CopyPolyDecryption
;===========================
END start
