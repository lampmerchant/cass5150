import struct

import cass5150


def ldcass(data):
  '''Make a Cassette with an ldcass.B that loads data from the cassette at 0x0500 and jumps to it.'''
  retval = cass5150.Cassette()
  retval.sections.append(cass5150.CassetteSection.directory_entry('ldcass', cass5150.FILE_TYPE_B, 256))
  retval.sections.append(cass5150.CassetteSection.from_bytes(int(i, 16) for i in (
    # This is a BASIC program that pokes a machine language program into the 'intra-application communication area' and executes it,
    # the function of which is to load the next section from cassette (which is the data parameter given to this function) into
    # memory at 0000:0500 and execute it.
    '7A 12 0A 00 97 53 45 47 E7 11 00 '        # 10 DEF SEG=0
    '88 12 14 00 98 0C F0 04 2C 0C 0E 00 00 '  # 20 POKE &H4F0,&HE       'PUSH CS      ;INT 15 loads into segment given by CS,
    '96 12 1E 00 98 0C F1 04 2C 0C 07 00 00 '  # 30 POKE &H4F1,&H7       'POP ES       ; which is 0x0000 thanks to DEF SEG=0
    'A4 12 28 00 98 0C F2 04 2C 0C BB 00 00 '  # 40 POKE &H4F2,&HBB      'MOV BX,0500  ;INT 15 loads into offset 0x0500, which is
    'B2 12 32 00 98 0C F3 04 2C 0C 00 00 00 '  # 50 POKE &H4F3,&H0       ' "           ; the start of memory reserved for DOS and
    'C0 12 3C 00 98 0C F4 04 2C 0C 05 00 00 '  # 60 POKE &H4F4,&H5       ' "           ; BASIC
    'CE 12 46 00 98 0C F5 04 2C 0C B9 00 00 '  # 70 POKE &H4F5,&HB9      'MOV CX,xxxx  ;INT 15 loads the number of bytes in the
    'DC 12 50 00 98 0C F6 04 2C 0C %X 00 00 '  # 80 POKE &H4F6,&Hxx      ' "           ; data parameter into memory at the
    'EA 12 5A 00 98 0C F7 04 2C 0C %X 00 00 '  # 90 POKE &H4F7,&Hxx      ' "           ; specified segment and offset
    'F8 12 64 00 98 0C F8 04 2C 0C B4 00 00 '  # 100 POKE &H4F8,&HB4     'MOV AH,02    ;INT 15 operation is to read blocks
    '06 13 6E 00 98 0C F9 04 2C 0C 02 00 00 '  # 110 POKE &H4F9,&H2      ' "           ; "
    '14 13 78 00 98 0C FA 04 2C 0C CD 00 00 '  # 120 POKE &H4FA,&HCD     'INT 15       ;Call INT 15 to do a cassette operation
    '22 13 82 00 98 0C FB 04 2C 0C 15 00 00 '  # 130 POKE &H4FB,&H15     ' "           ; "
    '30 13 8C 00 98 0C FC 04 2C 0C 73 00 00 '  # 140 POKE &H4FC,&H73     'JNC 0500     ;If there was no error, jump to 0000:0500 to
    '3E 13 96 00 98 0C FD 04 2C 0C 02 00 00 '  # 150 POKE &H4FD,&H2      ' "           ; execute the code we just loaded
    '4C 13 A0 00 98 0C FE 04 2C 0C CD 00 00 '  # 160 POKE &H4FE,&HCD     'INT 19       ;If there was an error, return to BASIC
    '5A 13 AA 00 98 0C FF 04 2C 0C 19 00 00 '  # 170 POKE &H4FF,&H19     ' "           ; "
    '6D 13 B4 00 91 22 4C 4F 41 44 49 4E 47 '  # 180 PRINT "LOADING..."
     '2E 2E 2E 22 00 '                         #  "
    '7A 13 BE 00 41 E7 0C F0 04 00 '           # 190 A=&H4F0
    '83 13 C8 00 B3 41 00 '                    # 200 CALL A
    '00 00'
    % tuple(struct.pack('<H', len(data)))).split()))
  retval.sections.append(cass5150.CassetteSection.from_bytes(data))
  return retval
