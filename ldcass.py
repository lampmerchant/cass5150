import struct

import cass5150


def ldcass(data):
  '''Make a Cassette with an ldcass.B that loads data from the cassette at 0x0500 and jumps to it.'''
  retval = cass5150.Cassette()
  retval.sections.append(cass5150.CassetteSection.directory_entry('ldcass', cass5150.FILE_TYPE_B, 256))
  retval.sections.append(cass5150.CassetteSection.from_bytes(int(i, 16) for i in ('''
    7A 12 0A 00 97 53 45 47 E7 11 00 88 12 14 00 98
    0C F0 04 2C 0C 0E 00 00 96 12 1E 00 98 0C F1 04
    2C 0C 07 00 00 A4 12 28 00 98 0C F2 04 2C 0C BB
    00 00 B2 12 32 00 98 0C F3 04 2C 0C 00 00 00 C0
    12 3C 00 98 0C F4 04 2C 0C 05 00 00 CE 12 46 00
    98 0C F5 04 2C 0C B9 00 00 DC 12 50 00 98 0C F6
    04 2C 0C %X 00 00 EA 12 5A 00 98 0C F7 04 2C 0C
    %X 00 00 F8 12 64 00 98 0C F8 04 2C 0C B4 00 00
    06 13 6E 00 98 0C F9 04 2C 0C 02 00 00 14 13 78
    00 98 0C FA 04 2C 0C CD 00 00 22 13 82 00 98 0C
    FB 04 2C 0C 15 00 00 30 13 8C 00 98 0C FC 04 2C
    0C 73 00 00 3E 13 96 00 98 0C FD 04 2C 0C 02 00
    00 4C 13 A0 00 98 0C FE 04 2C 0C CD 00 00 5A 13
    AA 00 98 0C FF 04 2C 0C 19 00 00 6D 13 B4 00 91
    22 4C 4F 41 44 49 4E 47 2E 2E 2E 22 00 7A 13 BE
    00 41 E7 0C F0 04 00 83 13 C8 00 B3 41 00 00 00
    ''' % tuple(struct.pack('<H', len(data)))).split()))
  retval.sections.append(cass5150.CassetteSection.from_bytes(data))
  return retval
