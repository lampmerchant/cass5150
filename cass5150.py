from collections import deque
from dataclasses import dataclass, field
from itertools import chain
import struct
import sys
import wave


FILE_TYPE_D = 0x00  # data file
FILE_TYPE_M = 0x01  # memory image
FILE_TYPE_A = 0x40  # ASCII BASIC listing
FILE_TYPE_B = 0x80  # tokenized BASIC program
FILE_TYPE_P = 0xA0  # protected tokenized BASIC program


def crc16(data, reg=0xFFFF, poly=0x1021):
  '''Feed data bytes through a 16-bit CRC calculator and return the register contents when done.'''
  for byte in data:
    reg ^= byte << 8
    for i in range(8): reg = reg << 1 & 0xFFFF ^ (poly if reg & 0x8000 else 0)
  return reg


def zcd(inp, threshold):
  '''Zero crossing detector.  Given signed samples, yield number of samples in between zero crossings.'''
  current_state = None
  last_crossing = 0
  for sample_number, sample in enumerate(inp):
    if current_state is None:
      current_state = True if sample >= 0 else False
    elif current_state is True and -sample >= threshold:
      current_state = False
      yield sample_number - last_crossing
      last_crossing = sample_number
    elif current_state is False and sample >= threshold:
      current_state = True
      yield sample_number - last_crossing
      last_crossing = sample_number


def peak_detector_with_zcd(inp, threshold):
  '''Detects peaks in between zero crossings.  Given signed samples, yield number of samples between peaks.'''
  current_state = None
  last_crossing = 0
  last_peak = 0
  cur_peak = 0
  cur_peak_amplitude = 0
  for sample_number, sample in enumerate(inp):
    if sample > cur_peak_amplitude if current_state else sample < cur_peak_amplitude:
      cur_peak = sample_number
      cur_peak_amplitude = sample
    if current_state is None:
      current_state = True if sample >= 0 else False
    elif current_state is True and -sample >= threshold:
      current_state = False
      last_crossing = sample_number
      yield cur_peak - last_peak
      last_peak = cur_peak
      cur_peak_amplitude = 0
    elif current_state is False and sample >= threshold:
      current_state = True
      last_crossing = sample_number
      yield cur_peak - last_peak
      last_peak = cur_peak
      cur_peak_amplitude = 0


def wav_to_samples(wav):
  '''Read a wave.Wave_read object and yield its contents as signed 8-bit monaural samples.'''
  frame_width = wav.getnchannels() * wav.getsampwidth()
  frame_offset = 0 if sys.byteorder == 'big' else wav.getsampwidth() - 1
  unsigned = True if wav.getsampwidth() == 1 else False
  while frames := wav.readframes(4096):
    for i in range(frame_offset, len(frames), frame_width):
      sample = frames[i]
      yield sample - 128 if unsigned else sample - 256 if sample >= 128 else sample


class CassetteWavWriter:
  '''Writes PC cassettes as WAV files.'''
  
  def __init__(self, filename, framerate, amplitude=100):
    self.wav = wave.open(filename, 'wb')
    self.wav.setnchannels(1)
    self.wav.setsampwidth(1)
    self.wav.setframerate(framerate)
    self.framerate = framerate
    self.amplitude = amplitude
    self.residue = 0.0
  
  def _write(self, value, length):
    '''Write a value for a floating point length of time, maintaining the residue between writes for accuracy.'''
    length = float(length) * self.framerate
    length += self.residue
    self.residue = length - int(length)
    self.wav.writeframes(bytes(value for i in range(int(length))))
  
  def write_silence(self, seconds):
    '''Write silence to the WAV file.'''
    self._write(0x80, seconds)
  
  def write_bits(self, bit, number):
    '''Write a consecutive stream of bits to the WAV file.'''
    if bit:
      for i in range(number):
        self._write(0x80 + self.amplitude, 0.0005)
        self._write(0x80 - self.amplitude, 0.0005)
    else:
      for i in range(number):
        self._write(0x80 + self.amplitude, 0.00025)
        self._write(0x80 - self.amplitude, 0.00025)
  
  def write_byte(self, byte):
    '''Write a byte to the WAV file.'''
    for i in range(8):
      if byte & 0x80:
        self._write(0x80 + self.amplitude, 0.0005)
        self._write(0x80 - self.amplitude, 0.0005)
      else:
        self._write(0x80 + self.amplitude, 0.00025)
        self._write(0x80 - self.amplitude, 0.00025)
      byte <<= 1
  
  def close(self):
    '''Close the WAV file for writing.'''
    self.wav.close()


@dataclass
class CassetteBlock:
  '''Block of a cassette tape section, representing 256 bytes of data followed by a 16-bit CRC.'''
  data: bytes
  crc: int
  
  def crc_good(self): return crc16(chain(self.data, (self.crc >> 8, self.crc & 0xFF))) == 0x1D0F
  
  @classmethod
  def from_data(cls, data):
    retval = cls(data=bytes(data), crc=0)
    retval.crc = crc16(retval.data) ^ 0xFFFF
    return retval


@dataclass
class CassetteSection:
  '''Section of a cassette tape, representing a leader, a sync bit, a sync byte, some number of blocks, and a trailer.'''
  blocks: list[CassetteBlock] = field(default_factory=list)
  
  @classmethod
  def from_bytes(cls, b):
    '''Build a CassetteSection from a bytes-like object.'''
    blocks = []
    next_block = bytearray(256)
    block_idx = -1
    for byte in b:
      block_idx += 1
      next_block[block_idx] = byte
      if block_idx == 255:
        blocks.append(CassetteBlock.from_data(next_block))
        block_idx = -1
    if block_idx != -1:
      pad = next_block[block_idx]
      for i in range(block_idx + 1, 256): next_block[i] = pad
      blocks.append(CassetteBlock.from_data(next_block))
    return cls(blocks=blocks)
  
  @classmethod
  def directory_entry(cls, file_name, file_type, length=0, segment=0x0060, offset=0x081E):
    '''Build a CassetteSection that is a directory entry.'''
    if len(file_name) > 8: raise ValueError('file name must be 8 chars or less')
    file_name = file_name.encode('ascii', 'replace')
    if len(file_name) < 8: file_name = b'%-8s' % file_name
    if not 0 <= file_type < 256: raise ValueError('file type must be from 0-0xFF')
    if not 0 <= length < 65536: raise ValueError('length must be from 0-65535')
    if not 0 <= segment < 65536: raise ValueError('segment must be from 0-0xFFFF')
    if not 0 <= offset < 65536: raise ValueError('offset must be from 0-0xFFFF')
    data = struct.pack('<B8sBHHH240s', 0xA5, file_name, file_type, length, segment, offset, bytes((offset >> 8)
                                                                                                  for i in range(240)))
    return cls(blocks=[CassetteBlock.from_data(data)])
  
  def crc_good(self):
    '''Returns True if all blocks have good CRCs.'''
    return all(block.crc_good() for block in self.blocks)
  
  def bad_crcs(self):
    '''Returns the total number of blocks with bad CRCs.'''
    return sum(0 if block.crc_good() else 1 for block in self.blocks)
  
  def iter_bytes(self):
    '''Yield all bytes in all blocks in sequence.'''
    for block in self.blocks:
      for byte in block.data: yield byte
  
  def is_directory_entry(self):
    '''Returns True if section can be interpreted as a directory entry.'''
    # This should check whether data[16:256] are all equal to data[15] but the diagnostics cassette adds mystery bytes...
    return True if len(self.blocks) == 1 and self.blocks[0].data[0] == 0xA5 and all(
      byte == self.blocks[0].data[17] for byte in self.blocks[0].data[18:]) else False
  
  def as_directory_entry(self):
    '''Returns 5-tuple of (filename, type, length, segment, offset) if section is a directory entry.'''
    if not self.is_directory_entry(): raise ValueError('section is not a directory entry')
    magic, file_name, file_type, length, segment, offset = struct.unpack('<B8sBHHH240x', self.blocks[0].data)
    return file_name.rstrip(), file_type, length, segment, offset


@dataclass
class Cassette:
  '''A cassette tape, an ordered collection of CassetteSections.'''
  sections: list[CassetteSection] = field(default_factory=list)
  
  def append_cas_stream(self, cas):
    '''Interpret a bytes object/byte stream as a CAS file and append its sections; return number of sections appended.'''
    
    sections_appended = 0
    cas_it = iter(cas)
    
    # Find initial leader
    ffs = 0
    while True:
      for byte in cas_it:
        if byte == 0xFF:
          ffs += 1
        elif byte == 0xFE and ffs >= 63:
          break
        else:
          ffs = 0
      else:
        return 0
      try:
        i = next(cas_it)
        if i == 0x16:
          break
        elif i == 0xFF:
          ffs = 1
        else:
          ffs = 0
      except StopIteration:
        return 0
    
    # Read sections, assuming 258 0xFFs is not another section but the leader of the next
    buf = deque()
    cur_sec = CassetteSection()
    for byte in cas_it:
      buf.append(byte)
      if len(buf) < 258: continue
      if len(buf) > 258: buf.popleft()
      if cur_sec and all(i == 0xFF for i in buf):
        self.sections.append(cur_sec)
        sections_appended += 1
        cur_sec = None
      elif cur_sec:
        data = bytes(buf.popleft() for i in range(256))
        crc = buf.popleft() << 8
        crc |= buf.popleft()
        cur_sec.blocks.append(CassetteBlock(data=data, crc=crc))
      else:
        it = iter(buf)
        if not all(next(it) == 0xFF for i in range(256)): continue
        if not next(it) == 0xFE: continue
        if not next(it) == 0x16: continue
        buf = deque()
        cur_sec = CassetteSection()
    if cur_sec and cur_sec.blocks:
      self.sections.append(cur_sec)
      sections_appended += 1
    return sections_appended
  
  @classmethod
  def from_cas_stream(cls, cas):
    '''Create a cassette from a CAS stream.'''
    retval = cls()
    retval.append_cas_stream(cas)
    return retval
  
  @classmethod
  def from_cas(cls, filename):
    '''Create a cassette from a CAS file.'''
    #TODO buffer read in chunks
    with open(filename, 'rb') as fp:
      return cls.from_cas_stream(fp.read())
  
  def append_wav(self, filename, interval_finder=None):
    '''Read a WAV file and append its sections; return number of sections appended.'''
    
    sections_appended = 0
    
    with wave.open(filename, 'rb') as wav:
      interval_finder = interval_finder or (lambda samples: zcd(samples, 16))
      one_low_threshold = (wav.getframerate() * 75) // 100000  # 750 us
      one_high_threshold = (wav.getframerate() * 125) // 100000  # 1250 us
      zero_low_threshold = (wav.getframerate() * 25) // 100000  # 250 us
      zero_high_threshold = (wav.getframerate() * 75) // 100000  # 750 us
      leader_low_threshold = (wav.getframerate() * 833) // 1000000  # 833 us
      leader_high_threshold = (wav.getframerate() * 125) // 100000  # 1250 us
      sync_low_threshold = (wav.getframerate() * 25) // 100000  # 250 us
      sync_high_threshold = (wav.getframerate() * 667) // 1000000  # 667 us
      pulse_length_threshold = (wav.getframerate() * 75) // 100000  # 750 us
      
      interval_iterator = iter(interval_finder(wav_to_samples(wav)))
      interval_queue = deque()
      interval_get = lambda: interval_queue.popleft() if interval_queue else next(interval_iterator)
      interval_unget = interval_queue.appendleft
      current_section = None
      try:
        while True:
          
          # Detect leader and sync bit
          intervals = deque()
          leader_count = 0
          while True:
            intervals.append(interval_get())
            if intervals[-1] > pulse_length_threshold:
              intervals = deque()
              leader_count = 0
              continue
            if len(intervals) < 4: continue
            if leader_count < 1024:
              left = intervals.popleft()
              if leader_low_threshold <= left + intervals[0] <= leader_high_threshold:
                leader_count += 1
              else:
                intervals = deque()
                leader_count = 0
                continue
            else:
              if leader_low_threshold <= intervals[0] + intervals[1] <= leader_high_threshold:
                if sync_low_threshold <= intervals[2] + intervals[3] <= sync_high_threshold:
                  break
                elif leader_low_threshold <= intervals[2] + intervals[3] <= leader_high_threshold:
                  intervals.popleft()
                elif leader_low_threshold <= intervals[1] + intervals[2] <= leader_high_threshold:
                  intervals.popleft()
                else:
                  intervals = deque()
                  leader_count = 0
                  continue
              else:
                intervals = deque()
                leader_count = 0
                continue
          
          # Verify sync byte
          intervals = deque()
          for i in range(16): intervals.append(interval_get())
          it = iter(intervals)
          if not (zero_low_threshold <= next(it) + next(it) <= zero_high_threshold and
                  zero_low_threshold <= next(it) + next(it) <= zero_high_threshold and
                  zero_low_threshold <= next(it) + next(it) <= zero_high_threshold and
                  one_low_threshold <= next(it) + next(it) <= one_high_threshold and
                  zero_low_threshold <= next(it) + next(it) <= zero_high_threshold and
                  one_low_threshold <= next(it) + next(it) <= one_high_threshold and
                  one_low_threshold <= next(it) + next(it) <= one_high_threshold and
                  zero_low_threshold <= next(it) + next(it) <= zero_high_threshold):
            for i in reversed(intervals): interval_unget(i)
            continue
          
          # Start building a CassetteSection
          current_section = CassetteSection()
          bail = False
          while True:
            intervals = deque()
            for i in range((256 + 2) * 8 * 2): intervals.append(interval_get())
            it = iter(intervals)
            data = deque()
            crc = 0
            for i in range(258):
              byte = 0
              for j in range(8):
                byte <<= 1
                interval = next(it) + next(it)
                if one_low_threshold <= interval <= one_high_threshold:
                  byte |= 1
                elif zero_low_threshold <= interval <= zero_high_threshold:
                  pass
                else:
                  for k in reversed(intervals): interval_unget(k)
                  bail = True
                  break
              if bail: break
              if i < 256:
                data.append(byte)
              elif i == 256:
                crc = byte << 8
              elif i == 257:
                crc |= byte
            if bail: break
            current_section.blocks.append(CassetteBlock(data=bytes(data), crc=crc))
          if current_section.blocks:
            self.sections.append(current_section)
            sections_appended += 1
          current_section = None
      
      except StopIteration:
        if current_section and current_section.blocks:
            self.sections.append(current_section)
            sections_appended += 1
      
      return sections_appended
  
  @classmethod
  def from_wav(cls, filename, interval_finder=None):
    '''Create a cassette from a CAS stream.'''
    retval = cls()
    retval.append_wav(filename, interval_finder)
    return retval
  
  def to_cas_stream(self):
    '''Turn a cassette into a CAS stream.'''
    for section in self.sections:
      for leader in range(318): yield 0xFF
      yield 0xFE
      yield 0x16
      for block in section.blocks:
        for byte in block.data: yield byte
        yield block.crc >> 8
        yield block.crc & 0xFF
      for trailer in range(4): yield 0xFF
  
  def to_cas(self, filename):
    '''Turn a cassette into a CAS file.'''
    #TODO buffer write in chunks
    with open(filename, 'wb') as fp:
      fp.write(bytes(self.to_cas_stream()))
  
  def to_wav(self, filename, framerate=22050, amplitude=100, pre_space=0.5, post_space=0.5, leader_ffs=256):
    '''Turn a cassette into a WAV file.'''
    wav = CassetteWavWriter(filename, framerate, amplitude)
    for section in self.sections:
      wav.write_silence(pre_space)
      wav.write_bits(1, leader_ffs * 8)
      wav.write_bits(0, 1)
      wav.write_byte(0x16)
      for block in section.blocks:
        for byte in block.data: wav.write_byte(byte)
        wav.write_byte(block.crc >> 8)
        wav.write_byte(block.crc & 0xFF)
      for i in range(4): wav.write_byte(0xFF)
      wav.write_silence(post_space)
  
  def append_data_file(self, filename, data):
    '''Append a bytes-like object or stream as a data file.'''
    self.sections.append(CassetteSection.directory_entry(filename, 0, 0, 0, 0))
    next_data = bytearray(256)
    ptr = 1
    for byte in data:
      next_data[ptr] = byte
      ptr += 1
      if ptr == 256:
        section = CassetteSection()
        section.blocks.append(CassetteBlock.from_data(next_data))
        self.sections.append(section)
        next_data = bytearray(256)
        ptr = 1
    next_data[0] = ptr
    section = CassetteSection()
    section.blocks.append(CassetteBlock.from_data(next_data))
    self.sections.append(section)

