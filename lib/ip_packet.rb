class IPPacket
  attr_reader :bytes

  def initialize(bytes)
    @bytes = bytes
  end

  # IP Version
  #
  # Bits: 0 - 4
  #
  # Take the leftmost nibble of the 1st byte
  # by shifting everything 4 bits to the right:
  #
  #     1010 1111
  #     ^
  #
  #     0000 1010
  #          ^
  #
  def version
    bytes[0] >> 4
  end

  # Internet Header Length (number of 32-bit words in the header)
  #
  # Bits: 4 - 7
  #
  # Take the rightmost nibble of the 1st byte
  # by masking over all bits in the leftmost
  # nibble:
  #
  #     1010 1100
  # AND 0000 1111 (0xF)
  #     ---------
  #     0000 1100
  #
  def ihl
    bytes[0] & 0xF
  end

  # Differentiated Services Code Point
  #
  # Bits: 8 - 13
  #
  # Take the 1st 6 bits of the byte by masking over the
  # last 2 bits, and shifting everything 2 to the right:
  #
  #     1010 1111
  # AND 1111 1100 (0xFC)
  #     ---------
  #     1010 1100
  #     ^
  #
  #     0010 1011
  #       ^
  #
  def dscp
    (bytes[1] & 0xFC) >> 2
  end

  # Explicit Congestion Notification
  #
  # Bits: 14 - 15
  #
  # Take the last 2 bits of the bytes by masking
  # over the first 6:
  #
  #     1010 1110
  # AND 0000 0011 (0x3)
  #     ---------
  #     0000 0010
  #
  def ecn
    bytes[1] & 0x3
  end

  # Total Length (number of bytes in the packet)
  #
  # Bits: 16 - 31
  #
  def total_length
    Utils.word16(bytes[2], bytes[3])
  end

  # Identification
  #
  # Bits: 32 - 47
  #
  def identification
    Utils.word16(bytes[4], bytes[5])
  end

  # Flags
  #
  # Bits: 48 - 50
  #
  # Take the 3 leftmost bits from the 1st nibble
  # by shifting everything 5 bits to the right:
  #
  #     1010 1111
  #     ^
  #
  #     0000 0101
  #           ^
  #
  def flags
    bytes[6] >> 5
  end

  # Fragment Offset
  #
  # Bits: 51 - 63
  #
  # Take the rightmost 5 bits of the 1st byte
  # by masking over the 1st 3 bits, and combine it
  # with the second byte.
  #
  #     0000 0000 1010 1101
  # AND 0000 0000 0001 1111
  #     -------------------
  #     0000 0000 0001 1101
  #               ^
  #
  #     0001 1101 0000 0000
  #     ^
  #
  #  OR 0000 0000 1101 0011
  #     -------------------
  #     0001 1101 1101 0011
  #
  def fragment_offset
    Utils.word16((bytes[6] & 0x1F), bytes[7])
  end

  # Time To Live
  #
  # Bits: 64 - 71
  #
  def time_to_live
    bytes[8]
  end

  # Time To Live
  #
  # Bits: 72 - 79
  #
  def protocol
    bytes[9]
  end

  # Header Checksum
  #
  # Bits: 80 - 95
  #
  def header_checksum
    Utils.word16(bytes[10], bytes[11])
  end

  # Source IP Address
  #
  # Bits: 96 - 127
  #
  def source_ip_address
    bytes[12, 4].join('.')
  end

  # Destination IP Address
  #
  # Bits: 128 - 159
  #
  def destination_ip_address
    bytes[16, 4].join('.')
  end

  def udp_datagram
    UDPDatagram.new(bytes.drop(header_bytes))
  end

  private

  def header_bytes
    (ihl * 32) / 8
  end
end
