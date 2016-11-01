class UDPDatagram
  attr_reader :bytes

  def initialize(bytes)
    @bytes = bytes
  end

  def source_port
    Utils.word16(bytes[0], bytes[1])
  end

  def destination_port
    Utils.word16(bytes[2], bytes[3])
  end

  def length
    Utils.word16(bytes[4], bytes[5])
  end

  def checksum
    Utils.word16(bytes[6], bytes[7])
  end

  def body
    bytes[8, (length - 8)].pack('C*')
  end
end
