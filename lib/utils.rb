module Utils
  # Interpret bytes `a` and `b` as a 16-bit word
  # by shifting `a` 8 bits to the left and holding
  # `b` in the rightmost 8 bits:
  #
  #     0000 0000 1010 1111
  #               ^
  #
  #     1010 1111 0000 0000
  #     ^
  #
  #  OR 0000 0000 1100 0011
  #     -------------------
  #     1010 1111 1100 0011
  #
  def self.word16(a, b)
    (a << 8) | b
  end
end
