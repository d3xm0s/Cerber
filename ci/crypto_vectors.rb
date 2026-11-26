#!/usr/bin/env ruby
# RFC test vectors - the crypto must match published ground truth.

$LOAD_PATH.unshift File.expand_path('..', __dir__)
load File.expand_path('../cerber.rb', __dir__)
include Cerber

failures = []
t = lambda do |name, got, want|
  if got == want
    puts "PASS #{name}"
  else
    failures << name
    puts "FAIL #{name}: got #{got[0, 40].inspect}"
  end
end

t.("md4 rfc1320", Crypto.md4("abc").unpack1("H*"), "a448017aaf21d8525fc10ae87aa6729d")
t.("md4 ntlm(password)", Crypto.md4("password".encode("UTF-16LE").b).unpack1("H*"), "8846f7eaee8fb117ad06bdd830b7586c")
t.("rc4 rfc vector", Crypto.rc4("Key".b, "Plaintext".b).unpack1("H*"), "bbf316e8d940af0ad3")
t.("nfold kerberos->64", Crypto.nfold("kerberos".b, 8).unpack1("H*"), "6b65726265726f73")
t.("nfold kerberos->128", Crypto.nfold("kerberos".b, 16).unpack1("H*"), "6b65726265726f737b9b5b2b93132b93")
t.("s2k aes128 i1", Crypto.string2key_aes("password", "ATHENA.MIT.EDUraeburn", 16, 1).unpack1("H*"), "42263c6e89f4fc28b8df68ee09799f15")
t.("s2k aes256 i1", Crypto.string2key_aes("password", "ATHENA.MIT.EDUraeburn", 32, 1).unpack1("H*"), "fe697b52bc0d3ce14432ba036a92e65bbb52280990a2fa27883998d72af30161")

key = "k".b * 32
[17, 32, 40, 64, 88].each do |len|
  data = ("hello kerberos world padding test string!!" * 3)[0, len]
  t.("cts roundtrip #{len}", Crypto.aes_cts_decrypt(key, Crypto.aes_cts_encrypt(key, data)), data)
  blob = Crypto.encrypt(18, key, 3, data)
  t.("aes profile #{len}", Crypto.decrypt(18, key, 3, blob), data)
end

key23 = Crypto.string2key_rc4("Sup3rSecret!")
blob = Crypto.encrypt(23, key23, 8, "rc4 hmac payload")
t.("rc4-hmac roundtrip", Crypto.decrypt(23, key23, 8, blob), "rc4 hmac payload")

if failures.empty?
  puts "ALL VECTORS OK"
else
  puts "#{failures.size} FAILURES: #{failures.join(', ')}"
  exit 1
end
