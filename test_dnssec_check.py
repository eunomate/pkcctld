from dns.rcode import NOERROR, REFUSED, SERVFAIL

from dnssec_check import classify

assert classify(True, NOERROR, True, True) == "secure"
assert classify(True, NOERROR, True, False) == "bogus"
assert classify(True, NOERROR, False, None) == "ds_no_dnskey"
assert classify(True, SERVFAIL, False, None) == "unreachable"
assert classify(False, NOERROR, True, None) == "signed_no_ds"
assert classify(False, NOERROR, False, None) == "unsigned"
assert classify(False, SERVFAIL, False, None) == "unreachable"
assert classify(False, REFUSED, False, None) == "unreachable"
print("ok")
