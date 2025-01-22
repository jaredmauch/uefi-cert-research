#!/usr/bin/python3

try:
    import asn1
except:
    import asn1crypto
from cryptography import x509
import sys

#
cert_files = []

for filename in sys.argv:

    try:
        fh = open (filename, 'rb') # open file as binary
    except IsADirectoryError:
        next

    # read into memory
    ba = bytearray(fh.read())

    # determine how many bytes
    length = len(ba)

    cert_index = -1
    for x in range(0, length-4):
        if cert_index > -1 and x < cert_index:
            continue
        if ba[x] == 0x30 and ba[x+1] == 0x82:
            #print("len@=%d/index=%d" % (length, x))

            #print("%s:[%d] has 0x3082 signature" % (filename, x))
            # x509.load_der_x509_certificate(endpoint.ServerCertificate[:1151])

            cert_index = x
            cert_len = ((ba[x+2] * 256) + ba[x+3]) + 4
            cert_space = b""+ ba[x:]
            #print("x=%d + cert_len=%d" % (x, cert_len))
            cert_index = x
#            try:
#                print("next_index=(%x/%d) %2.2x%2.2x" % (x+cert_len, x+cert_len, int(ba[cert_len + x]), int(ba[cert_len + x+1])))
#            except:
#                pass
            #
            try: 
                cert = x509.load_der_x509_certificate(cert_space[:cert_len])
                print("x509 cert found @ %d:%s" % (cert_index, filename))
                print("---- START CERT ----")
                cert_files.append("%s:%d" % (filename, cert_index))

                print("serial:           ", cert.serial_number)
                try:
                    print("NOT_VALID_BEFORE: ", cert.not_valid_before_utc)
                except:
                    print("not_valid_before: ", cert.not_valid_before)
                try:
                    print("NOT_VALID_AFTER:  ", cert.not_valid_after_utc)
                except:
                    print("not_valid_after:  ", cert.not_valid_after)
                print("CERT_ISSUER:      ", cert.issuer)
                print("Subject:          ", cert.subject)
#                for ex in cert.extensions:
#                    print("\tcritical:", ex.critical)
#                    print("\toid:", ex.oid._name)
#                    print("\t\tkey_identifier:", ex.value.key_identifier)
#                    print("\t\toid:", ex.value.oid)
#                    print("\tvalue:", dir(ex.value))
#                print("extensions:       ", cert.extensions)
                print("signature_hash_algorithm:", cert.signature_hash_algorithm.name)
                print("signature_algorithm_parameters", cert.signature_algorithm_parameters.name)
#                print("verify_directly_issued_by:", cert.verify_directly_issued_by.__text_signature__)
                print("version", cert.version)

#                print(dir(cert))
                print("---- END CERT ----")
                x = cert_index + cert_len
                cert_index = -1
            except Exception as e:
#                print(e)
                cert_index = -1


