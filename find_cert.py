#!/usr/bin/python3

""" This application tries to find x509 certificates, with a focus on
    those that are expired or likely expired.

"""
#    This script is maintained by Jared Mauch <jared@puck.nether.net>.
#    If you find problems, please submit bug reports/patches via the
#    github issue tracker
#
#    https://github.com/jaredmauch/uefi-cert-research/issues

# future plans - upload expired certificates
# upload all certificates
# upload unseen certificates
#
# do something like x509watch and report on just those that expire soon
# like in the next 180 days due to how long it might take to patch firmware?

# builtins before
import sys

# packages after
from cryptography import x509

debug = False

cert_files = []

for filename in sys.argv:

    try:
        # open file as binary
        with open(filename, 'rb') as fh:

            # read into memory
            ba = bytearray(fh.read())

            # determine how many bytes
            length = len(ba)

            CERT_INDEX = -1
            # search the file contents
            for x in range(0, (length - 4)):
                if CERT_INDEX > -1 and x < CERT_INDEX:
                    # skip ahead
                    continue
                if ba[x] == 0x30 and ba[(x + 1)] == 0x82:
                    # save start position of suspected x509 data
                    CERT_INDEX = x

                    # attempt to extract the length
                    cert_len = ((ba[(x + 2)] * 256) + ba[(x + 3)]) + 4

                    # copy the related data
                    cert_space = b"" + ba[CERT_INDEX:(CERT_INDEX + cert_len)]

                    # attempt to parse it
                    try:
                        cert = x509.load_der_x509_certificate(cert_space)

                        print(f"x509 cert found @ {CERT_INDEX}:{filename}")
                        print("---- START CERT ----")
                        cert_files.append(f"{CERT_INDEX}@{filename}")

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
                        print("signature_hash_algorithm:",
                            cert.signature_hash_algorithm.name)
                        print("signature_algorithm_parameters",
                            cert.signature_algorithm_parameters.name)
                        print("version", cert.version)
                        print("---- END CERT ----")

                        # attempt to advance to the end
                        x = CERT_INDEX + cert_len
                        # clear that we are in a cert
                        CERT_INDEX = -1

                    except Exception as e:
                        CERT_INDEX = -1
                        if debug:
                            print(f"{filename}@{CERT_INDEX}:{e}")
    except IsADirectoryError:
        # skip to next pathname
        pass
