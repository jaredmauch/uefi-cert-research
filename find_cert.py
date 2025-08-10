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
import argparse
import base64
import requests
import sys

# packages after
try:
    from cryptography import x509
except ModuleNotFoundError:
    print("ERROR: you need the cryptography x509 python module, suggested fix:")
    print("    sudo apt-install -y python3-cryptography")
    print("  or ")
    print("    pip3 install --user cryptography")
    print("")
    sys.exit(1)

parser = argparse.ArgumentParser(description='''
parse files searching for x509 data
''', epilog='''project details at uefi-cert-research.org
''')

UPLOAD_URL="https://api.uefi-cert-research.org/upload-cert.cgi"
debug = False
upload_data = True

cert_files = []
cert_der_data = []

parser.add_argument("-d", "--debug",  dest="Debug",  help="enable debug tracing",
    action='store_true')
parser.add_argument("-n", "--no-upload", help="disable upload of seen certs",
    action='store_false')
parser.add_argument(dest="file",  help="file to parse", nargs='+')
#
args=parser.parse_args()
#
if args.Debug:
    debug = True
#
if not args.no_upload:
    upload_data = False

#
for filename in args.file:
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
                    
                # Check for SEQUENCE tag (0x30)
                if ba[x] == 0x30:
                    # Check for valid length encoding
                    length_byte = ba[x + 1]
                    if length_byte < 0x80:  # Short form
                        cert_len = length_byte + 2
                    elif length_byte == 0x82:  # Long form
                        if x + 4 >= length:  # Check if we have enough bytes
                            continue
                        cert_len = ((ba[x + 2] * 256) + ba[x + 3]) + 4
                    else:
                        continue  # Skip other length encodings
                        
                    # Check if we have enough data
                    if x + cert_len > length:
                        continue
                        
                    # save start position of suspected x509 data
                    CERT_INDEX = x

                    # copy the related data
                    cert_space = b"" + ba[CERT_INDEX:(CERT_INDEX + cert_len)]

                    # attempt to parse it
                    try:
                        cert = x509.load_der_x509_certificate(cert_space)

                        print(f"x509 cert found @ {CERT_INDEX}:{filename}")
                        print("---- START CERT ----")
                        cert_files.append(f"{CERT_INDEX}@{filename}")
                        cert_der_data.append(cert_space)

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
    except PermissionError as e:
        # skip to next pathname
        print(f"WARN: unable to parse {filename} {e}")
        pass
    except FileNotFoundError:
        pass # perhaps a bogus symlink

#
#print(f"upload_data={upload_data}")

# Upload certificates if enabled
if upload_data and cert_der_data:
    for cert_der in cert_der_data:
        b64_data = base64.b64encode(cert_der).decode()
        # print(b64_data)
        res = requests.post(url=UPLOAD_URL, data=b64_data,
            headers={'Content-Type': 'application/octet-stream'})
        if not res.ok:
            print(res)
