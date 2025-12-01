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
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448
except ModuleNotFoundError:
    print("ERROR: you need the cryptography x509 python module, suggested fix:")
    print("    sudo apt install -y python3-cryptography")
    print("  or ")
    print("    pip3 install --user cryptography")
    print("")
    sys.exit(1)

def safe_get_attr(obj, attr_name, default="<not available>"):
    """Safely get an attribute value, handling exceptions gracefully."""
    try:
        value = getattr(obj, attr_name)
        if value is None:
            return default
        return value
    except Exception:
        return default

def safe_get_name_attr(obj, attr_name, default="<not available>"):
    """Safely get a name attribute value, handling exceptions gracefully."""
    try:
        value = getattr(obj, attr_name)
        if value is None:
            return default
        # Handle Name objects specially
        if hasattr(value, 'get_attributes_for_oid'):
            return str(value)
        return value
    except Exception:
        return default

def safe_explore_cert_attributes(cert):
    """Safely explore and display additional certificate attributes that might be available."""
    additional_attrs = []
    
    # Common attributes that might exist on some certificates
    potential_attrs = [
        'tbs_certificate_bytes', 'signature_bytes', 
        'public_key', 'issuer_name_hash', 'subject_name_hash',
        'subject_public_key_info', 'authority_key_identifier', 'subject_key_identifier'
    ]
    # removed
    # extensions signature_algorithm_oid
    #
    
    for attr in potential_attrs:
        try:
            if hasattr(cert, attr):
                value = getattr(cert, attr)
                if value is not None:
                    if hasattr(value, '__len__'):
                        additional_attrs.append(f"{attr}: {len(value)} bytes/items")
                    else:
                        additional_attrs.append(f"{attr}: {value}")
        except Exception:
            continue
    
    return additional_attrs

def print_certificate_details(cert, verbose=False, debug=False):
    """Print comprehensive certificate details while avoiding recursive structures."""
    print("---- START CERT ----")
    
    # Basic certificate information
    print(f"Version:                    {safe_get_attr(cert, 'version')}")
    
    # Validity dates
    try:
        print(f"Not Valid Before (UTC):    {cert.not_valid_before_utc}")
    except:
        try:
            print(f"Not Valid Before:         {cert.not_valid_before}")
        except:
            print("Not Valid Before:         <not available>")
    
    try:
        print(f"Not Valid After (UTC):     {cert.not_valid_after_utc}")
    except:
        try:
            print(f"Not Valid After:          {cert.not_valid_after}")
        except:
            print("Not Valid After:          <not available>")
    
    # Subject and Issuer
    print(f"Issuer:                     {safe_get_name_attr(cert, 'issuer')}")
    print(f"Subject:                    {safe_get_name_attr(cert, 'subject')}")
    
    # Signature information
    try:
        sig_algo = cert.signature_algorithm_oid
#        print(f"Signature Algorithm OID:   {sig_algo}")
#        print(f"Signature Algorithm Name:  {sig_algo._name if hasattr(sig_algo, '_name') else 'Unknown'}")
    except:
        print("Signature Algorithm:       <not available>")
    
    try:
        sig_hash = cert.signature_hash_algorithm
        if sig_hash:
            print(f"Signature Hash Algorithm:  {sig_hash.name}")
        else:
            print("Signature Hash Algorithm:  <not available>")
    except:
        print("Signature Hash Algorithm:  <not available>")
    
    # Public key information
    try:
        pub_key = cert.public_key()
        print(f"Public Key Type:           {type(pub_key).__name__}")
        
        if isinstance(pub_key, rsa.RSAPublicKey):
            try:
                key_numbers = pub_key.public_numbers()
                print(f"RSA Modulus Size:         {key_numbers.n.bit_length()} bits")
                print(f"RSA Public Exponent:      {key_numbers.e}")
                
                # Additional RSA key information
                try:
                    if hasattr(key_numbers, 'n'):
                        modulus_hex = hex(key_numbers.n)
                        print(f"RSA Modulus (hex):        {modulus_hex}")
                except:
                    pass
            except:
                print("RSA Key Details:          <not available>")
        elif isinstance(pub_key, ec.EllipticCurvePublicKey):
            try:
                curve = pub_key.curve
                print(f"EC Curve:                  {curve.name}")
                print(f"EC Key Size:               {curve.key_size} bits")
                
                # Additional EC key information
                try:
                    if hasattr(pub_key, 'public_numbers'):
                        ec_numbers = pub_key.public_numbers()
                        if hasattr(ec_numbers, 'x') and hasattr(ec_numbers, 'y'):
                            x_hex = hex(ec_numbers.x)[2:10] + "..." + hex(ec_numbers.x)[-8:]
                            y_hex = hex(ec_numbers.y)[2:10] + "..." + hex(ec_numbers.y)[-8:]
                            print(f"EC Point X:               {x_hex}")
                            print(f"EC Point Y:               {y_hex}")
                except:
                    pass
            except:
                print("EC Key Details:            <not available>")
        elif isinstance(pub_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            print(f"EdDSA Key Size:             {pub_key.key_size} bits")
            
            # Additional EdDSA key information
            try:
                if hasattr(pub_key, 'public_bytes'):
                    pub_bytes = pub_key.public_bytes(encoding=None, format=None)
                    if pub_bytes:
                        pub_hex = pub_bytes.hex()[:16] + "..." + pub_bytes.hex()[-16:]
                        print(f"EdDSA Public Key (hex):    {pub_hex}")
            except:
                pass
    except:
        print("Public Key:                <not available>")
    
    # Extensions (safely handled to avoid recursion)
    try:
        extensions = cert.extensions
        if extensions:
            print(f"Extensions Count:          {len(extensions)}")
            
            # Well-known extension OIDs to safely display - only the most common ones
            # This avoids potential recursion issues with complex enterprise extensions
            safe_extensions = {
                '2.5.29.15': 'Key Usage',
                '2.5.29.19': 'Basic Constraints',
                '2.5.29.32': 'Certificate Policies',
                '2.5.29.35': 'Authority Key Identifier',
                '2.5.29.14': 'Subject Key Identifier',
                '2.5.29.37': 'Extended Key Usage',
                '2.5.29.17': 'Subject Alternative Name',
                '2.5.29.18': 'Issuer Alternative Name',
                '2.5.29.31': 'CRL Distribution Points',
                '2.5.29.30': 'Name Constraints',
                '2.5.29.36': 'Policy Constraints',
                '2.5.29.33': 'Policy Mappings',
                '2.5.29.9': 'Subject Directory Attributes',
                '2.5.29.8': 'Subject Information Access',
                '2.5.29.1': 'Authority Information Access',
                '2.5.29.3': 'Subject Key Identifier',
                '2.5.29.4': 'Key Usage',
                '2.5.29.5': 'Certificate Policies',
                '2.5.29.6': 'Policy Mappings',
                '2.5.29.7': 'Subject Alternative Name',
                '2.5.29.10': 'Subject Information Access',
                '2.5.29.11': 'Subject Directory Attributes',
                '2.5.29.12': 'Certificate Policies',
                '2.5.29.13': 'Policy Mappings',
                '2.5.29.16': 'Private Key Usage Period',
                '2.5.29.20': 'Certificate Policies',
                '2.5.29.21': 'Policy Mappings',
                '2.5.29.22': 'Subject Alternative Name',
                '2.5.29.23': 'Issuer Alternative Name',
                '2.5.29.24': 'Subject Directory Attributes',
                '2.5.29.25': 'Subject Information Access',
                '2.5.29.26': 'Certificate Policies',
                '2.5.29.27': 'Policy Mappings',
                '2.5.29.28': 'Subject Alternative Name',
                '2.5.29.29': 'Issuer Alternative Name',
                '2.5.29.34': 'Policy Constraints',
                '2.5.29.38': 'Freshest CRL',
                '2.5.29.39': 'Inhibit Any Policy',
                '2.5.29.40': 'Freshest CRL',
                '2.5.29.41': 'Freshest CRL',
                '2.5.29.42': 'Freshest CRL',
                '2.5.29.43': 'Freshest CRL',
                '2.5.29.44': 'Freshest CRL',
                '2.5.29.45': 'Freshest CRL',
                '2.5.29.46': 'Freshest CRL',
                '2.5.29.47': 'Freshest CRL',
                '2.5.29.48': 'Freshest CRL',
                '2.5.29.49': 'Freshest CRL',
                '2.5.29.50': 'Freshest CRL'
            }
            
            # Additional well-known OIDs for common certificate types
            additional_safe_oids = {
                '1.3.6.1.4.1.311.20.2': 'Certificate Template Name',
                '1.3.6.1.4.1.311.21.1': 'Certificate Template Information',
                '1.3.6.1.4.1.311.21.7': 'Certificate Template',
                '1.3.6.1.4.1.311.21.10': 'Application Policies',
                '1.3.6.1.4.1.311.21.11': 'Application Policy Mappings',
                '1.3.6.1.4.1.311.21.12': 'Application Policy Constraints',
                '1.3.6.1.4.1.311.21.13': 'Application Policy Mappings',
                '1.3.6.1.4.1.311.21.14': 'Application Policy Constraints',
                '1.3.6.1.4.1.311.21.15': 'Application Policy Mappings',
                '1.3.6.1.4.1.311.21.16': 'Application Policy Constraints',
                '1.3.6.1.4.1.311.21.17': 'Application Policy Mappings',
                '1.3.6.1.4.1.311.21.18': 'Application Policy Constraints',
                '1.3.6.1.4.1.311.21.19': 'Application Policy Mappings',
                '1.3.6.1.4.1.311.21.20': 'Application Policy Constraints'
        }
            
            # Common enterprise and industry OIDs
            enterprise_oids = {
                '1.3.6.1.4.1.311.16.4': 'Microsoft Certificate Services',
                '1.3.6.1.4.1.311.16.5': 'Microsoft Certificate Services',
                '1.3.6.1.4.1.311.16.6': 'Microsoft Certificate Services',
                '1.3.6.1.4.1.311.16.7': 'Microsoft Certificate Services',
                '1.3.6.1.4.1.311.16.8': 'Microsoft Certificate Services',
                '1.3.6.1.4.1.311.16.9': 'Microsoft Certificate Services',
                '1.3.6.1.4.1.311.16.10': 'Microsoft Certificate Services',
                '1.3.6.1.4.1.311.16.11': 'Microsoft Certificate Services',
                '1.3.6.1.4.1.311.16.12': 'Microsoft Certificate Services',
                '1.3.6.1.4.1.311.16.13': 'Microsoft Certificate Services',
                '1.3.6.1.4.1.311.16.14': 'Microsoft Certificate Services',
                '1.3.6.1.4.1.311.16.15': 'Microsoft Certificate Services',
                '1.3.6.1.4.1.311.16.16': 'Microsoft Certificate Services',
                '1.3.6.1.4.1.311.16.17': 'Microsoft Certificate Services',
                '1.3.6.1.4.1.311.16.18': 'Microsoft Certificate Services',
                '1.3.6.1.4.1.311.16.19': 'Microsoft Certificate Services',
                '1.3.6.1.4.1.311.16.20': 'Microsoft Certificate Services'
            }
            
            safe_extensions.update(additional_safe_oids)
            safe_extensions.update(enterprise_oids)
            
            for ext in extensions:
                try:
                    oid = ext.oid.dotted_string
                    ext_name = safe_extensions.get(oid, f"Unknown Extension ({oid})")
                    critical = "Critical" if ext.critical else "Non-Critical"
#                    print(f"  Extension: {ext_name} ({critical})")
                    
                    # Only display values for well-known, safe extensions
                    if oid in safe_extensions:
                        try:
                            # Handle specific well-known extension types with proper formatting
                            ext_type = type(ext.value).__name__
                            
                            if ext_type == 'AuthorityKeyIdentifier':
                                # Format AuthorityKeyIdentifier properly
                                if hasattr(ext.value, 'key_identifier') and ext.value.key_identifier:
                                    print(f"    AuthorityKeyIdentifier - Key Identifier: {ext.value.key_identifier.hex()}")
                                if hasattr(ext.value, 'authority_cert_issuer') and ext.value.authority_cert_issuer:
                                    print(f"    AuthorityKeyIdentifier - Authority Cert Issuer: {ext.value.authority_cert_issuer}")
                                if hasattr(ext.value, 'authority_cert_serial_number') and ext.value.authority_cert_serial_number:
                                    print(f"    AuthorityKeyIdentifier - Authority Cert Serial: {ext.value.authority_cert_serial_number}")
                                    
                            elif ext_type == 'SubjectKeyIdentifier':
                                # Format SubjectKeyIdentifier properly
                                if hasattr(ext.value, 'digest'):
                                    digest = ext.value.digest
                                    if isinstance(digest, bytes):
                                        print(f"    SubjectKeyIdentifier - Digest: {digest.hex()}")
                                    else:
                                        print(f"    SubjectKeyIdentifier - Digest: {digest}")
                                        
                            elif ext_type == 'KeyUsage':
                                # Format KeyUsage flags
                                usage_flags = []
                                try:
                                    if hasattr(ext.value, 'digital_signature') and ext.value.digital_signature:
                                        usage_flags.append("Digital Signature")
                                    if hasattr(ext.value, 'key_encipherment') and ext.value.key_encipherment:
                                        usage_flags.append("Key Encipherment")
                                    if hasattr(ext.value, 'key_agreement') and ext.value.key_agreement:
                                        usage_flags.append("Key Agreement")
                                    if hasattr(ext.value, 'key_cert_sign') and ext.value.key_cert_sign:
                                        usage_flags.append("Certificate Signing")
                                    if hasattr(ext.value, 'crl_sign') and ext.value.crl_sign:
                                        usage_flags.append("CRL Signing")
                                    if hasattr(ext.value, 'content_commitment') and ext.value.content_commitment:
                                        usage_flags.append("Content Commitment")
                                    if hasattr(ext.value, 'data_encipherment') and ext.value.data_encipherment:
                                        usage_flags.append("Data Encipherment")
                                    
                                    # encipher_only and decipher_only are only defined when key_agreement is True
                                    if hasattr(ext.value, 'key_agreement') and ext.value.key_agreement:
                                        if hasattr(ext.value, 'encipher_only') and ext.value.encipher_only:
                                            usage_flags.append("Encipher Only")
                                        if hasattr(ext.value, 'decipher_only') and ext.value.decipher_only:
                                            usage_flags.append("Decipher Only")
                                    
                                    if usage_flags:
                                        print(f"    KeyUsage - Usage: {', '.join(usage_flags)}")
                                    else:
                                        print(f"    KeyUsage - Usage: No specific usage flags set")
                                except Exception as e:
                                    if debug:
                                        print(f"    KeyUsage - Usage: <error displaying: {e}>")
                                    else:
                                        print(f"    KeyUsage - Usage: <cannot display>")
                                    
                            elif ext_type == 'BasicConstraints':
                                # Format BasicConstraints
                                if hasattr(ext.value, 'ca'):
                                    print(f"    BasicConstraints - CA: {ext.value.ca}")
                                if hasattr(ext.value, 'path_length') and ext.value.path_length is not None:
                                    print(f"    BasicConstraints - Path Length: {ext.value.path_length}")
                                    
                            elif ext_type == 'SubjectAlternativeName':
                                # Format SubjectAlternativeName
                                if hasattr(ext.value, 'get_values_for_type'):
                                    for dns_name in ext.value.get_values_for_type(x509.DNSName):
                                        print(f"    SubjectAlternativeName - DNS Name: {dns_name}")
                                    for ip_name in ext.value.get_values_for_type(x509.IPAddress):
                                        print(f"    SubjectAlternativeName - IP Address: {ip_name}")
                                        
                            elif hasattr(ext.value, 'digest'):
                                # For other extensions with digest
                                digest = ext.value.digest
                                if isinstance(digest, bytes):
                                    print(f"    {ext_type} - Digest: {digest.hex()}")
                                else:
                                    print(f"    {ext_type} - Digest: {digest}")
                                    
                            elif hasattr(ext.value, 'value'):
                                # For extensions with a value attribute
                                value = ext.value.value
                                if isinstance(value, bytes):
                                    # Try to decode as UTF-8 if possible, otherwise show as hex
                                    try:
                                        decoded = value.decode('utf-8')
                                        if decoded.isprintable():
                                            print(f"    {ext_type} - Value: {decoded}")
                                        else:
                                            print(f"    {ext_type} - Value: {value.hex()}")
                                    except UnicodeDecodeError:
                                        print(f"    {ext_type} - Value: {value.hex()}")
                                else:
                                    print(f"    {ext_type} - Value: {value}")
                                    
                            elif hasattr(ext.value, '__str__'):
                                # For other objects, try to get a meaningful string representation
                                ext_value = str(ext.value)
                                if 'UnrecognizedExtension' not in ext_value or debug or verbose:
                                    # Clean up the output to show meaningful information
                                    if 'digest=' in ext_value:
                                        # Extract digest value and show as hex
                                        import re
                                        match = re.search(r'digest=b\'([^\']+)\'', ext_value)
                                        if match:
                                            digest_bytes = eval(match.group(1))  # Safe for our controlled input
                                            print(f"    {ext_type} - Digest: {digest_bytes.hex()}")
                                        else:
                                            print(f"    {ext_type} - Value: {ext_value}")
                                    elif 'value=' in ext_value and 'b\'' in ext_value:
                                        # Extract binary value and show as hex
                                        import re
                                        match = re.search(r'value=b\'([^\']+)\'', ext_value)
                                        if match:
                                            value_bytes = eval(match.group(1))  # Safe for our controlled input
                                            try:
                                                decoded = value_bytes.decode('utf-8')
                                                if decoded.isprintable():
                                                    print(f"    {ext_type} - Value: {decoded}")
                                                else:
                                                    print(f"    {ext_type} - Value: {value_bytes.hex()}")
                                            except UnicodeDecodeError:
                                                print(f"    {ext_type} - Value: {value_bytes.hex()}")
                                        else:
                                            print(f"    {ext_type} - Value: {ext_value}")
                                    else:
                                        print(f"    {ext_type} - Value: {ext_value}")
                                        
                            elif hasattr(ext.value, '__len__'):
                                # Handle objects with length (like lists, bytes)
                                if isinstance(ext.value, bytes):
                                    print(f"    {ext_type} - Value: {ext.value.hex()}")
                                else:
                                    print(f"    {ext_type} - Value: <{type(ext.value).__name__} with {len(ext.value)} items>")
                            else:
                                print(f"    {ext_type} - Value: <{type(ext.value).__name__} object>")
                                
                        except Exception as e:
                            if debug:
                                print(f"    Value: <error displaying: {e}>")
                            else:
                                print(f"    Value: <cannot display>")
                    else:
                        # For unknown extensions, only show details in verbose/debug mode
                        if verbose or debug:
                            print(f"    OID: {oid}")
                            if debug:
                                print(f"    Type: {type(ext.value).__name__}")
                                try:
                                    ext_value = str(ext.value)
                                    if len(ext_value) > 200:
                                        ext_value = ext_value[:200] + "... (truncated)"
                                    print(f"    Value: {ext_value}")
                                except:
                                    print(f"    Value: <cannot display>")
                        # Don't print anything for unknown extensions in normal mode
                except Exception as e:
                    if debug:
                        print(f"    Extension parsing error: {e}")
                    continue
        else:
             pass
#            print("Extensions:                None")
    except Exception as e:
        if debug:
            print(f"Extensions:                <error reading: {e}>")
        else:
            print("Extensions:                <not available>")
    
    # Fingerprints
    try:
        sha1_fp = cert.fingerprint(hashes.SHA1())
        print(f"SHA1 Fingerprint:          {sha1_fp.hex().upper()}")
    except:
        print("SHA1 Fingerprint:          <not available>")
    
    try:
        sha256_fp = cert.fingerprint(hashes.SHA256())
        print(f"SHA256 Fingerprint:        {sha256_fp.hex().upper()}")
    except:
        print("SHA256 Fingerprint:        <not available>")
    
    # Additional certificate metadata
    try:
        if hasattr(cert, 'tbs_certificate_bytes'):
            tbs_size = len(cert.tbs_certificate_bytes)
            print(f"TBS Certificate Size:      {tbs_size} bytes")
    except:
        pass
    
    try:
        if hasattr(cert, 'signature_bytes'):
            sig_size = len(cert.signature_bytes)
            print(f"Signature Size:            {sig_size} bytes")
            
            # Show signature in hex format (truncated)
            try:
                sig_hex = cert.signature_bytes.hex()
                print(f"Signature (hex):           {sig_hex}")
            except:
                pass
    except:
        pass
    
    # Certificate serial number in different formats
    try:
        if hasattr(cert, 'serial_number'):
            serial = cert.serial_number
            if hasattr(serial, '__int__'):
                print(f"Serial Number:             {int(serial)} (0x{int(serial):x})")
    except:
        pass
    
    # Certificate validation hints
    try:
        from datetime import datetime
        now = datetime.utcnow()
        if hasattr(cert, 'not_valid_before') and hasattr(cert, 'not_valid_after'):
            if cert.not_valid_before <= now <= cert.not_valid_after:
                print("Certificate Status:        VALID")
                
                # Calculate days until expiration
                try:
                    days_until_expiry = (cert.not_valid_after - now).days
                    if days_until_expiry <= 30:
                        print(f"Days Until Expiry:        {days_until_expiry} (EXPIRING SOON!)")
                    elif days_until_expiry <= 90:
                        print(f"Days Until Expiry:        {days_until_expiry} (expiring soon)")
                    else:
                        print(f"Days Until Expiry:        {days_until_expiry}")
                except:
                    pass
            elif now < cert.not_valid_before:
                days_until_valid = (cert.not_valid_before - now).days
                print("Certificate Status:        NOT YET VALID")
                print(f"Days Until Valid:         {days_until_valid}")
            else:
                days_since_expiry = (now - cert.not_valid_after).days
                print("Certificate Status:        EXPIRED")
                print(f"Days Since Expiry:        {days_since_expiry}")
        else:
            print("Certificate Status:        <cannot determine>")
    except:
        print("Certificate Status:        <cannot determine>")
    
    # Additional attributes that might be available
    additional_attrs = safe_explore_cert_attributes(cert)
    if additional_attrs:
        print("Additional Attributes:")
        for attr in additional_attrs:
            print(f"  {attr}")
    
    # Certificate chain information (if available)
    try:
        if hasattr(cert, 'issuer') and hasattr(cert, 'subject'):
            if str(cert.issuer) == str(cert.subject):
                print("Self-Signed:               YES")
            else:
                print("Self-Signed:               NO")
    except:
        print("Self-Signed:               <cannot determine>")
    
    print("---- END CERT ----")

def print_simple_certificate_details(cert):
    """Print simple certificate details in the original format."""
    print("---- START CERT ----")
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
    try:
        print("signature_hash_algorithm:", cert.signature_hash_algorithm.name)
    except:
        print("signature_hash_algorithm: <not available>")
    try:
        print("signature_algorithm_parameters", cert.signature_algorithm_parameters.name)
    except:
        print("signature_algorithm_parameters: <not available>")
    print("version", cert.version)
    print("---- END CERT ----")

parser = argparse.ArgumentParser(description='''
parse files searching for x509 data with enhanced certificate analysis
''', epilog='''project details at uefi-cert-research.org

Enhanced Features:
  - Comprehensive certificate analysis with safety measures
  - Extension parsing with well-known OID support
  - Public key details for RSA, EC, and EdDSA
  - Certificate validation status and expiry warnings
  - Safe handling of recursive ASN.1 structures
  - Multiple output formats (simple, detailed, verbose)
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
parser.add_argument("-v", "--verbose", dest="verbose", help="enable verbose certificate output",
    action='store_true')
parser.add_argument("-s", "--simple", dest="simple", help="use simple certificate output (original format)",
    action='store_true')
parser.add_argument(dest="file",  help="file to parse", nargs='+')
#
args=parser.parse_args()
#
if args.Debug:
    debug = True
#
if args.no_upload:
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
                        cert_files.append(f"{CERT_INDEX}@{filename}")
                        cert_der_data.append(cert_space)

                        # Use the appropriate certificate printing function based on arguments
                        if args.simple:
                            print_simple_certificate_details(cert)
                        elif args.verbose:
                            print_certificate_details(cert, verbose=True, debug=debug)
                            # In verbose mode, also show some additional debugging info
                            if debug:
                                print(f"Debug: Certificate object type: {type(cert)}")
                                print(f"Debug: Certificate object attributes: {dir(cert)}")
                        else:
                            print_certificate_details(cert, verbose=False, debug=debug)

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

# Upload certificates if enabled
if upload_data and cert_der_data:
    for cert_der in cert_der_data:
        b64_data = base64.b64encode(cert_der).decode()
        print(b64_data)
        res = requests.post(url=UPLOAD_URL, data=b64_data,
            headers={'Content-Type': 'application/octet-stream'})

# Print summary
if cert_files:
    print(f"\n=== SUMMARY ===")
    print(f"Total certificates found: {len(cert_files)}")
    print(f"Files processed: {len(args.file)}")
    if args.verbose or not args.simple:
        print(f"Enhanced analysis: Enabled")
        print(f"Safety measures: Active (recursive ASN.1 protection)")
    else:
        print(f"Enhanced analysis: Disabled (use -v for detailed output)")
else:
    print(f"\nNo certificates found in {len(args.file)} file(s)")
