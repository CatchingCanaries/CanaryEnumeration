import base64
import binascii

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# Multiple posts on pastebin / twitter
CanaryVendorAccountIDs = (
    '171436882533',
    '717712589309',
    '534261010715',
    '597260573541',
    '052310077262'
)

# Single post on pastebin / twitter
PasteBinCanaryAccountIDs = (
    '682442579669',
    '581039954779',
    '967948378280',
    '985010860775',
    '518862968171',
    '962171338105',
    '593069397380',
    '655538803783',
    '595918472158',
    '757406278445'
)

def AWSAccount_from_AWSKeyID(AWSKeyID):
    trimmed_AWSKeyID = AWSKeyID[4:]  # remove KeyID prefix
    x = base64.b32decode(trimmed_AWSKeyID)  # base32 decode
    y = x[0:6]

    z = int.from_bytes(y, byteorder='big', signed=False)
    mask = int.from_bytes(binascii.unhexlify(b'7fffffffff80'), byteorder='big', signed=False)

    e = (z & mask) >> 7
    return e

aws_access_key_id = input(bcolors.WARNING + "\n\n\nEnter the AWS Access Key ID from the potential canary:\n" + bcolors.ENDC)

AccountID = "{:012d}".format(AWSAccount_from_AWSKeyID(aws_access_key_id))

if AccountID in CanaryVendorAccountIDs:
    print(bcolors.FAIL + "\n##### AWS Keys Canary Detected! #####\n" + bcolors.WARNING + "AccountID " + AccountID + " belongs to a " + bcolors.FAIL + "canary provider.\n\n\n" + bcolors.ENDC)
elif AccountID in PasteBinCanaryAccountIDs:
    print(bcolors.FAIL + "\n##### AWS Keys Canary Detected! #####\n" + bcolors.WARNING + "AccountID " + AccountID + " was found on " + bcolors.FAIL + "Pastebin.\n\n\n" + bcolors.ENDC)
else:
    print(bcolors.OKGREEN + "\nAccountID " + AccountID + " is unique.\n" + bcolors.WARNING + "Likely not a deception canary.\n\n\n" + bcolors.ENDC)