import ast
import json
import os

from Crypto.PublicKey import RSA
from common_functions import *

with open('../ca_cert/bulletin.key', 'r') as f:
    bulletin_pr_key = f.read()

with open('../ca_cert/bulletin.cer', 'r') as f:
    bulletin_pub_key = f.read()

with open('../bulletin/candidates', 'r') as f:
    candidates_list = f.read()

candidates_dict = ast.literal_eval(candidates_list)
print('Candidates list:')
for key in candidates_dict:
    print(key, candidates_dict[key], sep=': ')


is_agree = bool(input('Are you sure that you want to sign this list? Enter any number if you are agree, else skip: '))
if is_agree:
    candidates_json_s = json.dumps(candidates_dict)
    #print(type(candidates_json_s))
    #print(candidates_list)
    s = sign_data(candidates_json_s, bulletin_pr_key, with_password=True)
    with open('../bulletin/candidates_signed', 'wb') as f:
        f.write(s)
    print(verify_sign(candidates_json_s, s, bulletin_pub_key))

else:
    print('Something wrong with list of candidates!')
    os.remove('../bulletin/candidates_signed')

