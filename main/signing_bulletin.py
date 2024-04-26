import ast

with open('../ca_cert/bulletin.key', 'r') as f:
    bulletin_pr_key = f.read()

with open('../bulletin/candidates', 'r') as f:
    candidates_list = f.read()

candidates_dict = ast.literal_eval(candidates_list)
print('Candidates list:')
for key in candidates_dict:
    print(key, candidates_dict[key], sep=': ')


is_agree = bool(input('Are you sure that you want to sign this list? Enter any number if you are agree, else skip: '))
#if is_agree:
# add sign with password
