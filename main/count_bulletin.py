#remove randomness
bulletin_num = decrypt_data(bulletin_num_enc, priv_key)[:-3]
#
bulletin_list = parse_bulletin(bulletin_num, list(cand_list.values()))
print(bulletin_list)