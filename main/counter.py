import ast
import json

import pyrankvote
from pyrankvote import *

from common_functions import *


def fetch_enc_votes_and_signature(db_conn, db_cur):
    db_cur.execute(
        '''
            SELECT vote FROM enc_votes
        '''
    )
    enc_votes = db_cur.fetchall()

    db_cur.execute(
        '''
            SELECT signature FROM enc_votes
        '''
    )
    signatures = db_cur.fetchall()
    return enc_votes, signatures


def parse_bulletin(bulletin_num_list, cand_names):
    """
    input (one of many votes): pos in original list +1, 00; pos in original list +1, 00; ...
    """

    bulletins = []
    for bulletin_num in bulletin_num_list:
        bulletin_list = []
        curr_pos = 0
        try:
            while curr_pos < len(bulletin_num):
                # FIXME: bad idea if amount of candidates >= 10
                # pos_in_bulletin_length: the length of the number that represents candidate position in bulletin
                # ex: for 10 length 2
                pos_b_length = bulletin_num.find('00', curr_pos) - curr_pos
                if pos_b_length == -1:  # if '00' wasn't found
                    raise Exception('Log: INCORRECT BULLETIN FORMAT! Skip this bulletin...')
                cand_int = int(bulletin_num[curr_pos: curr_pos + pos_b_length])
                bulletin_list.append(cand_names[cand_int - 1])
                curr_pos += pos_b_length + 2  # +2 from len('00')
            bulletins.append(bulletin_list)
        except Exception as e:
            print(e.args[0])

    return bulletins


def create_candidates(cand_list):
    """
    Create type 'Candidate' to use library pyrankvote
    :param cand_list: list of all candidates
    :return: list of 'Candidates'
    """
    cand_list_names = list(cand_list.values())

    cand_lib = []
    for name in cand_list_names:
        cand = Candidate(name)
        cand_lib.append(cand)

    return cand_lib


def make_bulletin_lib(bulletin: list, cand_lib: list):
    """
    match the vote as list of strings to vote as list of candidates from library
    :param bulletin: one bulletin
    :param cand_lib: list of candidates from library
    :return:
    """
    # bulletin_lib = []
    # for el in bulletin:
    #     for cand in cand_lib:
    #         if el == cand.name:
    #             bulletin_lib.append(cand)
    #             break
    # return bulletin_lib
    bulletin_lib = []
    cands_name = [cand.name for cand in cand_lib]
    for el in bulletin:
        if el in cands_name:
            for cand in cand_lib:
                if el == cand.name:
                    bulletin_lib.append(cand)
                    cands_name.remove(el)
                    break
        else:
            print('Log: INCORRECT VOTE! DATA DUPLICATION OR UNEXPECTED CANDIDATE!')
            return
    # if everything OK
    return bulletin_lib


def counter_job():
    with open('../ca_cert/counter.key', 'r') as f:
        priv_key_counter = f.read()
    with open('../ca_cert/server.cer', 'r') as f:
        server_pub_key = f.read()

    # fetch encrypted votes from DB
    db_conn, db_cur = connect_to_db()
    enc_votes, signatures = fetch_enc_votes_and_signature(db_conn, db_cur)
    close_connection_to_db(db_conn, db_cur)
    # verify signatures
    ver_enc_votes = verify_sign_list(enc_votes, signatures, server_pub_key)
    if ver_enc_votes is None:
        print('Log: All votes weer substituted')
        return
    # decrypt votes
    bulletins_num = decrypt_data_list(enc_votes, priv_key_counter)
    with open("../bulletin/candidates", 'r') as f:
        # ast.literal_eval: str -> dict
        cand_list = ast.literal_eval(f.read())

    # bulletins - clear votes
    bulletins = parse_bulletin(bulletins_num, list(cand_list.values()))
    if not bulletins:  # in case when all bulletins are incorrect
        print('Log: ALL VOTES WERE INCORRECT OR CORRUPTED!')
        return

    # create 'Candidates'
    cand_lib = create_candidates(cand_list)
    bulletins_lib = []
    for bulletin in bulletins:
        one_bulletin_lib = make_bulletin_lib(bulletin, cand_lib)
        if one_bulletin_lib:
            bulletins_lib.append(Ballot(ranked_candidates=one_bulletin_lib))

    # election_result = instant_runoff_voting(cand_lib, bulletins_lib)
    # winners = election_result.get_winners()
    # print(election_result)

    election_result = pyrankvote.single_transferable_vote(
        cand_lib, bulletins_lib, number_of_seats=2
    )

    print(election_result)


if __name__ == "__main__":
    counter_job()
