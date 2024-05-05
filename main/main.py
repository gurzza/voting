from server import *
from counter import *
from signing_bulletin import *

if __name__ == '__main__':
    # signing bulletin
    print('______________________________FOR SIGNER SIDE______________________________________')
    is_signed = signer_job()
    print('___________________________________________________________________________________\n')
    if is_signed:
        # do all server-side work: get votes from voters and add to DB
        print('_________________________THE VOTING HAS STARTED____________________________________')
        try:
            server_job()
        except psycopg2.InterfaceError:
            pass
        print('___________________________THE VOTING IS OVER______________________________________\n')
        # count votes
        print('________________________IT\'S TIME TO COUNT VOTES__________________________________')
        counter_job()
