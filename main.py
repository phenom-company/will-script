import argparse
from base import *
import settings

def create_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--init', action='store_true', help='init')
    parser.add_argument('-u', '--update_time', action='store_true',  help='update time')
    return parser

def main():
    parser = create_parser()
    args = parser.parse_args()
    will = Will(settings.PATH_TO_CONFIG, settings.PAHT_TO_MESSAGE, settings.SUPER_SECRET_KEY,
                settings.SUPER_SECRET_MESSAGE, settings.DELAY_FACTOR, settings.MAIL_USER, settings.MAIL_PASSWORD)
    if args.init:
        will.initialize()
    elif args.update_time:
        will.update_time()
    else:
        will.check_timeout()


if __name__ == '__main__':
    main()