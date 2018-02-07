from ets.ets_small_config_parser import ConfigParser as Parser
from inspect import getsourcefile
from os.path import dirname, normpath
from os import chdir

PATH = normpath(dirname(getsourcefile(lambda: 0)))
chdir(PATH)

CONFIG_FILE = 'certificate_checker.conf'


config = Parser(config_file=CONFIG_FILE)

timezone = config.get_option('main', 'timezone')

local_dir = config.get_option('main', 'local_dir', string=True)
remote_dir = config.get_option('main', 'remote_dir', string=True)

crl_file = config.get_option('main', 'crl_file', string=True)
mca_file = config.get_option('main', 'mca_file', string=True)
mroot_file = config.get_option('main', 'mroot_file', string=True)

log_file = config.get_option('main', 'log', string=True)

