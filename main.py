import ets.ets_certmanager_logs_parser as cert_mngr
import ets.ets_certificate_lib as cert_lib
from ets.ets_ssh_connector import SSHConnection as Ssh
from datetime import datetime
from os.path import join, normpath
from config_parser import *
import argparse
import logger_module

PROGNAME = 'Certificate checker'
DESCRIPTION = '''Скрипт для проверки сертификатов'''
VERSION = '1.0'
AUTHOR = 'Belim S.'
RELEASE_DATE = '2018-02-07'

CERTIFICATE_VERSION = 0
NOW = datetime.now()

crl_file_local = normpath(join(local_dir, crl_file))
mca_file_local = normpath(join(local_dir, mca_file))
mroot_file_local = normpath(join(local_dir, mroot_file))

crl_file_remote = normpath(join(remote_dir, crl_file))
mca_file_remote = normpath(join(remote_dir, mca_file))
mroot_file_remote = normpath(join(remote_dir, mroot_file))

connections = {1: Ssh.CONNECT_CRYPTO_1,
               2: Ssh.CONNECT_CRYPTO_2,
               3: Ssh.CONNECT_CRYPTO_3,
               4: Ssh.CONNECT_CRYPTO_4,
               5: Ssh.CONNECT_CRYPTO_5}


def show_version():
    print(PROGNAME, VERSION, '\n', DESCRIPTION, '\nAuthor:', AUTHOR, '\nRelease date:', RELEASE_DATE)


# обработчик параметров командной строки
def create_parser():
    parser = argparse.ArgumentParser(description=DESCRIPTION)

    parser.add_argument('-v', '--version', action='store_true',
                        help="Show version")

    parser.add_argument('-s', '--server', type=int,
                        help="Set server number")

    parser.add_argument('-f', '--file', type=str,
                        help="Set certificate file")

    return parser


def update_files(server_num):
    """Функция получения файлов данных с крипто-сервера server_num"""
    print('Обновление файлов данных с криптосервера %s...' % server_num)
    server_connection = connections[server_num]
    connect = Ssh(connection=server_connection, connection_type='key')

    with connect.open_ssh():
        connect.exec_command('/opt/cprocsp/bin/amd64/certmgr -list -store mRoot > %s' % mroot_file_remote)
        connect.exec_command('/opt/cprocsp/bin/amd64/certmgr -list -store mCA > %s' % mca_file_remote)
        connect.exec_command('/opt/cprocsp/bin/amd64/certmgr -list -store mCA -crl > %s' % crl_file_remote)

        connect.get_file(mroot_file_remote, mroot_file_local)
        connect.get_file(mca_file_remote, mca_file_local)
        connect.get_file(crl_file_remote, crl_file_local)

    print('Файлы данных обновлены')


def check_cert(certificate):
    """Функция проверки сертификата"""
    global CERTIFICATE_VERSION

    CERTIFICATE_VERSION += 1
    # обрабатываем пользовательский сертификат
    user_certificate = cert_lib.Certificate(certificate)

    # получаем данные об subjectKey
    user_certificate_subject_key = user_certificate.get_subject_key_identifier()
    user_certificate_serial = user_certificate.get_sertificate_serial()
    print('\n=================== Checking certificate %s ===================' % CERTIFICATE_VERSION)
    print('SERIAL_N:', user_certificate_serial)
    if not user_certificate_subject_key:
        user_certificate_subject_key = 'UNKNOWN'
    print('SUBJ_KEY:', user_certificate_subject_key)

    # получаем состояние отозванности по всем точкам
    web_revoke_status = user_certificate.check_web_revoke_status(user_certificate_serial, info=True)

    # получаем дату последнего изменения на сервере по всем точкам
    web_crl_last_modified = user_certificate.check_web_crl_last_modified(user_certificate_serial)

    # получаем файл корневого к указанному
    root_cert_link, error = user_certificate.get_root_certificate_file()

    # проверять на установку в mca и mroot нужно все КРОМЕ пользовательского (первого)
    if CERTIFICATE_VERSION > 1:
        mca_certificate_text_info = mca_certificate_mngr_file.get_text_info(user_certificate_subject_key,
                                                                            key='SubjKeyID')

        if mca_certificate_text_info:
            print("mCA: установлен")
            print(mca_certificate_text_info)
        else:
            print("mCA: отсутствует")

        mroot_certificate_text_info = mroot_certificate_mngr_file.get_text_info(user_certificate_subject_key,
                                                                                key='SubjKeyID')

        if mroot_certificate_text_info:
            print("mRoot: установлен\n")
            print(mroot_certificate_text_info)
        else:
            print("mRoot: отсутствует\n")

    # для кажлой точки распространения проверяем
    for web_crl_num in range(len(user_certificate.get_crl_distribution_points())):
        user_web_crl_num = web_crl_num + 1
        last_modified_info, last_modified_error = web_crl_last_modified[web_crl_num]
        if not last_modified_error:
            last_modified_date = last_modified_info
        else:
            last_modified_date = 'дата не определена'

        status_info_dict, error_info_dict = web_revoke_status[web_crl_num]
        if not error_info_dict:
            if status_info_dict:
                print(
                    'CRL (WEB_%s от %s): cертификат %s отозван %s (%s)' % (user_web_crl_num,
                                                                           last_modified_date,
                                                                           user_certificate_serial,
                                                                           status_info_dict['revoke_date'],
                                                                           status_info_dict['reason']))
            else:
                print('CRL (WEB_%s от %s): не числится в списке отозванных' % (user_web_crl_num, last_modified_date))
        else:
            print('CRL (WEB_%s): невозможно проверить наличие в списке отозванных' % user_web_crl_num)

    # проверять наличие CRL в mca нужно для всех, КРОМЕ пользовательского (первого)
    if CERTIFICATE_VERSION > 1:
        # проверим CRL на площадке (по дате действия)
        crl_certificate_data = crl_certificate_mngr_file.get_info(user_certificate_subject_key, key='AuthKeyID')
        if crl_certificate_data:
            this_update = crl_certificate_data['ThisUpdate']
            next_update = crl_certificate_data['NextUpdate']

            if not this_update <= NOW <= next_update:
                print('CRL (mCA): установлен, действует с %s по %s (НЕ АКТУАЛЕН)' % (this_update, next_update))
            else:
                print('CRL (mCA): установлен, действует с %s по %s' % (this_update, next_update))

        else:
            print('CRL (mCA): не установлен')

    if root_cert_link:
        print("Проверка корневого сертификата...")
        check_cert(root_cert_link)
    else:
        print("Корневой не требуется (не указан)")

# ОСНОВНОЙ КОД
if __name__ == '__main__':

    logger = logger_module.logger()
    try:
        # парсим аргументы командной строки
        my_parser = create_parser()
        namespace = my_parser.parse_args()

        if namespace.version:
            show_version()
            exit(0)

        if namespace.server:
            if namespace.server not in connections.keys():
                print('Параметр server должен быть одним из значений: %s' % connections.keys())

            update_files(namespace.server)

        if namespace.file:

            mca_certificate_mngr_file = cert_mngr.CertmanagerFile(mca_file_local, timezone=timezone)
            mroot_certificate_mngr_file = cert_mngr.CertmanagerFile(mroot_file_local, timezone=timezone)
            crl_certificate_mngr_file = cert_mngr.CertmanagerFile(crl_file_local, timezone=timezone)

            print('Checking started %s' % NOW)
            check_cert(namespace.file)
            print('--------------------------------------------\nChecking finished %s' % datetime.now())

        else:
            show_version()
            print('For more information run use --help')
    # если при исполнении будут исключения - кратко выводим на терминал, остальное - в лог
    except Exception as e:
        logger.fatal('Fatal error! Exit', exc_info=True)
        print('Critical error: %s' % e)
        print('More information in log file')
        exit(1)

    exit(0)












