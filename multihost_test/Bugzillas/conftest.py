"""conftest.py for Shadow-utils"""

from __future__ import print_function
import subprocess
import pytest
import os
import time
import ldap
import random
from pytest_multihost import make_multihost_fixture
from sssd.testlib.common.qe_class import session_multihost
from sssd.testlib.common.paths import SSSD_DEFAULT_CONF
from sssd.testlib.ipa.utils import ipaTools
from sssd.testlib.common.utils import PkiTools, sssdTools, LdapOperations
from sssd.testlib.common.libdirsrv import DirSrvWrap
from sssd.testlib.common.exceptions import PkiLibException, LdapException
from sssd.testlib.common.libkrb5 import krb5srv


def pytest_configure():
    """ Namespace hook to add below dict in the pytest namespace """
    pytest.num_masters = 0
    pytest.num_ad = 0
    pytest.num_atomic = 0
    pytest.num_replicas = 0
    pytest.num_clients = 1
    pytest.num_others = 0


def execute_cmd(session_multihost, command):
    cmd = session_multihost.client[0].run_command(command)
    return cmd


@pytest.fixture(scope="class")
def multihost(session_multihost, request):
    """ Multihost fixture to be used by tests """
    if hasattr(request.cls(), 'class_setup'):
        request.cls().class_setup(session_multihost)
        request.addfinalizer(
            lambda: request.cls().class_teardown(session_multihost))
    return session_multihost


@pytest.fixture(scope='function')
def backupsssdconf(session_multihost, request):
    """ Backup and restore sssd.conf """
    bkup = 'cp -f %s %s.orig' % (SSSD_DEFAULT_CONF,
                                 SSSD_DEFAULT_CONF)
    session_multihost.client[0].run_command(bkup)
    session_multihost.client[0].service_sssd('stop')

    def restoresssdconf():
        """ Restore sssd.conf """
        restore = 'cp -f %s.orig %s' % (SSSD_DEFAULT_CONF, SSSD_DEFAULT_CONF)
        session_multihost.client[0].run_command(restore)
    request.addfinalizer(restoresssdconf)


@pytest.fixture(scope='class')
def compile_list_subid_ranges(session_multihost, request):
    """
    Compile list_subid_ranges.c file And install
    necessary packages
    """
    session_multihost.client[0].run_command("yum "
                                            "--enablerepo=*-CRB install"
                                            " -y shadow-utils*")
    session_multihost.client[0].run_command("yum "
                                            "install -y "
                                            "shadow-utils-*")
    session_multihost.client[0].run_command("yum "
                                            "install -y gcc")

    file_location = "/multihost_test/Bugzillas/data/list_subid_ranges.c"
    session_multihost.client[0].transport.put_file(os.getcwd() +
                                                   file_location,
                                                   '/tmp/list_subid_ranges.c')
    session_multihost.client[0].run_command("gcc /tmp/list_subid_ranges.c "
                                            "-lsubid -o  /tmp/list_subid_ranges")

    def remove():
        """ Remove file """
        session_multihost.client[0].run_command("rm -vf /tmp/list_subid_ranges")

    request.addfinalizer(remove)


@pytest.fixture(scope='function')
def create_backup(session_multihost, request):
    """ Create backup for necessary files used in test """
    user = "local_anuj"
    for place in ['subuid', 'subgid']:
        with pytest.raises(subprocess.CalledProcessError):
            session_multihost.client[0].run_command(f"grep {user} "
                                                    f"/etc/{place}")
    with pytest.raises(subprocess.CalledProcessError):
        session_multihost.client[0].run_command(f"grep subid "
                                                f"/etc/nsswitch.conf")
    for f_file in ['subuid',
                   'subgid',
                   'nsswitch.conf',
                   'shadow',
                   'group',
                   'gshadow',
                   'passwd']:
        session_multihost.client[0].run_command(f"cp -vf  "
                                                f"/etc/{f_file} "
                                                f"/tmp/{f_file}_bkp")

    def restore():
        """ Restore files """
        for f_file in ['subuid',
                       'subgid',
                       'nsswitch.conf',
                       'shadow',
                       'group',
                       'gshadow',
                       'passwd']:
            session_multihost.client[0].run_command(f"mv -vf  "
                                                    f"/tmp/{f_file}_bkp "
                                                    f"/etc/{f_file}")
    request.addfinalizer(restore)


@pytest.fixture(scope='function')
def create_localuser(session_multihost, request):
    """ Create local users """
    user = "local_anuj"
    password = "Secret123"
    session_multihost.client[0].run_command(f"useradd {user}")
    passwd_cmd = f'passwd --stdin {user}'
    session_multihost.client[0].run_command(passwd_cmd,
                                            stdin_text=password,
                                            raiseonerr=False)

    def delusers():
        """ Delete local users """
        session_multihost.client[0].run_command(f"userdel -rf {user}")
    request.addfinalizer(delusers)


@pytest.fixture(scope="session", autouse=True)
def setup_session(session_multihost, request):
    """
    Session fixture which calls fixture in order before tests run
    :param obj session_multihost: multihost object
    :param obj request: pytest request object
    """
    execute_cmd(session_multihost, "yum update -y shadow-utils")
    execute_cmd(session_multihost, 'yum install -y expect')
    #execute_cmd(session_multihost, 'yum install -y libeconf*')
    execute_cmd(session_multihost, "dnf --enablerepo=resilientstorage install gfs2-utils")
    #execute_cmd(session_multihost, "yum install -y gfs2-utils")
