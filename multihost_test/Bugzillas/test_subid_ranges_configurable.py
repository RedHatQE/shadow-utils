"""
Shadow Utils Test Cases

:requirement: shadow-utils
:casecomponent: shadow-utils
:subsystemteam: sst_idm_sssd
:status: approved
"""

import pytest
import subprocess
import time
import os
from sssd.testlib.common.utils import SSHClient


def execute_cmd(multihost, command):
    """ execute cmd in client machine """
    cmd = multihost.client[0].run_command(command)
    return cmd


local_user = "local_anuj"
test_password = "Secret123"
subid_start = "165536"
subid_size = "65536"


@pytest.mark.usefixtures('compile_list_subid_ranges')
@pytest.mark.tier1
class TestSubid(object):
    """
    This is for Shadow bugs automation
    """

    @pytest.mark.parametrize("subid_db",
                             ["",
                              "subid: files",
                              "subid: unexisting"],)
    def test_subid(self, multihost,
                   create_backup,
                   create_localuser,
                   subid_db):
        """
        :Title: support pluggable data sources for
         subid ranges configurable via /etc/nsswitch.conf
        :Customerscenario: true
        :id: 6ff93666-00c0-11ec-9be4-845cf3eff344
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1859252
        :steps:
            1. Define user range in /etc/subuid
            2. Define group range in /etc/subgid
            3. Create a process for user
            4. Check newuidmap command is working
            with value of subid_db in /etc/nsswitch.conf
            5. Check newgidmap command is working
            with value of subid_db in /etc/nsswitch.conf
        :expectedresults:
            1. Should succeed
            2. Should succeed
            3. Should succeed
            4. Should succeed
            5. Should succeed
        """
        execute_cmd(multihost,
                    f"echo '{local_user}:{subid_start}:{subid_size}'"
                    f"  > /etc/subuid")
        execute_cmd(multihost,
                    f"echo '{local_user}:{subid_start}:{subid_size}'"
                    f"  > /etc/subgid")
        if subid_db != "":
            execute_cmd(multihost,
                        f"echo {subid_db} >> "
                        f"/etc/nsswitch.conf")
        ssh1 = SSHClient(multihost.client[0].sys_hostname,
                         username=local_user,
                         password=test_password)
        (results1, results2, results3) = ssh1.exec_command('unshare -U bash')
        # ps is returning only partial part of user
        # local_a+ 10131 10105 0 08:30 ? 00:00:00 bash
        # test looks for a most recent 'bash' process
        # started by user local_*
        time.sleep(3)
        find_id = "ps -ef | grep bash | grep local_| tail -1"
        proces_id = [int(word)
                     for word in execute_cmd(multihost,
                                             find_id).stdout_text.split()
                     if word.isdigit()][0]
        ssh1.exec_command(f"newuidmap {proces_id} "
                          f"{subid_start}  "
                          f"{int(subid_start)+1} 1")
        ssh1.exec_command(f"newgidmap {proces_id} "
                          f"{subid_start} "
                          f"{int(subid_start)+1} 1")
        result = execute_cmd(multihost, f"cat /proc/{proces_id}/uid_map")
        assert subid_start in result.stdout_text
        assert str(int(subid_start)+1) in result.stdout_text
        result = execute_cmd(multihost, f"cat /proc/{proces_id}/gid_map")
        assert subid_start in result.stdout_text
        assert str(int(subid_start)+1) in result.stdout_text
        execute_cmd(multihost, f'kill -9 {proces_id}')
        ssh1.close()

    @pytest.mark.parametrize("subid_db",
                             ["",
                              "subid: files",
                              "subid: unexisting"],)
    def test_list_subid_ranges(self, multihost,
                               create_backup,
                               create_localuser,
                               subid_db):
        """
        :Title: support pluggable data sources for
         subid ranges configurable via /etc/nsswitch.conf
        :Customerscenario: true
        :id: 496e0142-00c1-11ec-8cb7-845cf3eff344
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1859252
        :steps:
            1. Define user range in /etc/subuid
            2. Define group range in /etc/subgid
            3. Create a process for user
            4. Check list_subid_ranges command is working
            with value of subid_db in /etc/nsswitch.conf
            5. Check list_subid_ranges -g command is working
            with value of subid_db in /etc/nsswitch.conf
        :expectedresults:
            1. Should succeed
            2. Should succeed
            3. Should succeed
            4. Should succeed
            5. Should succeed
        """
        execute_cmd(multihost, f"echo '{local_user}:{subid_start}:{subid_size}'"
                               " > /etc/subuid")
        execute_cmd(multihost, f"echo '{local_user}:{subid_start}:{subid_size}'"
                               " > /etc/subgid")
        if subid_db != "":
            execute_cmd(multihost, f"echo {subid_db} >>"
                                   f" /etc/nsswitch.conf")
        cmd = execute_cmd(multihost, "cd /tmp/; "
                                     "./list_subid_ranges "
                                     "local_anuj")
        assert f'{local_user} {subid_start} {subid_size}' in cmd.stdout_text
        cmd = execute_cmd(multihost, "cd /tmp/; "
                                     "./list_subid_ranges"
                                     " -g local_anuj")
        assert f'{local_user} {subid_start} {subid_size}' in cmd.stdout_text
