
import pytest
import subprocess
import os
import time


def execute_cmd(multihost, command):
    cmd = multihost.client[0].run_command(command)
    return cmd


@pytest.mark.tier1
class TestShadowBz(object):
    def test_segmentation(self, multihost):
        """
        :title: Groupdel gives segmentation fault when using '-P'
        :id: f86daef6-540c-11ec-a7c2-845cf3eff344
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1986782
                   https://bugzilla.redhat.com/show_bug.cgi?id=2024834
        """
        for i in ["mkdir -p $HOME/custom_root/etc/",
                  "touch $HOME/custom_root/etc/group",
                  "groupadd -P $HOME/custom_root test_group",
                  "groupdel -P $HOME/custom_root test_group",
                  "rm -vfr $HOME/custom_root/etc/"]:
            execute_cmd(multihost, i)

    def test_crashes(self, multihost):
        """
        :title: Useradd crashes with --prefix
        :id: 348894f6-5416-11ec-b822-845cf3eff344
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=2020238
        """
        execute_cmd(multihost, "rm -fr /tmp/newroot "
                               "&& mkdir -p /tmp/newroot/etc"
                               " && cp -at /tmp/newroot/etc "
                               "/etc/{passwd,group,"
                               "sub[ug]id,gshadow,shadow,"
                               "login.defs,default} ")
        multihost.client[0].run_command("useradd --prefix /tmp/newroot "
                                        "--groups=wheel --create-home "
                                        "--password= test_user",
                                        raiseonerr=False)
        assert "/home/test_user:" \
               "/bin/bash" in \
               execute_cmd(multihost,
                           "grep test_user "
                           "/tmp/newroot/etc/passwd").stdout_text
        execute_cmd(multihost, "rm -fr /tmp/newroot")

    def test_2093311(self, multihost, create_backup, create_localuser):
        """
        :title: sub*id files can also contain IDs
        :id: 80471586-122d-11ed-8890-845cf3eff344
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=2093311
                   https://bugzilla.redhat.com/show_bug.cgi?id=2109410
        """
        execute_cmd(multihost, "yum install -y  podman")
        user_uid = execute_cmd(multihost, "id local_anuj").stdout_text.split(" ")[0].split('(')[0].split("=")[1]
        execute_cmd(multihost, f"sed -i -e 's/local_anuj/{user_uid}/g' /etc/subuid")
        execute_cmd(multihost, f"sed -i -e 's/local_anuj/{user_uid}/g' /etc/subgid")
        result = execute_cmd(multihost, 'su - local_anuj -c "podman run fedora cat /proc/self/uid_map"').stdout_text
        for i in execute_cmd(multihost, f"grep {user_uid} /etc/subuid").stdout_text[:-1].split(":"):
            assert i in result.split()
