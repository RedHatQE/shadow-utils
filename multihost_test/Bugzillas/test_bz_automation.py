
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

    def test_bz672510(self, multihost):
        """
        :title: Checks if newgrp command works properly
         for password protected groups
        :id: f2bb9b8e-39a9-11ed-88a4-845cf3eff344
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=672510
        :steps:
          1. newgrp works for password protected group with correct password
          2. Adding password to group
          3. Trying good password with newgrp
          4. newgrp doesn't work for password protected group with incorrect password
          5. newgrp doesn't work for non existing group
          6. newgrp doesn't work for not password protected group for non-member
          7. newgrp works for not password protected group for member
        :expectedresults:
          1. Should succeed
          2. Should succeed
          3. Should succeed
          4. Should succeed
          5. Should succeed
          6. Should succeed
          7. Should succeed
        """
        tgroup = "tgroup00011"
        tuser = "tuser1"
        tuser2 = "tuser2"
        file_location = "/multihost_test/Bugzillas/data/"
        for file in ['bz672510_1.sh',
                     'bz672510_2.sh',
                     'bz672510_3.sh']:
            multihost.client[0].transport.put_file(os.getcwd()+
                                                   f'/{file_location}{file}',
                                                   f'/tmp/{file}')
            execute_cmd(multihost, f"chmod 755 /tmp/{file}")
        # newgrp works for password protected group with correct password
        execute_cmd(multihost, f"useradd {tuser}")
        execute_cmd(multihost, f"groupadd {tgroup}")
        # Adding password to group
        execute_cmd(multihost, f"sh /tmp/bz672510_1.sh {tgroup} {tgroup}")
        # Trying good password with newgrp
        execute_cmd(multihost, f"sh /tmp/bz672510_2.sh {tuser} {tgroup} {tgroup}")
        # newgrp doesn't work for password protected group with incorrect password
        with pytest.raises(subprocess.CalledProcessError):
            execute_cmd(multihost, f"sh /tmp/bz672510_2.sh {tuser} {tgroup} badpass")
        # newgrp doesn't work for non existing group
        with pytest.raises(subprocess.CalledProcessError):
            execute_cmd(multihost, f"sh /tmp/bz672510_2.sh {tuser} badgroup badpass")
        # newgrp doesn't work for not password protected group for non-member
        execute_cmd(multihost, f'gpasswd -r {tgroup}')
        # Trying good password with newgrp for non-member
        with pytest.raises(subprocess.CalledProcessError):
            execute_cmd(multihost, f"sh /tmp/bz672510_2.sh {tuser} {tgroup} {tgroup}")
        # newgrp works for not password protected group for member
        execute_cmd(multihost, f"gpasswd -M {tuser} {tgroup}")
        # Trying no password with newgrp for group member
        execute_cmd(multihost, f"sh /tmp/bz672510_3.sh {tuser} {tgroup}")
        execute_cmd(multihost, f"userdel -rf {tuser}")
        execute_cmd(multihost, f"groupdel  {tgroup}")

    def test_bz787736(self, multihost, create_backup):
        """
        :title: bz787736-pwconv-grpconv-skips-2nd-of-consecutive-failures
        :id: 017f615a-92a8-11eb-bca1-002b677efe14
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=787736
        :steps:
          1. If /etc/shadow (or /etc/gshadow) contains consecutive
           bad lines pwconv only fixes the first, skipping the 2nd.
        :expectedresults:
          1. Should not succeed
        """
        execute_cmd(multihost, "echo 'example1:!!:15372:0:99999:7:::' >> /etc/shadow")
        execute_cmd(multihost, "echo 'example2:!!:15372:0:99999:7:::' >> /etc/shadow")
        # pwck first try should end with 2
        # 2 means error in one or more bad password entries
        with pytest.raises(subprocess.CalledProcessError):
            execute_cmd(multihost, "pwck -r > /tmp/anuj")
        assert "no matching password file entry in /etc/passwd" in \
               execute_cmd(multihost, "cat /tmp/anuj").stdout_text
        execute_cmd(multihost, "pwconv")
        with pytest.raises(subprocess.CalledProcessError):
            execute_cmd(multihost, "pwck -r > /tmp/anuj")
        assert "no matching password file entry" not in \
               execute_cmd(multihost, "cat /tmp/anuj").stdout_text
