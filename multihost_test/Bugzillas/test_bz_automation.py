
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
        for file in ['add_passwod_to_group.sh',
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
        execute_cmd(multihost, f"sh /tmp/add_passwod_to_group.sh {tgroup} {tgroup}")
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
        :id: 827afc78-4e23-11ed-b914-845cf3eff344
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

    def test_bz_667593(self, multihost):
        """
        :title: Shadow-Utils: sg works with password
         protected group with correct password
        :id: 8e5d5324-4e23-11ed-95b7-845cf3eff344
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=667593
        :steps:
          1. Add user
          2. Add group
          3. Add password to group
          4. Try good password with sg
        :expectedresults:
          1. Should succeed
          2. Should succeed
          3. Should succeed
          4. Should succeed
        """
        # Adding user
        execute_cmd(multihost, "useradd  tuser0011")
        # Adding group
        execute_cmd(multihost, "groupadd tgroup00011")
        # script
        file_location = "/multihost_test/Bugzillas/data/"
        for file in [f'bz_667593_1.sh',
                     f'bz_667593_4.sh',
                     f'add_passwod_to_group.sh']:
            multihost.client[0].transport.put_file(os.getcwd()+f'/{file_location}{file}', f'/tmp/{file}')
            execute_cmd(multihost, f"chmod 755 /tmp/{file}")
        # Adding password to group
        execute_cmd(multihost, "sh /tmp/add_passwod_to_group.sh tgroup00011 Secret123")
        # Trying good password with sg
        cmd = execute_cmd(multihost, "sh /tmp/bz_667593_1.sh tuser0011 Secret123")
        for data_1 in ['tgroup00011', 'groups=', 'tuser0011', 'logout']:
            assert data_1 in cmd.stdout_text
        # Try Bad password with sg
        # Should not succeed
        with pytest.raises(subprocess.CalledProcessError):
            execute_cmd(multihost, "sh /tmp/bz_667593_1.sh tgroup00011 Badpass")
        # Remove password from Group
        execute_cmd(multihost, "gpasswd -r tgroup00011")
        # Trying bad password with sg
        with pytest.raises(subprocess.CalledProcessError):
            execute_cmd(multihost, "sh /tmp/bz_667593_1.sh ")
        # Add user to members of group
        execute_cmd(multihost, "gpasswd -M tuser0011 tgroup00011")
        # Trying no password with sg
        cmd = execute_cmd(multihost, "sh /tmp/bz_667593_4.sh")
        execute_cmd(multihost, "groupdel tgroup00011")
        execute_cmd(multihost, "pkill -U tuser0011 && sleep 5 || :")
        execute_cmd(multihost, "userdel -r tuser0011")
        execute_cmd(multihost, "rm -vf /tmp/bz_667593*")
        for data_1 in ['tgroup00011', 'groups=', 'tuser0011', 'logout']:
            assert data_1 in cmd.stdout_text

    def test_bz_2012929(self, multihost, create_backup):
        """
        :title: Pre allocated subordinate user/group IDs don't get honored
        :id: 1aee5474-c7a9-11ed-9638-845cf3eff344
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=2012929
        :steps:
          1. Manually manage the sub[ug]id ranges
          2. Add User
          3. Check /etc/subuid
        :expectedresults:
          1. Should succeed
          2. Should succeed
          3. Useradd honors the predefined values in /etc/subuid,
            /etc/subgid and doesn't add different values for the new created user.
        """
        for _ in range(2):
            execute_cmd(multihost, "echo container:493216:65536 >> /etc/subuid")
            execute_cmd(multihost, "echo container:493216:65536 >> /etc/subgid")
        execute_cmd(multihost, "useradd container")
        for f_file in ['subuid', 'subgid']:
            assert len(execute_cmd(multihost, f"grep -c container "
                                              f"/etc/{f_file}").stdout_text.split()) < 2
        execute_cmd(multihost, "userdel -rf container")

    def test_bz_1994269(self, multihost):
        """
        :title: Stop allocating ID 65536 (reserved) for new users/groups
        :id: b012f94e-d73d-11ed-b7e6-845cf3eff344
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1994269
        :steps:
          1. Check UID_MAX value in login.def file, by default it is 60000.
          2. Add User
          3. Replace UID_MAX/GID_MAX value with 90000
          4. Add another user
          5. Users should not be created with UID 65535 (MAX_INT16)
        :expectedresults:
          1. Should succeed
          2. Should succeed
          3. Should succeed
          4. Should succeed
          5. Users are created with UIDs starting with UID_MIN -
            inside the pool between UID_MIN and old UID_MAX first
        """
        execute_cmd(multihost, "cp -vf /etc/login.defs /etc/login.defs_bkp")
        assert "UID_MAX" and "60000" in execute_cmd(multihost, "grep UID_ /etc/login.defs").stdout_text
        execute_cmd(multihost, "useradd okuser")
        assert "okuser" in execute_cmd(multihost, "id okuser").stdout_text
        execute_cmd(multihost, "sed -i 's/60000/90000/' /etc/login.defs")
        execute_cmd(multihost, "useradd nokuser")
        assert "uid=65535(nokuser)" not in execute_cmd(multihost, "id nokuser").stdout_text
        execute_cmd(multihost, "cp -vf /etc/login.defs_bkp /etc/login.defs")
        for user in ["okuser", "nokuser"]:
            execute_cmd(multihost, f"userdel -rf {user}")

    @pytest.mark.tier1
    def test_bz_955769(self, multihost):
        """
        :title: useradd not assigning correct SELinux user to contexts of home directory files
        :id: 76b787ce-ee52-11ed-b607-845cf3eff344
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=955769
        :steps:
          1. Create a new user with the username "testBZ955769" using the useradd
          2. Then checks the security context labeling of the user's
            home directory using the ls -Zal command
          3. Restores the security context labeling of the user's home
            directory using the restorecon command and checks the security
            context labeling again using the ls -Zal
          4. Check if the cmd and cmd1 variables are the same using an assertion statement
          5. Delete the user and creates a new user with the same username but with a
            different security context using the userdel and useradd commands respectively.
          6. Repeats the process of checking and restoring the security context labeling of
            the user's home directory and checks if the cmd1 and cmd variables are the same
        :expectedresults:
          1. Should succeed
          2. Should succeed
          3. Should succeed
          4. Should succeed
          5. Should succeed
          6. Should succeed
        """
        user = "testBZ955769"
        execute_cmd(multihost, f"useradd {user}")
        cmd = execute_cmd(multihost, "ls -Zal /home/testBZ955769").stdout_text
        execute_cmd(multihost, "restorecon -RFv /home/testBZ955769")
        cmd1 = execute_cmd(multihost, "ls -Zal /home/testBZ955769").stdout_text
        assert cmd == cmd1
        execute_cmd(multihost, "userdel -rfZ testBZ955769")
        execute_cmd(multihost, "useradd -m -Z staff_u testBZ955769")
        cmd = execute_cmd(multihost, "ls -Zal /home/testBZ955769").stdout_text
        execute_cmd(multihost, "restorecon -RFv /home/testBZ955769")
        cmd1 = execute_cmd(multihost, "ls -Zal /home/testBZ955769").stdout_text
        assert cmd1 == cmd
        execute_cmd(multihost, "userdel -rfZ testBZ955769")
