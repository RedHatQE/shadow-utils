""" Automation of Shadow Utils tests """

from __future__ import print_function
import pytest
import subprocess
import os
import time
from sssd.testlib.common.utils import SSHClient, sssdTools


def execute_cmd(multihost, command):
    """ Run command on client machine """
    cmd = multihost.client[0].run_command(command)
    return cmd


class TestShadowUtilsRegression():
    """
    Automation of Shadow Utils tests
    """
    @pytest.mark.tier1
    def test_bz507706(self, multihost, create_backup):
        """
        :title:bz507706 grpconv wants to take all memory if /etc/group contains duplicate entries
        :id: dfe8883e-6728-11ee-b0c7-845cf3eff344
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=507706
        :steps:
          1. Add 10 user groups named group_0 to group_9.
          2. Checks the number of groups with the name pattern group_ in the /etc/group file.
            It asserts that there should be 10 such groups.
          3. The content of the /etc/group file is saved into /tmp/anuj.
          4. The groups with the name pattern group_ from /tmp/anuj are appended back into the /etc/group file.
            This effectively doubles the number of such groups.
          5. Checks again and asserts that the number of groups with the name pattern group_ in
            the /etc/group file should now be 20.
          6. The grpconv command is executed.
          7. Run the grpck command, which checks the integrity of password and group files.
            If there's a mismatch, it prompts for a confirmation to fix it.
            Here, the script provides 10 "yes" responses to fix potential mismatches.
          8. Delete the 10 user groups it had previously created.
        :expectedresults:
          1. Should succeed
          2. Should succeed
          3. Should succeed
          4. Should succeed
          5. Should succeed
          6. Should succeed
          7. Should succeed
          8. Should succeed
        """
        for i in range(10):
            execute_cmd(multihost, f"groupadd group_{i}")
        assert execute_cmd(multihost, "grep group_ /etc/group | wc -l").stdout_text.split('\n')[0] == '10'
        execute_cmd(multihost, "cat /etc/group > /tmp/anuj")
        execute_cmd(multihost, "grep group_ /tmp/anuj >> /etc/group")
        assert execute_cmd(multihost, "grep group_ /etc/group | wc -l").stdout_text.split('\n')[0] == '20'
        execute_cmd(multihost, "grpconv")
        with pytest.raises(subprocess.CalledProcessError):
            execute_cmd(multihost, "echo -e 'y\ny\ny\ny\ny\ny\ny\ny\ny\ny\n' | grpck")
        for i in range(10):
            execute_cmd(multihost, f"groupdel group_{i}")

    @pytest.mark.tier1
    def test_bz494575(self, multihost):
        """
        :title:bz494575 usermod calls restorecon everytime you try to change home directory of a user
        :id: e4a5fcf8-6728-11ee-a718-845cf3eff344
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=494575
        :steps:
          1. A new user named test_anuj is added.
          2. A new directory /home/test_anuj-2 is created.
          3. restorecon is run on the new directory.
            This command is used to restore file(s) default SELinux security contexts.
          4. The ownership (chown) of /home/test_anuj-2 is set to match the ownership of /home/test_anuj.
          5. The permissions (chmod) of /home/test_anuj-2 are set to match the permissions of /home/test_anuj.
          6. The directory /home/test_anuj is deleted.
          7. The home directory of the test_anuj user is changed to /home/test_anuj-2.
            The output of this command is saved in the variable cmd.
          8. The user test_anuj is deleted, along with its home directory (due to the -r option).
          9. The directory /home/test_anuj-2 is also deleted.
          10. An assertion is made to check that the string 'restorecon' is not
            present in the output of the usermod command.
        :expectedresults:
          1. Should succeed
          2. Should succeed
          3. Should succeed
          4. Should succeed
          5. Should succeed
          6. Should succeed
          7. Should succeed
          8. Should succeed
          9. Should succeed
          10. Should succeed
        """
        execute_cmd(multihost, "useradd test_anuj")
        execute_cmd(multihost, "mkdir /home/test_anuj-2")
        execute_cmd(multihost, "restorecon -Rv /home/test_anuj-2")
        execute_cmd(multihost, "chown --reference /home/test_anuj /home/test_anuj-2")
        execute_cmd(multihost, "chmod --reference /home/test_anuj /home/test_anuj-2")
        execute_cmd(multihost, "rm -rf /home/test_anuj")
        cmd = execute_cmd(multihost, "usermod -d /home/test_anuj-2 test_anuj").stdout_text
        execute_cmd(multihost, "userdel -rf test_anuj")
        execute_cmd(multihost, "rm -rf /home/test_anuj-2")
        assert 'restorecon' not in cmd

    @pytest.mark.tier2
    def test_bz487575(self, multihost, create_backup):
        """
        :title:bz487575 useradd does not clear errno prior to checking what function returns
        :id: a0d1bdce-7d20-11ee-b8f8-845cf3eff344
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=487575
        :steps:
          1. Install the nscd package using yum and then restarts the nscd service to apply changes.
          2. Backup of the nscd cache directory
          3. Check if the nscd is configured to enable caching for the "group" service.
          4. Create a new group with the specified group ID and name.
          5. Iterates through a range of user IDs (min_uid to max_uid) and
            creates new user account entries in the /tmp/newusers.txt file using the useradd command.
            These users have home directories under /home and use /bin/bash as their shell.
          6. Create the new user accounts by reading from the /tmp/newusers.txt file.
          7. Add a user with a fixed user ID (nextuser_id) and checks whether the user was created successfully
            by inspecting the output of the useradd and userdel commands.
            It appears to assert that certain error messages are not present in the output.
        :expectedresults:
          1. Should succeed
          2. Should succeed
          3. Should succeed
          4. Should succeed
          5. Should succeed
          6. Should succeed
          7. Should succeed
        """
        nsd_conf = "/etc/nscd.conf"
        nextuser_id = 16
        gid = 600
        group_name = "mybiggroup"
        min_uid = 1000
        max_uid = 2600
        execute_cmd(multihost, "yum install -y nscd")
        execute_cmd(multihost, "systemctl restart nscd")
        execute_cmd(multihost, "cp -vfr /var/db/nscd /var/db/nscd_anuj")
        execute_cmd(multihost, f"grep -i 'enable-cache.*group.*yes' {nsd_conf}")
        execute_cmd(multihost, f"groupadd -g {gid} {group_name}")
        for i in range(min_uid, max_uid):
            execute_cmd(multihost, f'echo "bz487575dummy{i}:x:{i}:{group_name}::/home/bz487575dummy{i}:/bin/bash"'
                                   f' >> /tmp/newusers.txt')
        execute_cmd(multihost, "newusers /tmp/newusers.txt")
        execute_cmd(multihost, f"useradd -u {nextuser_id} nextuser >& /tmp/anuj1")
        assert 'invalid' not in execute_cmd(multihost, "cat /tmp/anuj1").stdout_text
        execute_cmd(multihost, "userdel -r nextuser >& /tmp/anuj1")
        assert 'not exist' not in execute_cmd(multihost, "cat /tmp/anuj1").stdout_text
        execute_cmd(multihost, "systemctl stop nscd")
        for user_name in [user_name.split(":")[0] for
                          user_name in execute_cmd(multihost,
                                                   "cat /tmp/newusers.txt").stdout_text.split("\n")]:
            if user_name != '':
                execute_cmd(multihost, f"userdel -rf {user_name}")
        execute_cmd(multihost, "cp -vfr /var/db/nscd_anuj /var/db/nscd")
        execute_cmd(multihost, "rm -rf /home/bz487575dummy*")
        execute_cmd(multihost, "rm -rf /tmp/newusers.txt")
