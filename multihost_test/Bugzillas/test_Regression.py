"""
Shadow Utils Test Cases

:requirement: shadow-utils
:casecomponent: shadow-utils
:subsystemteam: sst_idm_sssd
:status: approved
"""

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


def log_back_in_time(multihost, number_of_days_back, user):
    client = multihost.client[0]
    client.run_command(f'date -s "-{number_of_days_back} day"')
    client.run_command(f"su - {user} -c 'id'")
    client.run_command(f'date -s "+{number_of_days_back} day"')


class TestShadowUtilsRegression():
    """
    Automation of Shadow Utils tests
    """
    @pytest.mark.tier1
    def test_bz507706(self, multihost, create_backup):
        """bz507706 grpconv wants to take all memory if /etc/group contains duplicate entries

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
        with pytest.raises(subprocess.CalledProcessError):
            execute_cmd(multihost, "grpconv")
        with pytest.raises(subprocess.CalledProcessError):
            execute_cmd(multihost, "echo -e 'y\ny\ny\ny\ny\ny\ny\ny\ny\ny\n' | grpck")
        for i in range(10):
            execute_cmd(multihost, f"groupdel group_{i}")

    @pytest.mark.tier1
    def test_bz494575(self, multihost):
        """bz494575 usermod calls restorecon everytime you try to change home directory of a user

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
        """bz487575 useradd does not clear errno prior to checking what function returns

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

    @pytest.mark.tier1
    def test_chpasswd(self, multihost):
        """The value and format of salt in /etc/shadow is incorrect when chpasswd

        :title: The value and format of salt in /etc/shadow is incorrect when chpasswd
        :id: c7415312-85f8-11ee-b721-845cf3eff344
        :bugzilla: https://issues.redhat.com/browse/RHEL-16668
        :steps:
          1. Add users.
          2. Sets their passwords using the chpasswd command
          3. Retrieve the contents of the /etc/shadow file
          4. Asserts that the string "rounds" is not present in the result.
        :expectedresults:
          1. Should succeed
          2. Should succeed
          3. Should succeed
          4. Should succeed
        """
        client = multihost.client[0]
        password = "Secret123"
        for no_no in range(1, 3):
            client.run_command(f"useradd local_anuj{no_no}")
            client.run_command(f"echo local_anuj{no_no}:{password} | chpasswd")
        result = client.run_command("getent shadow").stdout_text
        for no_no in range(1, 3):
            client.run_command(f"userdel -rf local_anuj{no_no}")
        assert "rounds" not in result

    @pytest.mark.tier1
    def test_bz1315007(self, multihost):
        """/etc/shadow- is created by useradd with mode 0000

        :title: /etc/shadow- is created by useradd with mode 0000
        :id: 63b4cf58-8dbf-11ee-b0b4-845cf3eff344
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1315007
        :steps:
            1. Adds a new user "bz1315007_1" on the client.
            2. Checks the permissions of /etc/shadow and /etc/shadow- file.
            3. Checks the security context of /etc/shadow and /etc/shadow- file.
            4. Removes the /etc/shadow- file.
            5. Adds a new user "bz1315007_2".
            6. Repeats steps 2-4 for the new user.
            7. Removes both users "bz1315007_1" and "bz1315007_2".
        :expectedresults:
            1. Should succeed
            2. Permission should be 0000
            3. Security contexts should be system_u:object_r:shadow_t:s0
            4. File should be removed
            5. User should be added
            6. Should be success when repeated
            7. User should be removed
        """
        client = multihost.client[0]
        client.run_command("useradd bz1315007_1")
        client.run_command("stat -c%a /etc/shadow |grep ^0$")
        client.run_command("stat -c%a /etc/shadow- |grep ^0$")
        client.run_command("ls -Z /etc/shadow | grep `matchpathcon -n /etc/shadow`")
        client.run_command("ls -Z /etc/shadow- | grep `matchpathcon -n /etc/shadow-`")
        client.run_command("rm -f /etc/shadow-")
        client.run_command("useradd bz1315007_2")
        client.run_command("stat -c%a /etc/shadow |grep ^0$")
        client.run_command("stat -c%a /etc/shadow- |grep ^0$")
        client.run_command("ls -Z /etc/shadow | grep `matchpathcon -n /etc/shadow`")
        client.run_command("ls -Z /etc/shadow- | grep `matchpathcon -n /etc/shadow-`")
        client.run_command("userdel -fr bz1315007_1")
        client.run_command("userdel -fr bz1315007_2")

    @pytest.mark.tier1
    def test_bz455603(self, multihost, create_backup):
        """groupmems does not check input strings for special characters

        :title: groupmems does not check input strings for special characters
        :id: d4f84f78-995e-11ee-aaf0-845cf3eff344
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=455603
        :steps:
          1. Create two users (tu01 and tu02) and a test group (tg01)
          2. Check if the group has been successfully created by
            searching for its entry in the /etc/group file.
          3. Check whether the group membership command (groupmems) raises
            an exception when attempting to add users to the group  as groupmems should not
            accept string with ':' as a username
          4. check if the group entry is still present in the /etc/group file after
            the failed group membership attempt.
          5. Check if an exception is raised when searching for the group
            entry with specific user memberships.
          6. Cleanup
        :expectedresults:
          1. User group creation Should succeed
          2. Search Should succeed
          3. Groupmems should reject string with ':' as a username
          4. Entry should still present in the /etc/group
          5. Exception should rise
          6. Cleanup Should succeed
        """
        client = multihost.client[0]
        first_user = "tu01"
        second_user = "tu02"
        test_group = "tg01"
        client.run_command(f"useradd {first_user}")
        client.run_command(f"useradd {second_user}")
        client.run_command(f"groupadd {test_group}")
        client.run_command(f'grep "^{test_group}:" /etc/group')
        with pytest.raises(Exception):
            client.run_command(f'groupmems -a "{first_user}:{second_user}" -g {test_group}')
        client.run_command(f'grep "^{test_group}:" /etc/group')
        with pytest.raises(Exception):
            client.run_command(f'grep "^{test_group}:.*:{first_user}:{second_user}" /etc/group >& /dev/null')
        client.run_command(f'groupdel {test_group}')
        client.run_command(f'userdel -r {first_user}')
        client.run_command(f'userdel -r {second_user}')

    @pytest.mark.tier1
    def test_bz306241(self, multihost, create_backup):
        """newusers creates users with negative UID and GID

        :title: newusers creates users with negative UID and GID
        :id: 06e1072a-f0c9-11ee-9905-845cf3eff344
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=306241
        :steps:
          1. Generates user entries and appends them to the specified input file.
            It iterates five times, creating five different user entries.
          2. Pipe the contents of the input file into the newusers command,
            which adds multiple users to the system in a single batch operation.
          3. Checks if the user entries have been successfully added to the `/etc/passwd` file.
          4. Loop iterate over each user entry and perform tests to ensure that the user IDs (UIDs)
            and group IDs (GIDs) are greater than or equal to 500.
          5. Loops iterate over each user entry and delete the corresponding user accounts
        :expectedresults:
          1. Should succeed
          2. Should succeed
          3. Should succeed
          4. Should succeed
          5. Should succeed
        """
        client = multihost.client[0]
        user_name = "user101"
        user_secret = "Secret123"
        input_file = "/tmp/anuj"
        assert client.run_command("ls /usr/sbin/newusers")
        for i in range(5):
            client.run_command(f"echo \"{user_name}{i}:{user_secret}::::/home/{user_name}{i}:/bin/bash\" "
                               f">> {input_file}")
        client.run_command(f"cat {input_file} | newusers")
        client.run_command(f"grep {user_name} /etc/passwd")
        for i in range(5):
            client.run_command(f"test `grep {user_name}{i} /etc/passwd | cut -d ':' -f 3` -ge 500")
            client.run_command(f"test `grep {user_name}{i} /etc/passwd | cut -d ':' -f 4` -ge 500")
        for i in range(5):
            client.run_command(f"userdel -r {user_name}{i}")
        client.run_command("rm -vf /tmp/anuj")

    @pytest.mark.tier1
    def test_bz455609(self, multihost, create_backup):
        """groupmems -d does not work

        :title: groupmems -d does not work
        :id: 0d62b45e-f0c9-11ee-b808-845cf3eff344
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=455609
        :steps:
          1. Add a test user to the system.
          2. Add a test group to the system.
          3. Add the test user to the test group.
          4. Check if the test group exists in `/etc/group`.
          5. Checks if the test user is a member of the test group.
          6. Remove the test user from the test group.
          7. Check if the test group still exists after removing the user.
          8. Checks if the test user is still a member of the test group.
          9. Delete the test group
          10. Delete the test user along with their home directory
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
        client = multihost.client[0]
        test_user = "tu1"
        test_group = "tg1"
        client.run_command(f'useradd {test_user}')
        client.run_command(f'groupadd {test_group}')
        client.run_command(f'groupmems -a {test_user} -g {test_group}')
        client.run_command(f'grep "^{test_group}:" /etc/group')
        client.run_command(f'grep "^{test_group}:" /etc/group | grep ":{test_user}$" >& /dev/null')
        client.run_command(f'groupmems -d {test_user} -g {test_group}')
        client.run_command(f'grep "^{test_group}:" /etc/group')
        with pytest.raises(Exception):
            client.run_command(f'grep "^{test_group}:" /etc/group | grep ":{test_user}$" >& /dev/null')
        client.run_command(f'groupdel {test_group}')
        client.run_command(f'userdel -r {test_user}')

    @pytest.mark.tier1
    def test_bz213347(self, multihost, create_backup):
        """Huge sparse files /var/log/lastlog and /var/log/faillog creating system problems

        :title: Huge sparse files /var/log/lastlog and /var/log/faillog creating system problems
        :id: 12c1bdd2-f0c9-11ee-b22b-845cf3eff344
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=213347
        :steps:
          1. Truncate the contents of /var/log/lastlog and /var/log/faillog files
          2. Restore SELinux security contexts recursively on /var/log.
          3. Add a group nfsnobody with GID 4294967294 and a user nfsnobody with UID 4294967294.
            This is typically used for NFS operations where an anonymous user is required.
          4. Retrieve the sizes of /var/log/lastlog and /var/log/faillog files and store
            them in variables lastlogsize and failelogsize, respectively.
          5. Check whether the sizes of lastlog and faillog are less than 1048576 bytes (1 MB)
        :expectedresults:
          1. Should succeed
          2. Should succeed
          3. Should succeed
          4. Should succeed
          5. Should succeed
        """
        client = multihost.client[0]
        client.run_command("> /var/log/lastlog")
        client.run_command("> /var/log/faillog")
        client.run_command("restorecon -r /var/log")
        client.run_command("groupadd -g 4294967294 nfsnobody")
        client.run_command("useradd -u 4294967294 -g nfsnobody -l "
                           "nfsnobody -d /var/lib/nfs -s /sbin/nologin -c 'Anonymous NFS User'")
        lastlogsize = int(client.run_command("echo $(stat -c '%s' /var/log/lastlog)").stdout_text.split()[0])
        failelogsize = int(client.run_command("echo $(stat -c '%s' /var/log/faillog)").stdout_text.split()[0])
        client.run_command("userdel -r nfsnobody", raiseonerr = False)
        assert lastlogsize < 1048576
        assert failelogsize < 1048576

    @pytest.mark.tier1
    def test_bz247514(self, multihost, create_backup):
        """Make sure chpasswd does not segfault under some conditions

        :title: Make sure chpasswd does not segfault under some conditions
        :id: 1b9a2ed0-f0c9-11ee-989d-845cf3eff344
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=247514
        :steps:
          1. Add a new user named "foo247514" and sets the password for the user with chpasswd.
          2. Delete the user "foo247514" along with their home directory and mail spool.
          3. Add the user "foo247514" again and set their password to "password" with chpasswd.
        :expectedresults:
          1. Should succeed
          2. Should succeed
          3. Should succeed
        """
        client = multihost.client[0]
        client.run_command("useradd foo247514")
        client.run_command("echo foo247514:password | chpasswd -m")
        client.run_command("userdel -rf foo247514")
        client.run_command("useradd foo247514; echo foo247514:password |chpasswd -m")
        client.run_command("userdel -rf foo247514")

    @pytest.mark.tier1
    def test_bz450262(self, multihost, create_backup):
        """useradd/usermod may give access to root group

        :title: useradd/usermod may give access to root group
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=450262
        :id: 5d789546-f563-11ee-be64-845cf3eff344
        :steps:
          1. Create groups.
          2. Test various scenarios of adding users to groups with different configurations.
          3. Verify the behavior of user addition and group existence.
          4. Clean up by deleting users, groups, and temporary files.
        :expectedresults:
          1. Should succeed
          2. Should succeed
          3. Should succeed
          4. Should succeed
          5. Should succeed
        """
        client = multihost.client[0]
        first_group = "firstgroup"
        second_group = "secondgroup"
        user_name = "user"
        output_file = "/tmp/anuj"
        client.run_command(f"groupadd {first_group}")
        client.run_command(f"groupadd {second_group}")
        for command in [f"useradd -G ,{first_group} {user_name}",
                        f"useradd -G {first_group}, {user_name}",
                        f"useradd -G ,{first_group}, {user_name}",
                        f"useradd -G {first_group},{second_group}, {user_name}",
                        f"useradd -G ,{first_group},{second_group} {user_name}",
                        f"useradd -G ,{first_group},{second_group}, {user_name}",
                        f"useradd -G {first_group},,{second_group} {user_name}"]:
            with pytest.raises(Exception):
                client.run_command(command)
            client.run_command(f"groups {user_name} 2>&1 | tee {output_file}")
            client.run_command(f"grep -i \"{user_name}.*no such user\" {output_file}")
            with pytest.raises(Exception):
                client.run_command(f"userdel -r {user_name}")

        for command in [f"usermod -G {first_group}, {user_name} 2>&1 | tee {output_file}",
                        f"usermod -G ,{first_group} {user_name} 2>&1 | tee {output_file}",
                        f"usermod -G ,{first_group}, {user_name} 2>&1 | tee {output_file}",
                        f"usermod -G {first_group},{second_group}, {user_name} 2>&1 | tee {output_file}",
                        f"usermod -G ,{first_group},{second_group} {user_name} 2>&1 | tee {output_file}",
                        f"usermod -G ,{first_group},{second_group}, {user_name} 2>&1 | tee {output_file}",
                        f"usermod -G ,{first_group},,{second_group} {user_name} 2>&1 | tee {output_file}"]:
            client.run_command(f"useradd {user_name}")
            client.run_command(command)
            client.run_command(f"grep -i -e \"group.*does not exist\" -e \"invalid.*argument\" "
                               f"-e \"unknown group\" {output_file}")
            client.run_command(f"groups {user_name} 2>&1 | tee {output_file}")
            with pytest.raises(Exception):
                client.run_command(f"grep -i \"{user_name}.*{first_group}\" {output_file}")
            client.run_command(f"userdel -r {user_name}")

        client.run_command(f"rm -f {output_file}")
        client.run_command(f"groupdel {second_group}")
        client.run_command(f"groupdel {first_group}")

    @pytest.mark.tier1
    def test_bz1114081_1285547(self, multihost, create_backup):
        """pam_lastlog unable to reset locked account

        :title:pam_lastlog unable to reset locked account
        :id: 94626b58-f7c6-11ee-bf95-845cf3eff344
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1285547
                   https://bugzilla.redhat.com/show_bug.cgi?id=1114081
        :steps:
          1. Creates a new user test1.
          2. Clear the contents of the lastlog file and sets its context using restorecon.
          3. Generates options for the lastlog command and checks if they are all present.
          4. Simulates a login for user test1 that is five days in the past using log_back_in_time.
          5. Checks the last login entry for test1 to ensure it's not showing "Never logged in".
          6. Run lastlog to check if the user has logged in before the last 4 days.
          7. Run lastlog to check if the user has logged in before the last 6 days.
          8. Run lastlog to check if the user has logged in the last 4 days.
          9. Run lastlog to check if the user has logged in the last 6 days.
          10. Clears the last login entry for test1 and checks if it shows "Never logged in" again.
          11. Sets a new last login time for test1.
        :expectedresults:
          1. Should succeed
          2. Should succeed
          3. Should succeed
          4. Should succeed
          5. Should succeed
          6. Should succeed
          7. Should not succeed
          8. Should not succeed
          9. Should succeed
          10. Should succeed
          11. Should succeed
        """
        client = multihost.client[0]
        log = "/var/log/lastlog"
        options = "/tmp/options.txt"
        user = "test1"
        opt = ["before", "help", "root", "time", "user", "set", "clear"]
        client.run_command("useradd test1")
        client.run_command(f"> {log}")
        client.run_command(f"restorecon -vF {log}")
        client.run_command(f"lastlog --help | grep '^[[:blank:]]*-[[:alpha:]],' > {options}")
        real_data = client.run_command(f"cat {options}").stdout_text
        for data in opt:
            assert data in real_data
        assert int(client.run_command(f"cat {options}  | wc -l").stdout_text.split()[0]) == len(opt)

        log_back_in_time(multihost, 5, "test1")
        last = client.run_command(f"lastlog --user test1 | grep test1").stdout_text
        assert "test1" in last
        assert "Never logged in" not in last
        client.run_command(f"lastlog --before 4 --user {user} | grep {user}")
        with pytest.raises(Exception):
            client.run_command(f"lastlog --before 6 --user {user} | grep {user}")
        with pytest.raises(Exception):
            client.run_command(f"lastlog --time 4 --user {user} | grep {user}")
        client.run_command(f"lastlog --time 6 --user {user} | grep {user}")

        client.run_command(f"lastlog --clear --user {user}")
        assert "Never logged in" in client.run_command(f"lastlog --user {user} | grep {user}").stdout_text

        client.run_command(f"lastlog --set --user {user}")
        last = client.run_command(f"lastlog --user test1 | grep test1").stdout_text
        assert "test1" in last
        assert "Never logged in" not in last
        client.run_command(f"lastlog --clear --user {user}")
        client.run_command(f"userdel -rf {user}")

    @pytest.mark.tier1
    def test_bz1498628(self, multihost):
        """Update to get newuidmap and newgidmap binaries

        :title: Update to get newuidmap and newgidmap binaries
        :id: 3af5735a-fd87-11ee-8c23-845cf3eff344
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1498628
        :steps:
          1. Add a user and set password for user.
          2. Retrieve the UID (User ID) and GID (Group ID) of the created user.
          3. Checks for any sub-UID and sub-GID entries for the user "testUser1" in
            the /etc/subuid and /etc/subgid files respectively.
          4. Sanity check for binaries attributes
          5. Test that newuidmap and newgidmap have manual pages
          6. Test that newuidmap and newgidmap works without altering the capability bounding set
          7. Test that newuidmap and newgidmap does not allow mapping subuids outside of allowed range
          8. Test that newuidmap and newgidmap works when called from process
            with cap_sys_admin removed from bounding set
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
        client = multihost.client[0]
        pidfile = "/tmp/pidfile.txt"
        client.run_command("useradd testUser1")
        password = "Secret123"
        passwd_cmd = f'passwd --stdin testUser1'
        multihost.client[0].run_command(passwd_cmd, stdin_text=password, raiseonerr=False)
        client.run_command("grep testUser1 /etc/subuid")
        testUserUid = client.run_command("id -u testUser1").stdout_text.split()[0]
        testUserGid = client.run_command("id -g testUser1").stdout_text.split()[0]
        subuid = client.run_command("grep testUser1 /etc/subuid | cut -f2 -d':'").stdout_text.split()[0]
        client.run_command("grep testUser1 /etc/subgid")
        subgid = client.run_command("grep testUser1 /etc/subgid | cut -f2 -d':'").stdout_text.split()[0]

        # Sanity check for binaries attributes
        assert "/usr/bin/newuidmap cap_setuid=ep" in client.run_command("getcap `which newuidmap`").stdout_text
        assert "rwx" in client.run_command("ls -ld `which newuidmap`").stdout_text
        assert "rws" not in client.run_command("ls -ld `which newuidmap`").stdout_text
        assert "/usr/bin/newgidmap cap_setgid=ep" in client.run_command("getcap `which newgidmap`").stdout_text
        assert "rwx" in client.run_command("ls -ld `which newgidmap`").stdout_text
        assert "rws" not in client.run_command("ls -ld `which newgidmap`").stdout_text

        # Test that newuidmap and newgidmap have manual pages
        client.run_command("COLUMNS=1000 man newuidmap | col -b")
        client.run_command("COLUMNS=1000 man newgidmap | col -b")

        # Test that newuidmap and newgidmap works without altering the capability bounding set
        ssh1 = SSHClient(multihost.client[0].ip, username="testUser1", password=password)
        (r, r2, r3) = ssh1.exec_command(f"unshare -U bash -c 'grep PPid /proc/self/status | "
                                        f"cut -f 2 ; sleep 30' >{pidfile} &")
        time.sleep(2)
        assert subuid not in client.run_command(f'cat "/proc/$(cat {pidfile})/uid_map"').stdout_text
        client.run_command(f"runuser -u testUser1 -- newuidmap $(cat {pidfile}) {testUserUid} {subuid} 10")
        assert subuid in client.run_command(f'cat "/proc/$(cat {pidfile})/uid_map"').stdout_text

        (r1, r2, r3) = ssh1.exec_command(f"unshare -U bash -c 'grep PPid /proc/self/status | "
                                         f"cut -f 2 ; sleep 30' >{pidfile} &")
        time.sleep(2)
        assert subgid not in client.run_command(f'cat "/proc/$(cat {pidfile})/gid_map"').stdout_text
        client.run_command(f"runuser -u testUser1 -- newgidmap $(cat {pidfile}) {testUserGid} {subgid} 10")
        assert subuid in client.run_command(f'cat "/proc/$(cat {pidfile})/gid_map"').stdout_text

        # Test that newuidmap and newgidmap does not allow mapping subuids outside of allowed range
        (r1, r2, r3) = ssh1.exec_command(f"unshare -U bash -c 'grep PPid /proc/self/status | "
                                         f"cut -f 2 ; sleep 30' >{pidfile} &")
        time.sleep(2)
        assert subuid not in client.run_command(f'cat "/proc/$(cat {pidfile})/uid_map"').stdout_text
        with pytest.raises(Exception):
            client.run_command(f"runuser -u testUser1 -- newuidmap $(cat {pidfile}) {testUserUid} {subuid} 1 10")
        assert subuid not in client.run_command(f'cat "/proc/$(cat {pidfile})/uid_map"').stdout_text

        (r1, r2, r3) = ssh1.exec_command(f"unshare -U bash -c 'grep PPid /proc/self/status | "
                                         f"cut -f 2 ; sleep 30' >{pidfile} &")
        time.sleep(2)
        assert subgid not in client.run_command(f'cat "/proc/$(cat {pidfile})/gid_map"').stdout_text
        with pytest.raises(Exception):
            client.run_command(f"runuser -u testUser1 -- newgidmap $(cat {pidfile}) {testUserGid} {subgid} 1 10")
        assert subuid not in client.run_command(f'cat "/proc/$(cat {pidfile})/gid_map"').stdout_text

        # Test that newuidmap and newgidmap works when called from process with cap_sys_admin removed from bounding set
        (r1, r2, r3) = ssh1.exec_command(f"unshare -U bash -c 'grep PPid /proc/self/status | "
                                         f"cut -f 2 ; sleep 30' >{pidfile} &")
        time.sleep(2)
        assert subuid not in client.run_command(f'cat "/proc/$(cat {pidfile})/uid_map"').stdout_text
        client.run_command(f"capsh --gid={testUserGid} "
                           f"--groups= --drop=cap_sys_admin "
                           f"--uid={testUserUid} --inh= "
                           f"--caps= -- -c 'newuidmap "
                           f"'$(cat {pidfile})' {testUserUid} '{subuid}' 10'")
        assert subuid in client.run_command(f'cat "/proc/$(cat {pidfile})/uid_map"').stdout_text

        (r1, r2, r3) = ssh1.exec_command(f"unshare -U bash -c 'grep PPid /proc/self/status | "
                                         f"cut -f 2 ; sleep 30' >{pidfile} &")
        time.sleep(2)
        assert subgid not in client.run_command(f'cat "/proc/$(cat {pidfile})/gid_map"').stdout_text
        client.run_command(f"capsh --gid={testUserGid} "
                           f"--groups= --drop=cap_sys_admin "
                           f"--uid={testUserUid} --inh= --caps= -- "
                           f"-c 'newgidmap '$(cat {pidfile})' {testUserUid} '{subuid}' 10'")
        assert subuid in client.run_command(f'cat "/proc/$(cat {pidfile})/gid_map"').stdout_text

        client.run_command("userdel -rf testUser1")
