""" Automation of Shadow Utils tests """

from __future__ import print_function
import subprocess
import pytest
import os
from sssd.testlib.common.expect import pexpect_ssh
from sssd.testlib.common.ssh2_python import SSHClient


@pytest.mark.tier1
class TestShadowUtilsRegressions():
    """
    Automation of Shadow Utils tests
    """
    def test_bz_593683(self, multihost):
        """
        :title: Shadow-Utils: useradd doesn't create
         system accounts with the same uid and gid
         when no groupid specified
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=593683
        :id: d6ced7c4-a0c6-11eb-b897-002b677efe14
        :steps:
          1. Creating the user shadowtestuser
          2. Comparing the UID and GID
        :expectedresults:
          1. Should succeed
          2. Should succeed
        """
        # Creating the user shadowtestuser
        cmd = multihost.client[0].run_command("useradd -c "
                                              "'shadow-utils testuser'"
                                              " -u 199 -s /sbin/nologin"
                                              " -m -r shadowtestuser")
        assert cmd.returncode == 0
        # Comparing the UID and GID
        cmd = multihost.client[0].run_command("id shadowtestuser")
        assert cmd.returncode == 0
        assert 'uid=199(shadowtestuser) ' \
               'gid=199(shadowtestuser) ' \
               'groups=199(shadowtestuser)' in cmd.stdout_text
        multihost.client[0].run_command("userdel -r shadowtestuser")

    def test_bz_639975(self, multihost):
        """
        :title: Shadow-Utils: useradd and usermod should return
         a special exit code if SELinux user mapping is invalid
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=639975
        :id: dd169d9c-a0c6-11eb-a238-002b677efe14
        :steps:
          1. Creating the user shadowtestuser
          2. Comparing the UID and GID
        :expectedresults:
          1. Should succeed
          2. Should succeed
        """
        with pytest.raises(subprocess.CalledProcessError):
            multihost.client[0].run_command("useradd -Z xyz user_11")
        multihost.client[0].run_command("userdel -rf user_11")
        multihost.client[0].run_command("useradd user_11")
        with pytest.raises(subprocess.CalledProcessError):
            multihost.client[0].run_command("usermod -Z xyz user_11")
        multihost.client[0].run_command("userdel -rf user_11")
        multihost.client[0].run_command("useradd -Z system_u user_11")
        multihost.client[0].run_command("userdel -rfZ user_11")
        cmd = multihost.client[0].run_command("semanage login -l")
        assert 'user_11' not in cmd.stdout_text

    def test_bz_1220504(self, multihost):
        """
        :title: BZ#1220504 (usermod -p allowing colon (ie. '' ) in encrypted)
        :id: 7d7848f8-9de1-11ed-b5f3-845cf3eff344
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1220504
        :steps:
          1. Create test user
          2. Modify user password with usermod and include colon
          3. Now see that the ':' was accepted even though it is
            really a delimiter for the file
        :expectedresults:
          1. Should succeed
          2. Should succeed
          3. Should not succeed
        """
        user = "bz1220504"
        client = multihost.client[0]
        client.run_command("cp -vf /etc/shadow /etc/shadow_anuj")
        client.run_command(f"useradd {user}")
        # Adding user password
        client.run_command(f"echo password123 | passwd --stdin {user}")
        cmd1 = client.run_command(f"grep {user} /etc/shadow")
        with pytest.raises(subprocess.CalledProcessError):
            client.run_command(f"usermod -p 'badPassword:123' {user}")
        cmd2 = client.run_command(f"grep {user} /etc/shadow")
        client.run_command(f"userdel -rf {user}")
        client.run_command("cp -vf /etc/shadow_anuj /etc/shadow")
        assert cmd1.returncode == 0
        assert cmd2.returncode == 0
        assert cmd1.stdout_text == cmd2.stdout_text

    def test_bz_956742(self, multihost):
        """
        :title: libmisc/strtoday.c backport return -2 in case of invalid date
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=956742
        :id: 6ec36e98-ab6d-11ed-a54b-845cf3eff344
        :steps:
            1. Create a new user with the username bz956742_user using the useradd command.
            2. Get the date of tomorrow using the date command and set it as the
                user's password expiration date using the chage command.
            3. Check that the password expiration date was set successfully
                by running chage -l on the user.
            4. Try to set an invalid date using the chage -d command and check
                that the password expiration date was not changed by running chage -l on the user.
            5. Set a valid date in the future for the password expiration using the chage -d command.
            6. Try to set a date in a different language using the
                chage -d command and check the error message using chage -l.
            7. Delete the user using the userdel command.
        :expectedresults:
          1. Should succeed
          2. Should succeed
          3. Should succeed
          4. Should succeed
          5. Should succeed
          6. Should succeed
          7. Should succeed
        """
        user = "bz956742_user"
        client = multihost.client[0]
        client.run_command(f"useradd {user}")
        date_t = client.run_command('date -d tomorrow +"%F"').stdout_text.split("\n")[0]
        client.run_command(f"chage -d {date_t} {user}")
        assert "Last password change" in client.run_command(f"chage -l  {user}").stdout_text
        assert "Last password change.*never" not in client.run_command(f"chage -l  {user}").stdout_text
        with pytest.raises(subprocess.CalledProcessError):
            client.run_command(f"chage -d 'invalid date' {user}")
        assert "Last password change" in client.run_command(f"chage -l  {user}").stdout_text
        assert "Last password change.*never" not in client.run_command(f"chage -l  {user}").stdout_text
        client.run_command(f"chage -d 'Jan 01 3000' {user}")
        assert "Jan 01, 3000" in client.run_command(f"chage -l  {user}").stdout_text
        with pytest.raises(subprocess.CalledProcessError):
            client.run_command(f"LANG=c chage -d '15 märz 3013' {user}")
        client.run_command(f"LANG=c chage -l  {user}")
        client.run_command(f"userdel -rf {user}")

    def test_bz_1206273(self, multihost):
        """
        :title: Issue using chage command to remove account expiration date.
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1206273
        :id: 1c2d9994-b1e2-11ed-b608-845cf3eff344
        :steps:
          1. Check if the account's expiration date is set to "never".
          2. Change the account expiration date for the user to
            never expire. The -E -1 option sets the expiration date to "never".
          3. Search for the user stored in user in the /etc/shadow file,
            which contains password and account expiration information for users.
          4. Check if the account's expiration date is set to "never" again.
            The output of the command is searched for the string "Account expires" followed by ": never".
          5. Delete the user
        :expectedresults:
          1. Should succeed
          2. Should succeed
          3. Should succeed
          4. Should succeed
          5. Should succeed
        """
        client = multihost.client[0]
        user = "bz1206273_user"
        client.run_command(f"useradd {user}")
        cmd1 = client.run_command(f"chage -l {user} | grep 'Account expires.*:.*never'")
        client.run_command(f"chage -E -1 {user}")
        cmd2 = client.run_command(f"grep {user} /etc/shadow")
        cmd3 = client.run_command(f"chage -l {user} | grep 'Account expires.*:.*never'")
        client.run_command(f"userdel -rf {user}")
        assert cmd1.returncode == 0
        assert cmd3.returncode == 0
        assert user in cmd2.stdout_text

    def test_bz_1089666(self, multihost):
        """
        :title: Given an existing user with no home directory, when the home directory
            is moved to a new location, then the new directory won't be
            created and a warning message will be printed.
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1089666
        :id: 8cb0f63a-b80d-11ed-a4d5-845cf3eff344
        :steps:
          1. Create a new user on the system using the useradd command
          2. Recursively removes the home directory of the user using rm -vfr
          3. Modify the user's home directory using usermod, and
            redirects any error messages to a file called /tmp/anuj.
          4. Deletes the user and all associated files using userdel -rf
        :expectedresults:
          1. Should succeed
          2. Should succeed
          3. Should succeed
          4. Should succeed
        """
        client = multihost.client[0]
        user = "bz1089666_user"
        client.run_command(f"useradd {user}")
        client.run_command(f"rm -vfr /home/{user}")
        client.run_command(f"usermod -m -d '/home/bz1089666_user_2' {user} &> /tmp/anuj")
        client.run_command(f"userdel -rf {user}")
        assert 'Move cannot be completed.' in client.run_command("cat /tmp/anuj").stdout_text
        with pytest.raises(subprocess.CalledProcessError):
            client.run_command("ls  /home/bz1089666_user_2")

    def test_bz_1016516(self, multihost):
        """
        :title: usermod exits with exit status 0 even when it fails.
        :id: 30b949b4-bca3-11ed-ba2a-845cf3eff344
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1016516
        :steps:
            1. A new user is created with the username "bz1016516_user" using the "useradd" command.
            2. The code asserts that the newly created user is present in
                the /etc/shadow file by running a "grep" command.
            3. The next command removes the newly created user
                from the /etc/shadow file using "sed" command.
            4. A "pytest" test is run to raise an error if the "grep" command used
                in step 2 is executed again and the user is found in the /etc/shadow file.
            5. The password for the user is changed to an invalid value using the "usermod" command.
            6. The code asserts that the user is still present in the
                /etc/shadow file despite the invalid password.
            7. The "userdel" command is used to remove the user account completely from the system.
        :expectedresults:
            1. Should succeed
            2. Should succeed
            3. Should succeed
            4. Should succeed
            5. Should succeed
            6. Should succeed
            7. Should succeed
        """
        client = multihost.client[0]
        user = "bz1016516_user"
        client.run_command(f"useradd {user}")
        assert "bz1016516_user" in \
               client.run_command("grep ^bz1016516_user /etc/shadow -E").stdout_text
        client.run_command("sed -i -e '/^bz1016516_user:/d' /etc/shadow")
        with pytest.raises(subprocess.CalledProcessError):
            client.run_command("grep ^bz1016516_user /etc/shadow -E")
        client.run_command("usermod -p 'XinvalidX' bz1016516_user")
        assert "bz1016516_user" in \
               client.run_command("grep ^bz1016516_user /etc/shadow -E").stdout_text
        client.run_command(f"userdel -rf {user}")

    def test_bz_973647(self, multihost):
        """
        :title: Missing error message when useradd cannot create user
            with homedir in location without default selinux context
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=973647
        :id: 86388e92-c228-11ed-88a2-845cf3eff344
        :steps:
            1. Sets SELinux to enforcing mode by running the command setenforce 1.
            2. Adds a new SELinux file context for the /althome directory and its subdirectories by
                running the command semanage fcontext -a -t '<<none>>' '/althome(/.*)*'.
            3. Creates the /althome directory.
            4. Checks if the user context of /althome is "unconfined_u" by running the command
                ls -laZ /althome and asserting that "unconfined_u" is in the output.
            5. Checks the SELinux file context of /althome by running the command matchpathcon /althome.
            6. Restores the default SELinux file contexts for /althome and its
                subdirectories by running the command restorecon -Rv /althome.
            7. Adds a new user named "hildegarda" with home directory /althome/hildegarda by
                running the command useradd -m -d /althome/hildegarda hildegarda.
                The command is piped to tee and grep, so that the output is both
                displayed and checked for a specific error message.
            8. Lists the contents of /althome and their SELinux file contexts by running the command ls -laZ /althome.
            9. Searches for the newly added user in /etc/passwd and deletes the user by
                running the command grep hildegarda /etc/passwd && userdel hildegarda.
            10. Deletes the /althome directory by running the command rm -rf /althome.
            11. Deletes the SELinux file context for /althome and its subdirectories by
                running the command semanage fcontext -d '/althome(/.*)*'.
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
            11. Should succeed
        """
        client = multihost.client[0]
        if '8' in client.run_command("cat /etc/redhat-release").stdout_text:
            client.run_command("setenforce 1")
            client.run_command("semanage fcontext -a -t '<<none>>' '/althome(/.*)*'")
            client.run_command("mkdir /althome")
            assert "unconfined_u" in client.run_command("ls -laZ /althome").stdout_text
            client.run_command("matchpathcon /althome")
            client.run_command("restorecon -Rv /althome")
            client.run_command("useradd -m -d /althome/hildegarda hildegarda"
                               " |& tee /dev/stderr | grep 'cannot set SELinux context for home directory'")
            client.run_command("ls -laZ /althome")
            client.run_command("grep hildegarda /etc/passwd && userdel hildegarda")
            client.run_command("rm -rf /althome")
            client.run_command("semanage fcontext -d '/althome(/.*)*'")

    def test_bz_921995(self, multihost):
        """
        :title: Include upstream patches to make it clear in the
            error message why userdel wasn't able to delete an account
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=921995
        :id: 784fae50-170a-11ee-9160-845cf3eff344
        :steps:
          1. Create a new user with the username specified
          2. Sets the password for the newly created user
          3. Check user can login
          4. Try to delete the user created
          5. Deletes the user forcefully, including their home
            directory and any files owned by them.
        :expectedresults:
          1. Should succeed
          2. Should succeed
          3. Should succeed
          4. Should not succeed
          5. Should succeed
        """
        user = "test921995"
        client = multihost.client[0]
        client.run_command(f"useradd {user}")
        client.run_command(f"echo {user} | passwd --stdin {user}")
        client_hostip = multihost.client[0].ip
        client1 = pexpect_ssh(client_hostip, f"{user}", 'test921995', debug=False)
        client1.login(login_timeout=30, sync_multiplier=5,
                      auto_prompt_reset=False)
        with pytest.raises(subprocess.CalledProcessError):
            client.run_command(f"LANG=c userdel {user}")
        client1.logout()
        client.run_command(f"userdel -rfZ {user}")

    def test_bz_782515(self, multihost):
        """
        :title: Useradd is unable to create homedir if top-level directory does not exist
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=782515
        :id: a305c84e-1720-11ee-847e-845cf3eff344
        :steps:
          1. Creates a new user named "tstusr" with the home directory set
            to /home2/tstusr2 using the useradd command.
        :expectedresults:
          1. Should succeed
        """
        temp_dir = "/home2"
        client = multihost.client[0]
        with pytest.raises(subprocess.CalledProcessError):
            client.run_command(f"ls -l {temp_dir}")
        if '8' in client.run_command("cat /etc/redhat-release").stdout_text:
            with pytest.raises(subprocess.CalledProcessError):
                client.run_command(f"useradd -d /home2/tstusr2 -m tstusr")
        else:
            client.run_command(f"useradd -d /home2/tstusr2 -m tstusr")
        client.run_command(f"userdel -rf tstusr")

    def test_bz469158(self, multihost):
        """
        :title:Useradd does not recognize -b and --base-dir options
        :id: 46ebb894-1edb-11ee-be06-845cf3eff344
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=469158
        :steps:
          1. Create the base_dir directory
          2. Executes the useradd command with the -b option,
            which sets the base directory for the user's home directory to base_dir
          3. Executes the ls command with the -Z option to list the files and directories in base_dir
            and pipes the output to grep to search for lines containing the username test_anuj.
          4. Executes the grep command to search for the user test_anuj in the /etc/passwd file.
          5. Forcefully remove the user test_anuj and delete their home directory.
          6. Executes the useradd command with the --base-dir option to set the base directory for
            the user's home directory to base_dir and creates a new user named test_anuj.
          7.  Executes the ls command with the -Z option to list the files and directories in base_dir and
            pipes the output to grep to search for lines containing the username test_anuj.
          8. Executes the grep command to search for the user test_anuj in the /etc/passwd file.
          9. Forcefully remove the user test_anuj and delete their home directory.
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
        """
        base_dir = "/home/servers"
        user = "test_anuj"
        client = multihost.client[0]
        client.run_command(f"mkdir {base_dir}")
        client.run_command(f"useradd -b {base_dir} {user}")
        client.run_command(f"ls -Z {base_dir} | grep {user}")
        client.run_command(f"grep {user} /etc/passwd")
        client.run_command(f"userdel -rf {user}")
        client.run_command(f"useradd --base-dir {base_dir} {user}")
        client.run_command(f"ls -Z {base_dir} | grep {user}")
        client.run_command(f"grep {user} /etc/passwd")
        client.run_command(f"userdel -rf {user}")

    def test_bz461455(self, multihost):
        """
        :title: New users will fail with an uninformative message if the
            new user's parent directory does not exist
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=461455
        :id: b76aa5b0-1edd-11ee-a067-845cf3eff344
        :steps:
          1. Executes the ls command with the -l option to list detailed information about newusers
          2. Constructs a string containing the user details in the format
            "username:password:UID:GID:gecos:home_dir:shell".Pipes this string to the newusers command, which
            reads a file in the same format and creates or modifies users accordingly.The output of the command
            is redirected to a file "/tmp/anuj".
          3. Checks if the string "No such file or directory" is present in the output of the cat command.
            If not, an assertion error will be raised.
        :expectedresults:
          1. Should succeed
          2. Should succeed
          3. Should succeed
        """
        user_name = "user0"
        user_secret = "s3kr3d0"
        client = multihost.client[0]
        for file in ["/etc/group", "/etc/gshadow", "/etc/passwd", "/etc/shadow"]:
            client.run_command(f"cp -vf {file} {file}_anuj")
        client.run_command("ls -l /usr/sbin/newusers")
        client.run_command("ls -l /usr/share/man/man8/newusers.8*")
        client.run_command(f"echo \"{user_name}:{user_secret}:12345:12345::/tmp/no/such/dir/{user_name}"
                           f":/bin/bash\" | newusers &>/tmp/anuj")
        for file in ["/etc/group", "/etc/gshadow", "/etc/passwd", "/etc/shadow"]:
            client.run_command(f"cp -vf {file}_anuj {file}")
        assert "No such file or directory" in client.run_command("cat /tmp/anuj").stdout_text

    def test_bz_749205(self, multihost):
        """
        :title: BZ#749205 (useradd -Z ... executes /usr/sbin/semanage but)
        :id: d2512a34-2469-11ee-a430-845cf3eff344
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=749205
        :steps:
          1. Creates a new user named "userBZ749205" on the system.
          2. Copy the file "/usr/sbin/semanage" to "/usr/sbin/semanage_anuj"
          3. Removes the "/usr/sbin/semanage" file from the system
          4. Deletes the "userBZ749205" user from the system
          5. Re-creates the "userBZ749205" user with the SELinux security context set to "user_u"
          6. Deletes the "userBZ749205" user again
          7. Copy the backup file "/usr/sbin/semanage_anuj" back to its original
        :expectedresults:
          1. Should succeed
          2. Should succeed
          3. Should succeed
          4. Should succeed
          5. Should succeed
          6. Should succeed
          7. Should succeed
        """
        client = multihost.client[0]
        client.run_command("useradd userBZ749205")
        client.run_command("cp -vf /usr/sbin/semanage /usr/sbin/semanage_anuj")
        client.run_command("rm -rf /usr/sbin/semanage")
        client.run_command("userdel -rfZ userBZ749205")
        client.run_command("useradd -Z user_u userBZ749205")
        client.run_command("userdel -rfZ userBZ749205")
        client.run_command("cp -vf /usr/sbin/semanage_anuj /usr/sbin/semanage")

    def test_bz723921(self, multihost):
        """
        :title: Checks if openssl partialy supports relro bz723921-shadow-utils-relro-support
        :id: d87de2ee-2469-11ee-bd8a-845cf3eff344
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=723921
        :steps:
          1. Run rpm-chksec file in the client system
          2. Rpm-chksec file should output desired text
        :expectedresults:
          1. Should succeed
          2. Should succeed
        """
        client = multihost.client[0]
        if '8' not in client.run_command("cat /etc/redhat-release").stdout_text:
            client.run_command("yum install -y libcap-ng-utils")
            file_location = "/multihost_test/Bugzillas/data/rpm-chksec"
            multihost.client[0].transport.put_file(os.getcwd() + file_location, '/tmp/rpm-chksec')
            client.run_command("chmod 755 /tmp/rpm-chksec")
            cmd = client.run_command("sh /tmp/rpm-chksec shadow-utils | grep -v FILE | awk '{print $3}'").stdout_text
            assert "no" not in cmd
            assert "full" in cmd

    def test_bz709605(self, multihost):
        """
        :title: bz709605-lock-files-are-not-deleted
        :id: de527d88-2469-11ee-b270-845cf3eff344
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=709605
        :steps:
          1. Create a user named "firstuser" with a specific user ID (UID) of 800.
          2. Create a group named "firstgroup" with a specific group ID (GID) of 900.
          3. List files in the /etc directory matching the pattern *lock.
          4. Attempt to create a user named "seconduser" with the same UID (800) as the previously created user.
          5. List files in the /etc directory matching the pattern *lock.
          6. Create a user named "seconduser" with a different UID (801).
          7. Attempt to modify the UID of the "seconduser" to 800, which is the UID of the "firstuser".
          8. List files in the /etc directory matching the pattern *lock.
          9. Attempt to create a group named "secondgroup" with the same GID (900) as the previously created group.
          10. List files in the /etc directory matching the pattern *lock.
          11. Create a group named "secondgroup" with a different GID (901).
          12. List files in the /etc directory matching the pattern *lock.
        :expectedresults:
          1. Should succeed
          2. Should succeed
          3. Should Not succeed
          4. Should Not succeed
          5. Should Not succeed
          6. Should succeed
          7. Should Not succeed
          8. Should Not succeed
          9. Should Not succeed
          10. Should Not succeed
          11. Should succeed
          12. Should Not succeed
        """
        client = multihost.client[0]
        client.run_command("useradd -u 800 firstuser")
        client.run_command("groupadd -g 900 firstgroup")
        with pytest.raises(subprocess.CalledProcessError):
            client.run_command("ls -l /etc/*lock")
        with pytest.raises(subprocess.CalledProcessError):
            client.run_command("useradd -u 800 seconduser")
        with pytest.raises(subprocess.CalledProcessError):
            client.run_command("ls -l /etc/*lock")
        client.run_command("useradd -u 801 seconduser")
        with pytest.raises(subprocess.CalledProcessError):
            client.run_command("usermod -u 800 seconduser")
        with pytest.raises(subprocess.CalledProcessError):
            client.run_command("ls -l /etc/*lock")
        with pytest.raises(subprocess.CalledProcessError):
            client.run_command("groupadd -g 900 secondgroup")
        with pytest.raises(subprocess.CalledProcessError):
            client.run_command("ls -l /etc/*lock")
        client.run_command("groupadd -g 901 secondgroup")
        with pytest.raises(subprocess.CalledProcessError):
            client.run_command("groupadd -g 900 secondgroup")
        with pytest.raises(subprocess.CalledProcessError):
            client.run_command("ls -l /etc/*lock")
        for command in ["groupdel secondgroup",
                        "groupdel firstgroup",
                        "userdel -rf seconduser",
                        "userdel -rf firstuser"]:
            client.run_command(command)

    def test_bz693377(self, multihost):
        """
        :title: bz693377-useradd-segfaults-when-UID_MAX-larger-than-2147483647
        :id: 3057c3f8-29e8-11ee-81fb-845cf3eff344
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=693377
        :steps:
          1. Change the maximum UID setting in the login.defs file to 2147483647.
          2. Add two new users. One of these users has a user ID specifically set to 2147483645.
          3. A loop is then started that runs for the number of times specified in the count variable.
            For each iteration, a new user is created with a name based on tuser and the current iteration number.
          4. Checks that the number of users created with the base name tuser is equal to the count variable.
          5. Checks that there are three users with UIDs in the 214748364X range.
        :expectedresults:
          1. Should succeed
          2. Should succeed
          3. Should succeed
          4. Should succeed
          5. Should succeed
        """
        client = multihost.client[0]
        loindefs = "/etc/login.defs"
        tuser = "test1"
        tuserf = "test2"
        count = 10
        client.run_command("cp -vf /etc/login.defs /etc/login.defs_anuj")
        try:
            client.run_command(f"sed -i 's/^UID_MAX.*/UID_MAX\t2147483647/g' {loindefs}")
            client.run_command(f"useradd {tuserf}")
            client.run_command(f"useradd -u 2147483645 {tuser}")
            for i in range(count):
                client.run_command(f"useradd {tuser}_{i}")
            assert client.run_command(f"cat /etc/passwd |  grep -c {tuser}_").stdout_text.split('\n')[0] == '10'
            assert client.run_command('cat /etc/passwd | egrep -c "214748364[0-9]"').stdout_text.split('\n')[0] == '3'
            for user in [tuser, tuserf]:
                client.run_command(f"userdel -r {user}")
            for i in range(count):
                client.run_command(f"userdel -rf {tuser}_{i}")
            client.run_command("mv /etc/login.defs_anuj /etc/login.defs")
        except:
            client.run_command("mv /etc/login.defs_anuj /etc/login.defs")
            for user in [tuser, tuserf]:
                client.run_command(f"userdel -r {user}", raiseonerr=False)
            for i in range(count):
                client.run_command(f"userdel -rf {tuser}_{i}", raiseonerr=False)
            pytest.xfail("Unable to create user.")

    @pytest.mark.tier1
    def test_bz681020(self, multihost):
        """
        :title:pwconv and pwunconv alter uids over 2147483647
        :id: 88b97d66-4630-11ee-a650-845cf3eff344
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=681020
        :steps:
          1. Create a new group called "bigid" with the GID (Group ID) of 3000000000.
          2. Create a new user named "bigid" with the UID (User ID) of
            3000000000 and associates it with the group "bigid".
          3. Check to make sure the user "bigid" has the correct UID of 3000000000.
          4. Check to ensure the user "bigid" has the correct primary GID of 3000000000.
          5. Running the pwunconv command which merges the users and groups from the /etc/shadow
            and /etc/gshadow files back into the /etc/passwd and /etc/group files.
          6. After pwunconv, it ensures that the user "bigid" still has the correct UID and GID.
          7. Running pwconv creates additional expiration information for the /etc/shadow file
            from entries in your /etc/login.defs file.
          8. After pwconv, it ensures that the user "bigid" still has the correct UID and GID.
        :expectedresults:
          1. Should succeed
          2. Should succeed
          3. Should succeed
          4. Should succeed
          5. Should succeed
          6. uid and gid are preserved at 3000000000
          7. Should succeed
          8. uid and gid are preserved at 3000000000
        """
        client = multihost.client[0]
        client.run_command("cp -vf /etc/shadow /etc/shadow_anuj")
        client.run_command("groupadd -g 3000000000 bigid" )
        client.run_command("useradd -u 3000000000 -g bigid -c 'Big ID' bigid")
        assert '3000000000' in client.run_command("id -u bigid | grep 3000000000").stdout_text
        assert '3000000000' in client.run_command("id -g bigid | grep 3000000000").stdout_text
        client.run_command("pwunconv")
        assert '3000000000' in client.run_command("id -u bigid | grep 3000000000").stdout_text
        assert '3000000000' in client.run_command("id -g bigid | grep 3000000000").stdout_text
        client.run_command("pwconv")
        assert '3000000000' in client.run_command("id -u bigid | grep 3000000000").stdout_text
        assert '3000000000' in client.run_command("id -g bigid | grep 3000000000").stdout_text
        client.run_command("userdel -r bigid")
        client.run_command("cp -vf /etc/shadow_anuj /etc/shadow")

    @pytest.mark.tier1
    def test_bz469158(self, multihost):
        """
        :title:bz469158 useradd does not recognize -b and --base-dir options
        :id: 773e7702-5c34-11ee-9186-845cf3eff344
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=469158
        :steps:
          1. Creates a directory
          2. Adds a user with its home directory inside the created directory
          3. Checks if the home directory exists with the correct SELinux context
            and if the user was added to the system
          4. Deletes the user
          5. Repeats the user creation and checks
          6. Deletes the user again
        :expectedresults:
          1. Should succeed
          2. Should succeed
          3. Should succeed
          4. Should succeed
          5. Should succeed
          6. Should succeed
        """
        client = multihost.client[0]
        base_dir = "/home/servers"
        user = "test_anuj"
        client.run_command(f"mkdir {base_dir}")
        client.run_command(f"useradd -b {base_dir} {user}")
        client.run_command(f"ls -Z {base_dir} | grep {user}")
        client.run_command(f"grep {user} /etc/passwd")
        client.run_command(f"userdel -rf {user}")
        client.run_command(f"useradd --base-dir {base_dir} {user}")
        client.run_command(f"ls -Z {base_dir} | grep {user}")
        client.run_command(f"grep {user} /etc/passwd")
        client.run_command(f"userdel -rf {user}")

    @pytest.mark.tier1
    def test_bz461455(self, multihost, create_backup):
        """
        :title:bz461455 new users fails with an obscure message when parent directory does not exist
        :id: 7ee888f8-5c34-11ee-b760-845cf3eff344
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=461455
        :steps:
          1. Checks the existence of the newusers executable and its manual pages.
          2. Tries to create a user with a non-existent home directory.
          3. Verifies the expected error message was generated.
          4. Restores the previously backed-up files.
        :expectedresults:
          1. Should succeed
          2. Should succeed
          3. Should succeed
          4. Should succeed
        """
        client = multihost.client[0]
        user_name = "user0"
        user_secret = "s3kr3d0"
        client.run_command("ls -l /usr/sbin/newusers")
        client.run_command("ls -l /usr/share/man/man8/newusers.8*")
        client.run_command(f"echo \"{user_name}:{user_secret}:12345:12345:"
                           f":/tmp/no/such/dir/{user_name}:/bin/bash\" | newusers &>/tmp/anuj")
        assert "No such file or directory" in client.run_command("cat /tmp/anuj").stdout_text
