""" Automation of Shadow Utils tests """

from __future__ import print_function
import subprocess
import pytest


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
