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
