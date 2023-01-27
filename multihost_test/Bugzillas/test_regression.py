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

    @pytest.mark.tier1
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
