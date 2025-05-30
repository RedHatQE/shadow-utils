"""
Shadow Utils Test Cases

:requirement: shadow-utils
:casecomponent: shadow-utils
:subsystemteam: sst_idm_sssd
:status: approved
"""

from __future__ import print_function
import pytest


@pytest.mark.tier1
class TestShadowUtilsErrors():
    """
    Automation of Shadow Utils tests
    """
    def test_error_2006_0032(self, multihost):
        """Tests if shadow-utils are immune against bugs in 2006:0032

        :title: Tests if shadow-utils are immune against bugs in 2006:0032
        :id: 017f615a-92a8-11eb-bca1-002b677efe14
        :steps:
          1. Creating tmp directory
          2. Allowing '.' in usernames
          3. Added two patches to shadow-utils for
          additional usermod flag
          4. The user foo must be included in both
          foo-group and foo-group2 groups
          5. usermod -p does not update sp_lstchg
        :expectedresults:
          1. Should succeed
          2. Should succeed
          3. Should succeed
          4. Should succeed
          5. Should succeed
        """
        # Creating tmp directory
        cmd = multihost.client[0].run_command("mktemp -d")
        assert cmd.returncode == 0
        # useradd not allowing '.' in usernames
        cmd = multihost.client[0].run_command("useradd "
                                              "joe.testing")
        assert cmd.returncode == 0
        multihost.client[0].run_command("userdel -rf joe.testing")
        # Added two patches to shadow-utils for
        # additional usermod flag
        multihost.client[0].run_command("useradd foo")
        multihost.client[0].run_command("groupadd foo-group")
        multihost.client[0].run_command("usermod -G "
                                        "foo-group foo")
        multihost.client[0].run_command("groupadd foo-group2")
        multihost.client[0].run_command("usermod -G "
                                        "foo-group2 -a foo")
        # The user foo must be included in both
        # foo-group and foo-group2 groups
        cmd = multihost.client[0].run_command("id foo")
        for i in ['foo', 'foo-group', 'foo-group2']:
            assert i in cmd.stdout_text
        multihost.client[0].run_command("groupdel "
                                        "foo-group")
        multihost.client[0].run_command("groupdel "
                                        "foo-group2")
        # usermod -p does not update sp_lstchg
        pass_ch0 = multihost.client[0].run_command("chage -l foo")
        pass_ch0 = pass_ch0.stdout_text.split('\n')[0].split(':')[1]
        multihost.client[0].run_command("date -s '-2 day'")
        multihost.client[0].run_command("usermod  -p foopass foo")
        multihost.client[0].run_command("date -s '+2 day'")
        pass_change = multihost.client[0].run_command("chage -l foo")
        pass_change = pass_change.stdout_text.split('\n')[0].split(':')[1]
        assert pass_ch0 != pass_change
        multihost.client[0].run_command("userdel -rf foo")
