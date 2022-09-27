# Test newgroup with password
# $1 - user to test
# $2 - group
# $3 - group password
function newgrpTestPass() {
    expect -c "
        spawn su - $1
        expect {
            {$1} { send -- \"newgrp $2\r\" }
            default { exit 1 }
        }
        expect {
            {Password} { send -- $3\r }
            {exist} { exit 2 }
            default { exit 2 }
        }
        expect {
            {Invalid} { exit 3 }
            {$1} { send -- groups\r }
        }
        expect {$1} { send -- exit\r }
        expect {
            {$1} { send -- exit\r }
            eof { exit 0 }
        }
        expect eof { exit 0 }
    "

    return $?
}
newgrpTestPass $1 $2 $3
