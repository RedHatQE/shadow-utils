# Test newgroup with password
# $1 - user to test
# $2 - group
function newgrpTestNoPass() {
    expect -c "
        spawn su - $1
        expect {
            {$1} { send -- \"newgrp $2\r\" }
            default { exit 1 }
        }
        expect {
            {$1} { send -- groups\r }
            {Password} { exit 2 }
        }
        expect {
            {$1} { send -- exit\r }
            default { exit 3 }
        }
        expect {
            {$1} { send -- exit\r }
            default { exit 4 }
        }
        expect eof { exit 0 }
    "

    return $?
}
newgrpTestNoPass $1 $2
