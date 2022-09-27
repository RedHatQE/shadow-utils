# Adds password to the group. The group must exist
# $1 - group
# $2 - password
function groupPasswordAdd() {
    expect -c "
        spawn gpasswd $1
        expect {
            {New} { send -- $2\r }
            default { exit 1 }
        }
        expect {
            {Re} { send -- $2\r }
            default { exit 2 }
        }
        expect {eof} { exit 0 }
        expect 3
    "

    # return expect exit code
    return $?
}
groupPasswordAdd $1 $2
