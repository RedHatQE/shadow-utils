function sgTestPass() {
expect -c "
spawn su - tuser0011
expect {
{tuser0011} { send -- \"sg tgroup00011 -c id\r\" }
default { exit 1 }
}
expect {
{Password} { send -- Secret123\r }
{exist} { exit 2 }
default { exit 2 }
}
expect {
{Invalid} { exit 3 }
{tuser0011} { send -- exit\r }
}
expect eof { exit 0 }
exit 4
"
}
sgTestPass
