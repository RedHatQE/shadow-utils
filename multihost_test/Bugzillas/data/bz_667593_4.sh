function sgTestNoPass() {
expect -c "
spawn su - tuser0011
expect {
{tuser0011} { send -- \"sg tgroup00011 -c id\r\" }
default { exit 1 }
}
expect {
{tuser0011} { send -- exit\r }
{Password} { exit 2 }
}
expect {
eof { exit 0 }
default { exit 3 }
}
exit 4
"
}
sgTestNoPass
