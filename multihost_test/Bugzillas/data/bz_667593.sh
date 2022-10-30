function groupPasswordAdd() {
expect -c "
spawn gpasswd tgroup00011
expect {
{New} { send -- Secret123\r }
default { exit 1 } 
} 
expect { 
{Re} { send -- Secret123\r }
default { exit 2 }
}
expect {eof} { exit 0 }
expect 3
"
}
groupPasswordAdd
