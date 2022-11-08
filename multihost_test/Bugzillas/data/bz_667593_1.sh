# $1 - user
# $2 - password

function sgTestPass() {
  expect -c "
    spawn su - $1
    expect {
      $1 { send -- \"sg tgroup00011 -c id\r\" }
      default { exit 1 }
    }
    expect {
      {Password} { send -- $2\r }
      {exist} { exit 2 }
      default { exit 2 }
    }
    expect {
      {Invalid} { exit 3 }
      $1 { send -- exit\r }
    }
    expect eof { exit 0 }
    exit 4
  "
}
sgTestPass $1 $2
