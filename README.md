# SSH Secret
Encrypt/Decript short messages using ssh keys

## To receive secret messages

generate new key pair:

```
ssh-keygen -t rsa -b 4096
```

Pick a path to store the file. *be careful* to not overide an existing `~/.ssh/id_rsa` 

share public key (*.pub) file with people that will send you "secrets".
