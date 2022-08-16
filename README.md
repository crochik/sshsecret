# SSH Secret

Encrypt/Decript short messages using ssh keys so you can share secrets with other people using unsafe channels (email, chat, ...) 

## To receive secret messages

For anybody to be able to send you secret messages they will need you public key.

Generate new key pair:

```
ssh-keygen -t rsa -b 4096
```

Pick a path to store the file. *be careful* to not overide an existing `~/.ssh/id_rsa` 

Share public key (*.pub) file with people that will send you "secrets".

...
