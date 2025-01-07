
# [SSH](../../networking/protocols/SSH.md)ing Into Module Exercise VMs
```bash
ssh -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" learner@192.168.50.52
```
Using `-o` to set `UserKnownHostsFile` to `/dev/null` tells ssh to *not verify the authenticity of the server's key*. 