# Cloudfox
Init.

Cloudfox is a tool used for *enumerating the attack surface of a cloud-based target* (during [pentesting](/cybersecurity/pen-testing/penetration-testing.md)). Cloudfox is a command line tool which can be deployed to enumerate the following assets on a cloud target:
- AWS account regions
- secrets in EC2 userdata and environment variables
- workloads which have administrative permissions attached to them
- the actions and permissions attached to a principle
- role trusts which are overly permissive or allow cross account assumption
- endpoints/ hostnames/ IPs which can be attacked from an *internal* AND/ OR *external* starting point
- filesystmes which can potentially be mounted from a compromised resource in a VPC
## Use

> [!Resources]
> - [Cloudfox GitHub](https://github.com/BishopFox/cloudfox)
> - [Cloudfox documentation](https://bishopfox.com/blog/introducing-cloudfox)
