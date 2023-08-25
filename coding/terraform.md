
# Terraform (Infrastructure as Code)
## Syntax:
```Terraform
terraform {
required_providers {
	aws = {
		source = "hashicorp/aws"
		version = "~>4.0"
		}
	}
}

# Configure AWS:
provider "aws"{
	region = "us-east-1" # Just a location where AWS has a datacenter
	access_key = "<access key>"
	secret_key = "<secret key>"
}

# Create a VPC (virtual private cloud)
resource "aws_instance" "test_ec"{
	ami = "ami-007855ac798b5175e" # Ubuntu EC2
	instance_type = "t2.micro"
}
```
Terraform is written in a language called "HashiCorp configuration language" which uses a `.tf` extension. Within a .tf file, the first thing you should do is *define a provider.*

The main job of the language is to declare resources, which are used to represent infrastructure objects.
### Terraform Configuration
A terraform configuration is a .tf document that tells Terraform how to manage a collection of infrastructure resources. It can be made up of multiple files and directories.

The language is "declarative" meaning the order of blocks and files are not meaningful. The only meaning which is relevant to terraform is the implicit and explicit relationships between resources (used to determine the order of operations).
#### Blocks
Blocks are containers for content and usually represent configuration for an object, like a resource. Blocks can have a *block type*, zero or more *labels*, and a *body* which contains arguments and nested blocks.
#### Arguments:
Appear w/i blocks and assign a value to a name.
#### Expressions:
Represent a value, literally or by referencing/ combining other values. They can be placed as values to arguments or w/i other expressions.
### Providers:
According to [Terraform](https://developer.hashicorp.com/terraform/language/providers/configuration) Providers allow Terraform to interact with APIs. Each Provider has specific configuration requirements/ settings which you can set in the root module of a terraform configuration.
```Terraform
provider "google"{
	project = "acme-app"
	region = "us-central1"
}
```
If a provider is referenced in a tf file, then terraform will download all the necessary code to talk to the provider API.
### Resources:
The resource we want to access provided by a specific provider. Syntax:
```Terraform
resource "<provider>_<reource_type>" "name" {
	config options...
	key = "value"
	key2 = "value"
}
```
## Running a configuration:
### Init
In the command line:
```bash
# make sure pwd = the directory the terraform main file is in
terraform init
```
Terraform does a "dry run" of your current infrastructure and will return any errors if they occur.
### Plan
Once the infrastructure has been initialized, use `terraform plan`:
```shell
terraform plan

Terraform used the selected providers to generate the following execution plan. Resource actions are indicated with the following symbols:
  + create

Terraform will perform the following actions:

  # aws_instance.test_ec will be created
  + resource "aws_instance" "test_ec" {
      + ami                                  = "ami-007855ac798b5175e"
      + arn                                  = (known after apply)
      + associate_public_ip_address          = (known after apply)
      + availability_zone                    = (known after apply)
      + cpu_core_count                       = (known after apply)
      + cpu_threads_per_core                 = (known after apply)
      + disable_api_stop                     = (known after apply)
      + disable_api_termination              = (known after apply)
      + ebs_optimized                        = (known after apply)
      + get_password_data                    = false
      + host_id                              = (known after apply)
      + host_resource_group_arn              = (known after apply)
      + iam_instance_profile                 = (known after apply)
      + id                                   = (known after apply)
      + instance_initiated_shutdown_behavior = (known after apply)
      + instance_state                       = (known after apply)
      + instance_type                        = "t2.micro"
      + ipv6_address_count                   = (known after apply)
      + ipv6_addresses                       = (known after apply)
      + key_name                             = (known after apply)
      + monitoring                           = (known after apply)
      + outpost_arn                          = (known after apply)
      + password_data                        = (known after apply)
      + placement_group                      = (known after apply)
      + placement_partition_number           = (known after apply)
      + primary_network_interface_id         = (known after apply)
      + private_dns                          = (known after apply)
      + private_ip                           = (known after apply)
      + public_dns                           = (known after apply)
      + public_ip                            = (known after apply)
      + secondary_private_ips                = (known after apply)
      + security_groups                      = (known after apply)
      + source_dest_check                    = true
      + subnet_id                            = (known after apply)
      + tags_all                             = (known after apply)
      + tenancy                              = (known after apply)
      + user_data                            = (known after apply)
      + user_data_base64                     = (known after apply)
      + user_data_replace_on_change          = false
      + vpc_security_group_ids               = (known after apply)
    }

Plan: 1 to add, 0 to change, 0 to destroy.
```
`+` indicates resources which were created to run the infrastructure.
`-` indicates resources which were deleted.
`~` indicates resources which were modified.

Fields which are unknown will be applied once terraform actually gets run for the first time.
### Apply
Use `terraform apply` to run the code based on the plan terraform laid out with the `plan` command. Terraform will give you the chance to review the runtime before it happens:

>[!Resources]
> - [Terraform Docs](https://developer.hashicorp.com/terraform/intro)
> - [Terraform Registry](https://registry.terraform.io/)


