https://docs.docker.com/get-started/
https://www.youtube.com/watch?v=rOTqprHv1YE
https://www.youtube.com/watch?v=3c-iBn73dDE

Docker [[containers]] sit on top of the host [[operating-system]]:
	- A #docker-container uses the host [[operating-system]]
		- prefers [[linux]]-based OS's
		- lighter than a [[virtual-machine]] because it piggy-backs on the pre-existing OS
		- #boot s faster
		- Occupies less [[memory]]
		- data volumes can be shared between [[containers]]
	- the [[containers]] also include all of the dependencies required for the #application to run.
- 

Docker vs [[virtual-machine]]s:
- [[operating-system]]s have two components:
	- #kernel
	- #applications 
- [[virtual-machine]]s and Docker virtualize different parts of the OS
	- Docker: virtualizes the #applications layer
		- needs to use the #host 's #kernel
	- [[virtual-machine]]s virtualize the complete [[operating-system]] (including the #kernel and #applications )

The #docker-engine is installed on the #host machine and allows the #docker-container s to be built and run using Docker services.
	- Can be accessed from the #host -side [[command-line-interface]]
	- uses a #client-server-architecture:
		- installed on the #host [[hardware]] and containers the docker-server ( #daemon )
		- controls how the #client is created
		- #client and #server communitcate using #REST-API

Components of Docker:
1. #client:
	1. accessed from host [[command-line-interface]]
	2. where the #daemon and #registry-service are run from
	3. from the [[command-line-interface]] the #user can build #docker-image s and run #docker-container s by sending commands from the CLI to the #server 
2. #docker-image :
	1. a template with instructions which is used to build #docker-container s 
		1. built using the #docker-file which is a text file w/ commands for building the image
		2. once the #docker-file is made, it is stored in 
		3. oncce the #docker-file is made, it is stored in a #repository ( #docker-hub)
			1. registry.hub.docker.com
	2. Can be pulled from the hub
		1. has versioning
	3. syntax for creating an image:
		1. `Docker container create [OPTIONS] IMAGE [COMMAND] [ARG...]`
3. #docker-container :
	1. runtime of the image
	2. . standalone executable software package which includes #applications and their dependencies
		1. multiple #docker-container s can run on the same infrastructure and share [[operating-system]]s with other containters
		2. isolared
	3. bound to a port
	4. has a virtual filesystem abstracted from the [[operating-system]]
4. #docker-registry
	1. open-source, #server -side service which hosts #docker-image s which can be shared easily (amongst team members)
	2. Docker has a default registry called #docker-hub 
		1. public vs private registries
	3. Commands: pull and push
		1. to build a #docker-container :
			1. `Docker pull <image>:<tag>` --> pulls an image from a docker repo
		2. to update a repo:
			1. `Docker push <image>:<tags>`

