
# Docker
Docker [containers](computers/containers-vms/containers.md) sit on top of the host [operating-system](/computers/operating-system.md):
- A docker container uses the host #operating-system
	- prefers [linux](/computers/linux)-based OS's
	- lighter than a #virtual-machine because it piggy-backs on the pre-existing OS
	- #boot s faster
	- Occupies less memory
	- data volumes can be shared between containers
- the containers also include all of the dependencies required for the #application to run.

## Docker vs virtual-machines:
- operating-systems have two components:
	- #kernel
	- #applications 
- virtual-machines and Docker virtualize different parts of the OS
	- Docker: virtualizes the #applications layer
		- needs to use the #host 's #kernel
	- virtual-machines virtualize the complete operating-system (including the #kernel and #applications)

## Docker Engine
The #docker-engine is installed on the #host machine and allows the #docker-container s to be built and run using Docker services.
- Can be accessed from the #host -side command-line-interface
- uses a #client-server-architecture:
	- installed on the #host [hardware](/computers/hardware.md) and contain the docker-server ( #daemon )
	- controls how the #client is created
	- #client and #server communicate using #REST-API

## Components of Docker:
1. #client:
	1. accessed from host command-line-interface
	2. where the #daemon and #registry-service are run from
	3. from the command-line-interface the #user can build #docker-image s and run #docker-container s by sending commands from the CLI to the #server 
2. #docker-image :
	1. a template with instructions which is used to build #docker-container s 
		1. built using the #docker-file which is a text file w/ commands for building the image
		2. once the #docker-file is made, it is stored in 
		3. once the #docker-file is made, it is stored in a #repository ( #docker-hub)
			1. registry.hub.docker.com
	2. Can be pulled from the hub
		1. has versioning
	3. syntax for creating an image:
		1. `Docker container create [OPTIONS] IMAGE [COMMAND] [ARG...]`
3. #docker-container :
	1. runtime of the image
	2. . standalone executable software package which includes #applications and their dependencies
		1. multiple #docker-container s can run on the same infrastructure and share operating-systems with other containers
		2. isolated
	3. bound to a port
	4. has a virtual file system abstracted from the operating-system
4. #docker-registry
	1. open-source, #server -side service which hosts #docker-image s which can be shared easily (amongst team members)
	2. Docker has a default registry called #docker-hub 
		1. public vs private registries
	3. Commands: pull and push
		1. to build a #docker-container :
			1. `Docker pull <image>:<tag>` --> pulls an image from a docker repo
		2. to update a repo:
			1. `Docker push <image>:<tags>`

## Usage:
To set up an application with Docker:

### Create Dockerfile:
Add the following:
```dockerfile
FROM <image>:<tag> # The base image for the container ex: ubuntu:latest

WORKDIR /app #Docker will create this directory to work from
COPY . . # This will copy everything in the current directory into the image

ENTRYPOINT ["/bin/bash"] # This designates bash as the interface when live

# Alternative to ENTRYPOINT:
CMD ["node", "example.js"] # This command will execute on runtime
```

### Build and Run the Image:
```bash
sudo docker build -t <container name> .
# -t sets the name from a string/array
sudo docker run -it <container name> 
# -it allows you to interact w/ the container when it is running
```
The `.` at the end of the first command points to the directory in which the Dockerfile is located, in this case the current directory

#### Mounting host directories into container:
```bash
# in the run command:
sudo docker run --mount type=bind,source="$(pwd)/dir",target=/app/dir --name <container name> <container name>
# $(pwd) is the current host directory
# dir is the example directory which will be mounted from the host
# /app/dir is the target directory when the container runs
```

### Manipulating running containers:
#### List all containers:
```bash
sudo docker container ls
CONTAINER ID   IMAGE     COMMAND   CREATED   STATUS    PORTS     NAMES
```

#### Kill specific container:
```bash
# kill using the container's name set in the run command
sudo docker kill <container name>
```

#### Kill all container processes:
```bash
sudo docker system prune -a
```

#### Create a shell into a running container:
```bash
sudo docker exec -it <container name> sh
# -it is interactive mode
```
You can also execute a more provisioned shell such as bash using this command instead:
```bash
docker exec -it <container name> /bin/bash
```

#### See the logs of a running container:
```bash
sudo docker logs <container name> -f
# -f stands for "--follow" / follow log output
```

>[!links]
>https://docs.docker.com/get-started/
>
>https://www.youtube.com/watch?v=rOTqprHv1YE
>
>https://www.youtube.com/watch?v=3c-iBn73dDE
