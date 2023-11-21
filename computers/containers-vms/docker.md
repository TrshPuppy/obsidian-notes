
# Docker
Docker [containers](computers/containers-vms/containers.md) sit on top of and uses the host's [operating-system](/computers/operating-system.md). Although Docker can be used on both [Windows](/computers/windows) and [Linux](/computers/linux), the software *prefers linux-based* OS's.

Compared to [virtual machines](/computers/containers-vms/virtual-machines.md), Docker containers are *lighter* b/c they *piggyback on the pre-existing host OS*. This allows them to:
- boot faster
- occupy less [memory](computers/memory/memory.md)
	- data volumes can be shared between containers
## Docker vs virtual-machines:
Operating-systems have two components: 
1. Kernel (communicates w/ the hardware)
2. Applications (help to run the kernel and create an interface for humans to interact w/ the computer)
### Virtualization:
Virtual-machines and Docker *virtualize different parts of the OS*. While Docker virtualizes *the application layer*, Virtual machines virtualize *the complete operating system* including the kernel and applications.

Because Docker only virtualizes one layer of the OS, it depends on the host's kernel to run.
## Docker Engine
The Docker engine is installed on the host machine and allows the docker containers to be built and run using Docker services. The engine is *installed on the host's hardware* and contains the *Docker server Daemon*. The Engine can be accessed by a user from the host's CLI.

The engine controls how the *Docker Client* is created and uses a client-server architecture. The client and server communicate using the [*REST-API*](/coding/APIs/REST-API.md).
## Components of Docker:
Docker uses a client-server architecture. The client talks to the Docker daemon (server) using the REST-API. The two communicate using either [UNIX sockets](/computers/linux/unix-sockets.md) or over a [network interface](/networking/OSI/MAC-addresses.md).
### Server
The Docker server does most of the work regarding building, running and distributing docker containers. It can be run on the same system as the client or the Docker client can be configured to communicate w/ a remote daemon.
### Client
The client is where the *Docker daemon* and *registry service* are run from. It's accessed via the command line and is where the user can build docker images and run docker containers.

The docker commands run from the CLI by the user are sent to the docker server.
#### Docker Image
Docker images are templates with instructions which *used to build docker containers*. The images are built via the *Dockerfile*; a text file w/ commands and configurations used to build the image.
#### Docker Container
The Docker container is the *runtime of a Docker Image*. It's a standalone executable which includes all the applications and dependencies needed by the container. It also has a virtual filesystem abstracted from the host's OS (however you need to use [*volumes*](/computers/containers-vms/docker.md#Mmounting-volumes) with Docker for files in the container to persist once the container is exited.)

If multiple docker containers are running at the same time, they use the same infrastructure and share operating system components w/ each other.
### Docker Registries
Docker Registries are used to store Docker images. *Docker Hub* is a public registry you can use to look for images (which is the default), but you can also run your own *private registry.*
#### Docker Hub
Once a Dockerfile is made, it can be stored in a repository called [*Docker Hub.*](https://registry.hub.docker.com/) Just like other [distributed version control](/coding/version-control.md) systems, images can be pulled from the hub, which also supports versioning.
##### Commands:
You can use the `docker run`, `docker pull` and `docker push` commands to pull, push, and run images from Docker Hub (or other registries).
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
### Mounting & Volumes:
Docker allows you to mount volumes/ share directories b/w host and guest in a few different ways. These include volumes, tmpfs, and bind mounts. Of these, volumes are considered the best way to persist data beyond the life of the container.

Volumes are preferred b/c, when used, a separate filesystem is created and maintained by Docker w/i the host's filesystem.
![](computers/computers-pics/docker-1.png)
> [Docker](https://docs.docker.com/storage/volumes/)
#### Create Volumes:
If you start a container w/ a volume which doesn't exist yet, Docker will create it for you.
##### `--mount` flag:
```bash
docker run -d \
  --name devtest \
  --mount source=myvol2,target=/app \
  nginx:latest
```
In this example, the volume `myvol2` is created and linked to the `/app/` directory inside the container.
##### Creating a mount w/ `docker run` (example):
```bash
# in the run command:
sudo docker run --mount type=bind,source="$(pwd)/dir",target=/app/dir --name <container name> <container name>
# $(pwd) is the current host directory
# dir is the example directory which will be mounted from the host
# /app/dir is the target directory when the container runs
```
#### Verifying/ Inspecting a mount:
You can make sure your volume mounted correctly on a running container by using `docker inspect <container name>` command:
```bash
"Mounts": [
    {
        "Type": "volume",
        "Name": "myvol2",
        "Source": "/var/lib/docker/volumes/myvol2/_data",
        "Destination": "/app",
        "Driver": "local",
        "Mode": "",
        "RW": true,
        "Propagation": ""
    }
],
```
#### Removing mounts/ volumes:
You can list docker volumes using the `docker volume` command:
```bash
docker volume ls
local               my-vol
```
You can also *remove* volumes w/ the `docker volume` command
```bash
docker volume rm my-vol
```
You can also use:
```bash
docker volume prune # <---- removes all unused volumes
```
#### Backing up volumes:
You can tell Docker to backup a volume in the `docker run` command. That way, when the container stops, the data in the volume is backed up:
```bash
docker run --rm --volumes-from dbstore -v $(pwd):/backup ubuntu tar cvf /backup/backup.tar /dbdata
```
In this command:
- A new container is launched which *mounts the volumes from a different container* called `dbstore`
- The local host directory is mounted as `/backup`
- A command is passed which *tars* the contents of `dbdata` (volume) into a file called `backup.tar` in the `/backup` mounted directory.
##### Restoring volumes (from a backup):
Backups are good because they allow you to *restore the volume* that was backed up. You can either restore the volume to the same container, or to a new one.
```bash
docker run -v /dbdata --name dbstore2 ubuntu /bin/bash
# '-v' is similar to the '--mount' flag
```
The file then needs to be *un-tarred* in the new container's volume:
```bash
docker run --rm --volumes-from dbstore2 -v $(pwd):/backup ubuntu bash -c "cd /dbdata && tar xvf /backup/backup.tar --strip 1"
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

>[!Resources]
> - [Docker: Get Started](https://docs.docker.com/get-started/)
> - [Simplilearn: What is Docker](https://www.youtube.com/watch?v=rOTqprHv1YE)
> - [Tech World w/ Nana: Docker Tutorial](https://www.youtube.com/watch?v=3c-iBn73dDE)
> - [Docker: Volumes](https://docs.docker.com/storage/volumes/#back-up-restore-or-migrate-data-volumes)
> - [Docker Hub](https://hub.docker.com/)
