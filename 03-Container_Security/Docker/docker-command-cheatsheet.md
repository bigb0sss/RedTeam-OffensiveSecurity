## Docker Command Cheatsheet

#### Version

```console
$ sudo docker --version
```

#### Add User to Docker Group

```console
$ sudo usermod -aG docker <USER>
```

> **NOTE**: You need to re-login to apply the modification

#### Pulling Docker Imsage from Docker Hub

```console
$ docker pull <IMAGE NAME>

[Example]
$ docker pull alpine:3.10
```

#### Docker Search

```console
$ docker search <REPO>
```

#### Finding Containers

```console
$ docker ps          <-- Only running containers

$ docker ps -a       <-- All running/stopped containers
```

#### Docker Images

```console
$ docker images
```

#### Running Docker Container

```console
$ docker run ubuntu:14.04 echo "Hello World"
```

#### Container with Terminal

```console
$ docker run -it ubuntu:14.04 /bin/bash

-i: Tell docker to connect to STDIN on the container
-t: To get Pseudo-Terminal
```

#### Docker Detached Mode

```console
$ docker run -d --name <NAME> ubuntu:14.04 <COMMAND>

[Example]
$ docker run --name pingcontainer -d alpine:latest ping 127.0.0.1 -c 50

[Attach]
$ docker attach <NAME>
```

#### Docker Running with Memory limits

```console
# Limiting the Memory usage of the host OS upto 4 megabites

$ docker run -d --memory 4m --name testDocker alpine:latest sleep 50000
```

#### Running Web App in Container

```container
$ docker run -d -P nginx:alpine    <-- This will choose a random Port
$ docker run -d -P 8000:80 nginx:alpine
$ docker ps
```

#### Docker Commit

```console
$ docker run --name <NAME> -it ubuntu:14.04 /bin/bash
mkdir -p /data/important
echo "pass" > /data/important/cred.txt
exit

$ docker ps -a
$ docker commit <NAME> bgib0ss/test:1.0
$ docker images

$ docker run -it bgib0ss/test:1.0 /bin/bash
cat /data/important/cred.txt
```

#### Managing Images and Containers

```console
[List all containers]
$ docker ps -a

[Start a container]
$ docker start <CONTAINER ID>

[Stop a container]
$ docker stop <CONTAINER ID>

[Remove a container]
$ docker rm <CONTAINER ID>

[Deleting Local Images]
$ docker rmi <IMAGE ID>
```

#### Push Images to Docker Hub

```console
$ docker push [repo:tag]
```

#### Tag Images

```console
[Rename the Image]
$ docker tag [image ID] [repo:tag]

OR

$ docker tag [local repo:tag] [Docker Hub repo:tag]
```

#### Volumes

```console
[Use of Volume]
• De-couple the data that is stored from the container which created the data
• Good for sharing data between containers
  ◦ Can setup a data containers which has a volume you mount in other containers
• Mounting folders from the host is good for testing purposes but generally not recommended for production use

[New Container w/ Mounting the /volume File System]
$ docker run -d -P -v /volume nginx:alpine
```

#### Docker Networking

```console
[Map Port 80 on the Container to 8080 on the Host]
$ docker run -d -p 8080:80

[Use Auto Mapping Port (49153 - 65535)]
$ docker run -d -P nginx:alpine
```

#### Linking Containers

```console
[Create the source container using the postgres]
$ docker run -d --name database mysql:5.7

[Create the recipient container and link it]
$ docker run -d -P --name website --link database:db nginx:alpine
```

#### Docker Log

```console
$ docker logs -f --tail 2 <Container NAME>
```

#### Dockerfile

```yaml
[Dockerfile Example]
FROM alpine:3.10        <-- Pulling alpine:3.10 from the Docker hub
COPY /etc/hosts /tmp    <-- Copying the file
CMD ["/bin/sh"]         <-- Run /bin/sh

# To build that Dockerfile
$ docker build -t bigb0ss/image1:0.1 .

# Running the created docker image
$ docker run --rm -it bigb0ss/image1:0.1
```
