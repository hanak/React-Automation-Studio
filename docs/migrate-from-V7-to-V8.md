# Migrate to V8.0.0
*If you use the standard RAS containers and latest version of docker this has no impact on you .*


RAS V8.0.0 includes breaking changes mainly due to backend package updates and docker orchestration changes.

Python packagement has been changed to UV with a local cache amongst all docker containers.



The latest version of docker is now also required. Repo has been tested with 28.1.1.

The epicsbase container is the starting point for  all the backend containers.

It contains epics and python. The container is now also based on Ubuntu 24.0.4. There is a build arg to change the base image.

If you need to update you local compose files, to reference the new epicsbase you need to add: 
```
    ...
    build:
        additional_contexts:
            epicsbase: "service:epicsbase"
    ...
    depends_on:
      - epicsbase
    ...

```




Enable docker compose bake for major speed improvements:
 https://docs.docker.com/compose/how-tos/dependent-images/

 Bake can be selected as the default builder by editing your ```$HOME/.docker/config.json``` config file:

```
{
  ...
  "plugins": {
    "compose": {
      "build": "bake"
    }
  }
  ...
}

```




