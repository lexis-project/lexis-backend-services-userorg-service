# lexis-backend-services-userorg-service

The UserOrg service behind the LEXIS PORTAL manages the creation, deletion, listing, and update of the following data related to LEXIS:
- Users
- Organizations
- Projects
- HPCResources

## Acknowledgement
This code repository is a result / contains results of the LEXIS project. The project has received funding from the European Union’s Horizon 2020 Research and Innovation programme (2014-2020) under grant agreement No. 825532.


## Capabilities

The service implements a RESTful API using the golang implementation of Swagger, to be precise we're using the Stratoscale implementation.

The service is able to sync itself against keycloak (WIP: partially working) and check for valid keycloak tokens for its usage.


## Building

The building of the service is carried by a multistage docker build, we build everything in an image containing everything needed to build Golang applications
and then the executable is moved to a new image that contains the bareminimum starting from the scratch image.

Within the folder build at the root of the repo there's a script call start.sh, it's invokation admits "Dev" as parameter.
Running the script with the parameter will use the local version in the repository as the base for the building of the service's docker image,
however doing it without providing it will make the building of the service taking everything from sources.

```
./start.sh [Dev]
```

The initial branch used when building from sources is "master", it can be changed with a few other parameters by editing the script.


## Runing

Within the folder run at the root of the repo there's a docker-compose sample file and a config.toml sample file.
Once configured with appropriate data to start the service just issue the following comand:

```
docker-compose up -d
```

Within the folder Utils there's also a couple of scripts to generate self-signed certificates and keycloak tokens, but they might need some work out.
Same goes for the system-tester (WIP: some more tests should be created) script which only contains a basic test of the system.


# Useful links

- Fast overview of golang: https://learnxinyminutes.com/docs/go/
- Swagger generation tool: https://github.com/Stratoscale/swagger
- Golang swagger documentation: https://goswagger.io/
