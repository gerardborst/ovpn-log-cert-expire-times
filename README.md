# Introduction 
This project delivers a OpenVPN plugin which writes user and the certificate not after time to the plugin log.

# Getting Started
Add this line to the OpenVPN server config file:

```
plugin <directory with shared libs>/liblog-cert-expire-times.so
```

# Build and Test
This project is an Eclipse CDT project.

It also can be build with:

```
cd [Debug|Release]
make clean install
```

# Contribute
