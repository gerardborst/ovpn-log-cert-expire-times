# Introduction 
This project delivers a OpenVPN plugin which writes user and the certificate not after time to the plugin log.

# Getting Started
Add this line to the OpenVPN server config file:

```
plugin <directory with shared libs>/libovpn-log-cert-expire-times.so
```

# Build and Test
It can be build with:

```
make all
```

# Contribute
