# Introduction 
This project delivers a OpenVPN plugin which writes user and the not after time to a file on condition of th enumber of days the certificate is still valid.

# Getting Started
Add this line to the OpenVPN server config file:

```
plugin <directory with shared libs>/liblog-cert-expire-times.so <log file> <number of days>
```

# Build and Test
This project is an Eclipse CDT project.

It also can be build with:

```
cd [Debug|Release]
make clean install
```

# Contribute
TODO: Explain how other users and developers can contribute to make your code better. 

If you want to learn more about creating good readme files then refer the following [guidelines](https://docs.microsoft.com/en-us/azure/devops/repos/git/create-a-readme?view=azure-devops). You can also seek inspiration from the below readme files:
- [ASP.NET Core](https://github.com/aspnet/Home)
- [Visual Studio Code](https://github.com/Microsoft/vscode)
- [Chakra Core](https://github.com/Microsoft/ChakraCore)