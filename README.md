# AppLimiter

AppLimiter is a simple tool designed to restrict specific applications to only communicate with designated server IPs and ports. This can be particularly useful for limiting user activity within a LAN environment, ensuring that only authorized applications can access certain network resources.

## Features

- **Application Limitation**: Restrict specific applications to communicate only with designated server IP and port.
- **Network Control**: Helps in managing and controlling user activity within a LAN.
- **Simple Command Usage**: Easily configure which applications are allowed to access specific network resources.

## Requirements

This project requires the WinDivert library to capture network packets. You need to configure WinDivert properly to ensure the application functions as expected. [WinDivert](https://reqrypt.org/windivert.html) is a user-mode packet capture and network driver for Windows, which allows you to intercept and modify network packets.

## Usage

To use AppLimiter, simply run the following command:

```sh
./applimiter [appname] [serverip] [serverport]
