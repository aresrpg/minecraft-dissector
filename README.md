# Wireshark Minecraft Dissector

A Wireshark dissector for the Minecraft protocol, written in C

# Installation

A version for Wireshark 3.4 is precompiled for easier installation

## Windows

- Download the packet-minecraft.dll from the latest [release](https://github.com/aresrpg/minecraft-dissector/releases/latest)
- Put it inside your [Wireshark Plugin Folder](https://www.wireshark.org/docs/wsug_html_chunked/ChPluginFolders.html): `%APPDATA%\Wireshark\plugins\3.4\epan` (Create the required folders if they don't exist)

## Linux

- Download the packet-minecraft.so from the latest [release](https://github.com/aresrpg/minecraft-dissector/releases/latest)
- Put it inside your [Wireshark Plugin Folder](https://www.wireshark.org/docs/wsug_html_chunked/ChPluginFolders.html): `~/.local/lib/wireshark/plugins/3.4/epan` (Create the required folders if they don't exist)

# Usage

This dissector will automatically decode packets on tcp port 25565 if your connection use another port you need to use `Decode As -> Minecraft`

You can use the `minecraft` filter to only display minecraft packets

# Build from source

## Dependencies

```bash
apt install make gcc pkg-config wireshark-dev nodejs # Ubuntu
nix-shell -p gnumake wireshark.dev pkg-config glib.dev nodejs_22 libgcrypt # Nixos
```

### Clone and compile

```bash
$ git clone https://github.com/aresrpg/minecraft-dissector
$ git submodule update --init
$ cd minecraft-dissector
$ make # Build the plugin
$ make install # Will install the plugin in your local plugin folder
```
