emqx_data_converter
=====

A CLI (implemented as escript) to convert EMQX 4.4 JSON backup files to EMQX 5.1+ tar.gz archive files.

Currently, the following configs/data are converted:

- Builtin (Mnesia) authn/authz (both data and config)
- Internal (file) authz
- Redis authn/authz config
- MySQL authn/authz config
- PostgreSQL authn/authz config
- HTTP authn/authz config
- MongoDB authn/authz config
- JWT authn config
- PSK authentication data
- Blacklist (banned clients)
- API Keys (Applications)
- Rules and resources(bridges), except for:
  - IoTDB
  - GCP Pubsub
  - republish rules
  - Consumer bridges (modules in EMQX 4.4)

Incompatibilities that cannot be handled by the converter automatically are printed to the stdout,
please don't ignore these warnings, as they may be helpful to correct compatibility issues afterwards.

# Quick start GNU/Linux

Download `emqx_data_converter.tar.gz` from the latest GitHub release and unpack it.
The converter is ready to be used, no dependencies need to be installed (verified on Ubuntu 20.04, 22.04, Debian 12).
```
tar -xf emqx_data_converter.tar.gz
emqx_data_converter/bin/emqx_data_converter <input file path>
```
# Usage

Basic usage:
```
emqx_data_converter <input file path>
```
where `<input file path>` is a path to  EMQX 4.4 backup JSON file.
This will produce EMQX 5.1+ backup file in the current working directory,
the output file name will be printed out to the console:
```
[INFO] Converted to EMQX 5.1 backup file: /conv/emqx-export-2023-07-13-14-48-58.895.tar.gz
```
Output directory can be set with `-o <dir path>` or `--output-dir <dir path>` option.
Please note that the converter always needs write access to the current working directory (even when `-o <output dir>` is used),
because it uses to create some temporary files.

Version:
```
emqx_data_converter -v
emqx_data_converter --version
```
Help:
```
emqx_data_converter -h
emqx_data_converter --help
```
Help command contains info about several 'business logic' options, please make sure to read it.

# Build

## Prerequisites

Install the following dependencies:

- Erlang/OTP 25+
- Rebar3
- Docker (optional)

## Compile emqx-data-converter
```
rebar3 escriptize
```
## Docker example
```
docker run -it -v <path to emqx-data-converter>:/emqx-data-converter -v <path to input files dir>:/input erlang:25 bash
```
where:
- `<path to emqx-data-converter>` - a path to the cloned `emqx-data-converter`
- `<path to input files dir>` - a path to the directory where EMQX 4.4 backup JSON files are stored

```
cd /emqx-data-converter
rebar3 escriptize
_build/default/bin/emqx_data_converter /input/emqx-export-2023-7-13-15-52-15.json
```

# Bundle the escript with Erlang/OTP
```
./package
```
`package` script will produce `_build/emqx_data_converter.tar.gz.` It is the escript bundled with Erlang/OTP,
which can be copied to and used on another machine without the need to install Erlang/OTP and Rebar3.
Note: the target machine OS must match the OS on which the package was created, otherwise it won't work.
