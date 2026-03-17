# The Network Simulator, Version 3

[![codecov](https://codecov.io/gh/nsnam/ns-3-dev-git/branch/master/graph/badge.svg)](https://codecov.io/gh/nsnam/ns-3-dev-git/branch/master/)
[![Gitlab CI](https://gitlab.com/nsnam/ns-3-dev/badges/master/pipeline.svg)](https://gitlab.com/nsnam/ns-3-dev/-/pipelines)
[![Github CI](https://github.com/nsnam/ns-3-dev-git/actions/workflows/per_commit.yml/badge.svg)](https://github.com/nsnam/ns-3-dev-git/actions)

[![Latest Release](https://gitlab.com/nsnam/ns-3-dev/-/badges/release.svg)](https://gitlab.com/nsnam/ns-3-dev/-/releases)

## Table of Contents

* [Building ns-3](#building-ns-3)
* [Testing ns-3](#testing-ns-3)
* [Running ns-3](#running-ns-3)
* [Debugging ns-3](#debugging-ns-3)
* [Working with the Development Version of ns-3](#working-with-the-development-version-of-ns-3)
* [ns-3 App Store](#ns-3-app-store)

> **NOTE**: Much more substantial information about ns-3 can be found at
<https://www.nsnam.org>

## Building ns-3

To configure ns-3 with examples and tests enabled, run the following command on the ns-3 main directory:

```shell
./ns3 configure --enable-examples --enable-tests
```

Then, build ns-3 by running the following command:

```shell
./ns3 build
```

By default, the build artifacts will be stored in the `build/` directory.

## Testing ns-3

ns-3 contains test suites to validate the models and detect regressions.
To run the test suite, run the following command on the ns-3 main directory:

```shell
./test.py
```

## Running ns-3

On recent Linux systems, once you have built ns-3 (with examples enabled), it should be easy to run the mymain.cc with the following command, such as:

```shell
./ns3 run mymain -- mix/config.txt
```

That program has a txt file `mix/config.txt` to config the program, 
file `mix/attacker.txt` set the flow of attacker,
file `mix/npa_flow.txt` set the flow of normal host,
file `mix/npa_topo.txt` set the topo of the mymain.cc.

If you want monitor the flow speed of the node i, and get a txt file recording the speed:
set `rdmaHw->m_monitor_flag` to true in `scratch/mymain.cc`, then you can get `mixmonitor/agent_i.txt`.
If you want to draw the picture of speed, run `mixmonitor/draw.py`.

Attacker's packet size usually smaller than normal packet (normal size is packet_payload_size), so:
set `rdmaHw->SetAttribute("Mtu", UintegerValue(500))` in `scratch/mymain.cc`.

## Debugging ns-3

If you need to debug the ERROR, run the following command, such as:

```shell
gdb build/scratch/ns3.44-mymain-default
```

After you get in the gdb, set your args by running the following command:

```shell
(gdb) set args mix/config.txt
```

Then, run the program to find the bug:

```shell
(gdb) run
```

Finally, read the Backtrace to find where the ERROR is:

```shell
(gdb) bt
```

## Working with the Development Version of ns-3

If you want to download and use the development version of ns-3, you need to use the tool `git`. 
A quick and dirty cheat sheet is included in the manual, but reading through the Git tutorials found in the Internet is usually a good idea if you are not familiar with it.

If you have successfully installed Git, you can get a copy of the development version with the following command:

```shell
git clone https://gitlab.com/nsnam/ns-3-dev.git
```

However, we recommend to follow the GitLab guidelines for starters, that includes creating a GitLab account, forking the ns-3-dev project under the new account's name, and then cloning the forked repository.
You can find more information in the [manual](https://www.nsnam.org/docs/manual/html/working-with-git.html).

## ns-3 App Store

The official [ns-3 App Store](https://apps.nsnam.org/) is a centralized directory listing third-party modules for ns-3 available on the Internet.

More information on how to submit an ns-3 module to the ns-3 App Store is available in the [ns-3 App Store documentation](https://www.nsnam.org/docs/contributing/html/external.html).
