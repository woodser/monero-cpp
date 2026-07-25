# Monero C++ Library

A C++ library for creating Monero applications using RPC or native bindings to [monero v0.18.5.1 'Fluorine Fermi'](https://github.com/monero-project/monero/tree/v0.18.5.1).

* Supports fully client-side wallets by wrapping [wallet2.h](https://github.com/monero-project/monero/blob/master/src/wallet/wallet2.h).
* Supports wallet and daemon RPC clients.
* Supports multisig, view-only, and offline wallets.
* Uses a clearly defined [data model and API specification](https://woodser.github.io/monero-java/monero-spec.pdf) intended to be intuitive and robust.
* Query wallet transactions, transfers, and outputs by their properties.
* Receive notifications when wallets sync, send, or receive.
* Tested by over 100 tests in [monero-java](https://github.com/woodser/monero-java) and [monero-ts](https://github.com/woodser/monero-ts) using JNI and WebAssembly bindings.

## Sample code

```c++
// connect to daemon
monero_daemon* daemon = new monero_daemon_rpc("http://localhost:38081", "superuser", "abctesting123");
uint64_t height = daemon->get_height();                            // 1523651
vector<shared_ptr<monero_tx>> txs_in_pool = daemon->get_tx_pool(); // get transactions in the pool
for (const shared_ptr<monero_tx>& tx : txs_in_pool) monero_utils::free(tx);

// create wallet from mnemonic phrase using native bindings to monero-project
monero_wallet_config wallet_config;
wallet_config.m_path = "sample_wallet_full";
wallet_config.m_password = "supersecretpassword123";
wallet_config.m_network_type = monero_network_type::STAGENET;
wallet_config.m_server = make_shared<monero_rpc_connection>("http://localhost:38081", "superuser", "abctesting123");
wallet_config.m_seed = "hefty value scenic...";
wallet_config.m_restore_height = 573936;
monero_wallet* wallet_full = monero_wallet_full::create_wallet(wallet_config);

// synchronize the wallet and receive progress notifications
struct : monero_wallet_listener {
  void on_sync_progress(uint64_t height, uint64_t start_height, uint64_t end_height, double percent_done, const string& message) {
    // feed a progress bar?
  }
} my_sync_listener;
wallet_full->sync(my_sync_listener);

// synchronize in the background every 5 seconds
wallet_full->start_syncing(5000);

// receive notifications when funds are received, confirmed, and unlocked
struct : monero_wallet_listener {
  void on_output_received(const monero_output_wallet& output) {
    uint64_t amount = output.m_amount.get();
    string tx_hash = output.m_tx->m_hash.get();
    bool is_confirmed = output.m_tx->m_is_confirmed.get();
    bool is_locked = dynamic_pointer_cast<monero_tx_wallet>(output.m_tx)->m_is_locked.get();
    FUNDS_RECEIVED = true;
  }
} my_listener;
wallet_full->add_listener(my_listener);

// connect to wallet RPC and open wallet
monero_wallet_rpc* wallet_rpc = new monero_wallet_rpc("http://localhost:38083", "rpc_user", "abc123");
wallet_rpc->open_wallet("sample_wallet_rpc", "supersecretpassword123");
string primary_address = wallet_rpc->get_primary_address();       // 555zgduFhmKd2o8rPUz...
uint64_t balance = wallet_rpc->get_balance();                     // 533648366742
vector<shared_ptr<monero_tx_wallet>> txs = wallet_rpc->get_txs(); // get transactions containing transfers to/from the wallet
monero_utils::free(txs);

// send funds from RPC wallet to full wallet
monero_tx_config tx_config;
tx_config.m_account_index = 0;
tx_config.m_address = wallet_full->get_address(1, 0);
tx_config.m_amount = 250000000000; // send 0.25 XMR (denominated in atomic units)
tx_config.m_relay = false; // create transaction and relay to the network if true
shared_ptr<monero_tx_wallet> created_tx = wallet_rpc->create_tx(tx_config);
uint64_t fee = created_tx->m_fee.get(); // "Are you sure you want to send... ?"
wallet_rpc->relay_tx(*created_tx); // relay the transaction
monero_utils::free(created_tx);

// recipient receives unconfirmed funds within 5 seconds
this_thread::sleep_for(chrono::seconds(5));
assert(FUNDS_RECEIVED);

// save and close wallet
wallet_full->close(true);
delete wallet_full;
delete wallet_rpc;
delete daemon;
```

## Documentation

* [API documentation](https://woodser.github.io/monero-cpp/doxygen/annotated.html)
* [API and model overview with visual diagrams](https://woodser.github.io/monero-java/monero-spec.pdf)
* [monero-ts documentation](https://github.com/woodser/monero-ts#documentation) provides additional documentation which translates to monero-cpp

## Using monero-cpp in your project

This project may be compiled as part of another application or built as a shared or static library.

For example, [monero-java](https://github.com/woodser/monero-java) compiles this project to a shared library to support Java JNI bindings, while [monero-ts](https://github.com/woodser/monero-ts) compiles this project to WebAssembly binaries.

### Linux

1. Clone the project repository if applicable: `git clone --recurse-submodules https://github.com/woodser/monero-cpp.git`
2. Update dependencies: `sudo apt update && sudo apt install build-essential cmake pkg-config libssl-dev libzmq3-dev libunbound-dev libsodium-dev libunwind8-dev liblzma-dev libreadline6-dev libexpat1-dev libpgm-dev qttools5-dev-tools libhidapi-dev libusb-1.0-0-dev libprotobuf-dev protobuf-compiler libudev-dev libboost-chrono-dev libboost-date-time-dev libboost-filesystem-dev libboost-locale-dev libboost-program-options-dev libboost-regex-dev libboost-serialization-dev libboost-system-dev libboost-thread-dev python3 ccache doxygen graphviz nettle-dev libevent-dev`
3. Follow instructions to install [unbound](https://unbound.docs.nlnetlabs.nl/en/latest/getting-started/installation.html) for Linux to your home directory (e.g. `~/unbound-1.22.0`).

    For example, install expat:
    ```
    cd ~
    wget https://github.com/libexpat/libexpat/releases/download/R_2_4_8/expat-2.4.8.tar.bz2
    tar -xf expat-2.4.8.tar.bz2
    sudo rm expat-2.4.8.tar.bz2
    cd expat-2.4.8
    ./configure --enable-static --disable-shared
    make
    sudo make install
    cd ../
    ```

    For example, install unbound:
    ```
    cd ~
    wget https://www.nlnetlabs.nl/downloads/unbound/unbound-1.22.0.tar.gz
    tar xzf unbound-1.22.0.tar.gz
    sudo apt update
    sudo apt install -y build-essential
    sudo apt install -y libssl-dev
    sudo apt install -y libexpat1-dev
    sudo apt-get install -y bison
    sudo apt-get install -y flex
    cd unbound-1.22.0
    ./configure --with-libexpat=/usr --with-ssl=/usr --enable-static-exe
    make
    sudo make install
    cd ../
    ```
4. Build monero-project, located as a submodule at ./external/monero-project. Install [dependencies](https://github.com/monero-project/monero#dependencies) as needed for your system, then build with: `make release-static -j8`
5. Link to this library's source files in your application, or build monero-cpp to a shared library in ./build: `./bin/build_libmonero_cpp.sh`

### macOS

1. Clone the project repository if applicable: `git clone --recurse-submodules https://github.com/woodser/monero-cpp.git`
2. Follow instructions to install [unbound](https://unbound.docs.nlnetlabs.nl/en/latest/getting-started/installation.html) for macOS to your home directory (e.g. `~/unbound-1.22.0`).

    For example:
    ```
    cd ~
    wget https://nlnetlabs.nl/downloads/unbound/unbound-1.22.0.tar.gz
    tar xzf unbound-1.22.0.tar.gz
    cd ~/unbound-1.22.0
    ./configure --with-ssl=/opt/homebrew/Cellar/openssl@3/3.4.0/ --with-libexpat=/opt/homebrew/Cellar/expat/2.6.4
    make
    sudo make install
    ```
3. Build monero-project, located as a submodule at ./external/monero-project. Install [dependencies](https://github.com/monero-project/monero#dependencies) as needed for your system, then build with e.g.: `make release-static -j6`
4. Link to this library's source files in your application, or build monero-cpp to a shared library in ./build: `./bin/build_libmonero_cpp.sh`

### Windows

1. Download and install [MSYS2](https://www.msys2.org/).

    Note: If the latest version cannot be installed, use a historical version: https://github.com/msys2/msys2-installer/releases/download/2024-12-08/msys2-x86_64-20241208.exe
2. Press the Windows button and launch `MSYS2 MINGW64` for 64-bit systems or `MSYS2 MINGW32` for 32-bit.
3. Update packages: `pacman -Syu`, confirming at the prompts.
4. Relaunch MSYS2 (if necessary) and install dependencies:

    For 64-bit:

     ```
     pacman -S mingw-w64-x86_64-toolchain mingw-w64-x86_64-cmake mingw-w64-x86_64-openssl mingw-w64-x86_64-zeromq mingw-w64-x86_64-libsodium mingw-w64-x86_64-hidapi mingw-w64-x86_64-unbound mingw-w64-x86_64-protobuf mingw-w64-x86_64-libusb mingw-w64-x86_64-ntldd git make gettext base-devel wget
     wget https://repo.msys2.org/mingw/mingw64/mingw-w64-x86_64-icu-75.1-2-any.pkg.tar.zst
     pacman -U mingw-w64-x86_64-icu-75.1-2-any.pkg.tar.zst
     wget https://repo.msys2.org/mingw/mingw64/mingw-w64-x86_64-boost-1.87.0-3-any.pkg.tar.zst
     pacman -U mingw-w64-x86_64-boost-1.87.0-3-any.pkg.tar.zst
     ```

     For 32-bit:

     ```
     pacman -S  mingw-w64-i686-toolchain make mingw-w64-i686-cmake mingw-w64-i686-boost mingw-w64-i686-openssl mingw-w64-i686-zeromq mingw-w64-i686-libsodium mingw-w64-i686-hidapi mingw-w64-i686-unbound mingw-w64-i686-protobuf git mingw-w64-i686-libusb gettext base-devel mingw-w64-i686-icu
     ```
5. Clone repo if installing standalone (skip if building as part of another repo like monero-java or monero-ts): `git clone --recurse-submodules https://github.com/woodser/monero-cpp.git`
6. In ./external/monero-project/Makefile, add `-D USE_DEVICE_TREZOR=OFF` to the `release-static-win64` target (or `release-static-win32` for 32-bit).
7. Build monero-project, located as a submodule at ./external/monero-project. Install [dependencies](https://github.com/monero-project/monero#dependencies) as needed for your system, then build with:

    For 64-bit: `make release-static-win64`
    
    For 32-bit: `make release-static-win32`
8. Link to this library's source files in your application, or build monero-cpp to a shared library (libmonero-cpp.dll) in ./build: `./bin/build_libmonero_cpp.sh`

## Running sample code and tests

1. Download and install [Monero CLI](https://web.getmonero.org/downloads/).
2. Start monerod, e.g.: `./monerod --stagenet` (or use a remote daemon).
3. Start monero-wallet-rpc, e.g.: `./monero-wallet-rpc --daemon-address http://localhost:38081 --stagenet --rpc-bind-port 38083 --rpc-login rpc_user:abc123 --wallet-dir ./`
4. In CMakeLists.txt, set the flags to build:

         set(BUILD_LIBRARY ON)
         set(BUILD_SAMPLE ON)
         set(BUILD_SCRATCHPAD ON)
         set(BUILD_TESTS ON)
5. `./bin/build_libmonero_cpp.sh`
6. Run the app, for example: `./build/sample_code`

## Related projects

* [monero-java](https://github.com/woodser/monero-java)
* [monero-ts](https://github.com/woodser/monero-ts)

## License

This project is licensed under MIT.

## Donations

If this library has been valuable to you, please consider donating to support its continued development.

<p align="center">
	<img src="donate.png" width="115" height="115"/><br>
	<code>46FR1GKVqFNQnDiFkH7AuzbUBrGQwz2VdaXTDD4jcjRE8YkkoTYTmZ2Vohsz9gLSqkj5EM6ai9Q7sBoX4FPPYJdGKQQXPVz</code>
</p>
