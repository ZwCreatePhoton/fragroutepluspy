Install Dependencies:

    sudo add-apt-repository 'deb http://http.us.debian.org/debian stretch main contrib non-free'
    sudo apt update
    sudo apt install python-nfqueue
    sudo pip install -r requirements.txt

Run:

    sudo ./fragroutepluspy.py -f rulescript.conf dst [mac] [-pcap infilepath outfilepath]

Where "dst" is an IPv4 or IPv6 address.

Where "mac" is a hardware mac address using colons (":")

Directives:

    # comment

    #define <name>
    <value>
    #enddefine

    print

    echo string

    dup [first|last|random|<idx>] <prob>

    drop [first|last|random|<idx>] <prob>

    delay [first|last|random|<idx>] <ms>

    apply [first|last|random|<idx>] <prob> [/path/to/some.conf|@conf_var]

    order [reverse|random]

    ip_frag <size> [old|new]

        fragmentation favor old no longer works on Windows 7 and above.
        IPv4 ONLY

    ip_ttl <ttl>

        IPv4 ONLY

    ip_tos <tos>

        IPv4 ONLY

    ip_opt [lsrr|ssrr <ptr> <ip-addr> ...] | [raw <byte stream>]

        IPv4 ONLY

    ip_chaff [dup|opt|<ttl>|cksum|conf [/path/to/some.conf|@conf_var] [before|after|sandwich]

        IPv4 ONLY

    tcp_seg <size> [old|new|windows_new [<size2>]|windows_new_old <size2>]

    tcp_chaff [cksum|null|paws|rexmit|seq|syn|<ttl>|opt|timestamp|conf [/path/to/some.conf|@conf_var]] [before|after|sandwich]

        PAWS assumes TCP segments have monotonically increasing TCP timestamps
        <ttl>: IPv4 ONLY
        opt: IPv4 ONLY
        timestamp: IPv4 ONLY

    tcp_opt [mss|wscale] <size>

    if "(conditional):" [/path/to/true.conf|@conf_var] [/path/to/false.conf|@conf_var]

        conditional is a python expression

    ip6_frag <size>

        IPv6 ONLY

    ip6_chaff [dup|conf [/path/to/some.conf|@conf_var]] [before|after|sandwich]

        IPv6 ONLY

    ip6_qos <tc> <fl>

        IPv6 ONLY

    ip6_qos <tc> <fl>

        IPv6 ONLY

    ip6_opt raw <type> <byte stream> [fragmentable|unfragmentable]

        IPv6 ONLY




Supports the use of environment variables in configs.

    ip_frag $FRAG_SIZE
