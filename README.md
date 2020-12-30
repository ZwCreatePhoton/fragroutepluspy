<!--
*** Thanks for checking out the Best-README-Template. If you have a suggestion
*** that would make this better, please fork the repo and create a pull request
*** or simply open an issue with the tag "enhancement".
*** Thanks again! Now go create something AMAZING! :D
***
***
***
*** To avoid retyping too much info. Do a search and replace for the following:
*** CreatePhotonW, fragroutepluspy, @CreatePhotonW, email, FragroutePlusPy, Python port of Fragroute with new additions
-->



<!-- PROJECT SHIELDS -->
<!--
*** I'm using markdown "reference style" links for readability.
*** Reference links are enclosed in brackets [ ] instead of parentheses ( ).
*** See the bottom of this document for the declaration of the reference variables
*** for contributors-url, forks-url, etc. This is an optional, concise syntax you may use.
*** https://www.markdownguide.org/basic-syntax/#reference-style-links
-->
<!--
[![Contributors][contributors-shield]][contributors-url]
[![Forks][forks-shield]][forks-url]
[![Stargazers][stars-shield]][stars-url]
[![Issues][issues-shield]][issues-url]
[![MIT License][license-shield]][license-url]
[![LinkedIn][linkedin-shield]][linkedin-url]
-->


<!-- PROJECT LOGO -->
<br />
<p align="center">
  <a href="https://github.com/CreatePhotonW/fragroutepluspy">
<!--    <img src="images/logo.png" alt="Logo" width="80" height="80"> -->
  </a>

  <h3 align="center">FragroutePlusPy</h3>

  <p align="center">
    Python port of Fragroute with new additions
    <br />
<!--    <a href="https://github.com/CreatePhotonW/fragroutepluspy"><strong>Explore the docs »</strong></a> -->
    <br />
    <br />
    <!--
    <a href="https://github.com/CreatePhotonW/fragroutepluspy">View Demo</a>
    ·
    -->
    <a href="https://github.com/CreatePhotonW/fragroutepluspy/issues">Report Bug</a>
    ·
    <a href="https://github.com/CreatePhotonW/fragroutepluspy/issues">Request Feature</a>
  </p>
</p>



<!-- TABLE OF CONTENTS -->
<details open="open">
  <summary><h2 style="display: inline-block">Table of Contents</h2></summary>
  <ol>
    <li>
      <a href="#about-the-project">About The Project</a>
    </li>
    <li>
      <a href="#getting-started">Getting Started</a>
      <ul>
        <li><a href="#prerequisites">Prerequisites</a></li>
        <li><a href="#installation">Installation</a></li>
      </ul>
    </li>
    <li><a href="#usage">Usage</a></li>
    <li><a href="#roadmap">Roadmap</a></li>
    <li><a href="#contributing">Contributing</a></li>
    <li><a href="#license">License</a></li>
    <li><a href="#contact">Contact</a></li>
  </ol>
</details>



<!-- ABOUT THE PROJECT -->
## About The Project

<!--
[![Product Name Screen Shot][product-screenshot]](https://example.com)
-->

FragroutePlusPy started out as a direct Python port of Fragroute but grew as extensions of the original such as IPv6 support and original evasions were added.
This project uses [nfqueue](https://github.com/chifflier/nfqueue-bindings) to intercept packets, [dpkt](https://github.com/kbandla/dpkt) to manipulate packets, and [Scapy](https://scapy.net/) (for now) to write packets on the wire.

<!-- 
### Built With

* []()
* []()
* []()

-->



<!-- GETTING STARTED -->
## Getting Started

To get a local copy up and running follow these simple steps.

### Prerequisites

* python2

* nfqueue python bindings

    ```
    sudo add-apt-repository 'deb http://http.us.debian.org/debian stretch main contrib non-free'
    sudo apt update
    sudo apt install python-nfqueue
    ```

* python packages

    ```
    sudo pip install -r requirements.txt
    ```

### Installation

1. Clone the repo
   ```sh
   git clone https://github.com/CreatePhotonW/fragroutepluspy.git
   ```

<!-- USAGE EXAMPLES -->
## Usage

Run:

    sudo ./fragroutepluspy/fragroutepluspy.py -f fragroutepluspy/tcp_seg.conf 1.2.3.4

Where "1.2.3.4" is the IPv4 or IPv6 address of the destination.

_For more example rule scripts, please refer to the [example rule scripts](fragroutepluspy/scripts)_

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


_For more information on rule script directives, run `./fragroutepluspy/fragroutepluspy.py -?`


<!-- ROADMAP -->
## Roadmap

See the [open issues](https://github.com/CreatePhotonW/fragroutepluspy/issues) for a list of proposed features (and known issues).



<!-- CONTRIBUTING -->
## Contributing

Contributions are what make the open source community such an amazing place to be learn, inspire, and create. Any contributions you make are **greatly appreciated**.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request



<!-- LICENSE -->
## License

Distributed under the MIT License. See `LICENSE` for more information.



<!-- CONTACT -->
## Contact

CreatePhotonW - [@CreatePhotonW](https://twitter.com/CreatePhotonW)

Project Link: [https://github.com/CreatePhotonW/fragroutepluspy](https://github.com/CreatePhotonW/fragroutepluspy)



<!-- MARKDOWN LINKS & IMAGES -->
<!-- https://www.markdownguide.org/basic-syntax/#reference-style-links -->
[contributors-shield]: https://img.shields.io/github/contributors/CreatePhotonW/repo.svg?style=for-the-badge
[contributors-url]: https://github.com/CreatePhotonW/repo/graphs/contributors
[forks-shield]: https://img.shields.io/github/forks/CreatePhotonW/repo.svg?style=for-the-badge
[forks-url]: https://github.com/CreatePhotonW/repo/network/members
[stars-shield]: https://img.shields.io/github/stars/CreatePhotonW/repo.svg?style=for-the-badge
[stars-url]: https://github.com/CreatePhotonW/repo/stargazers
[issues-shield]: https://img.shields.io/github/issues/CreatePhotonW/repo.svg?style=for-the-badge
[issues-url]: https://github.com/CreatePhotonW/repo/issues
[license-shield]: https://img.shields.io/github/license/CreatePhotonW/repo.svg?style=for-the-badge
[license-url]: https://github.com/CreatePhotonW/repo/blob/master/LICENSE.txt
[linkedin-shield]: https://img.shields.io/badge/-LinkedIn-black.svg?style=for-the-badge&logo=linkedin&colorB=555
[linkedin-url]: https://linkedin.com/in/CreatePhotonW
