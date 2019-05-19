
# HTTP Filter

eBPF application that parses HTTP packets and extracts (and prints on screen) the URL contained in the GET/POST request.

[eBPF HTTP Filter - Short Presentation](https://github.com/iovisor/bpf-docs/blob/master/ebpf_http_filter.pdf)

## Usage Example


    $ sudo python http-parse-complete.py 
    GET /pipermail/iovisor-dev/ HTTP/1.1
    HTTP/1.1 200 OK
    GET /favicon.ico HTTP/1.1
    HTTP/1.1 404 Not Found
    GET /pipermail/iovisor-dev/2016-January/thread.html HTTP/1.1
    HTTP/1.1 200 OK
    GET /pipermail/iovisor-dev/2016-January/000046.html HTTP/1.1
    HTTP/1.1 200 OK
