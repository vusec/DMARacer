#!/usr/bin/env python
# Designed for use with boofuzz v0.2.0
from boofuzz import *
import argparse


def main():
    parser = argparse.ArgumentParser(description='Process DON reports.')
    parser.add_argument('--ip', metavar='ipaddr', help="IP address of the server", default="127.0.0.1", type=str)
    parser.add_argument('--port', metavar='portnum', help="Port number of the server", default=80, type=int)
    args = parser.parse_args()
    print("Connecting to server at ip=" + args.ip + ", port=" + str(args.port) + "...")

    session = Session(
        target=Target(connection=TCPSocketConnection(args.ip, args.port)),
    )

    s_initialize(name="Request")
    with s_block("Request-Line"):
        s_group("Method", ["GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE"])
        s_delim(" ", name="space-1")
        s_string("/index.html", name="Request-URI")
        s_delim(" ", name="space-2")
        s_string("HTTP/1.1", name="HTTP-Version")
        s_static("\r\n", name="Request-Line-CRLF")
        s_string("Host:", name="Host-Line")
        s_delim(" ", name="space-3")
        s_string("example.com", name="Host-Line-Value")
        s_static("\r\n", name="Host-Line-CRLF")
        s_static("Content-Length:", name="Content-Length-Header")
        s_delim(" ", name="space-4")
        s_size("Body-Content", output_format="ascii", name="Content-Length-Value")
        s_static("\r\n", "Content-Length-CRLF")
    s_static("\r\n", "Request-CRLF")

    with s_block("Body-Content"):
        s_string("Body content ...", name="Body-Content-Value")

    session.connect(s_get("Request"))

    session.fuzz()


if __name__ == "__main__":
    main()
