#!/bin/bash

import sys
import socket
from datetime import datetime

# Syntax: ./scanner.py  x.x.x.x -u  -p x x
#             [0           1    2   3 4 5]
# default: ./scanner.py x.x.x.x  (scan for tcp ports 1-50)

# Variables (set to defaults/ None):
target = None
s = None
result = None
range_start = 1
range_end = 50
protocol = "t"
port_flag_index = None
start_time = None
end_time = None
interval = None
interval_string = None

for i in range(0, len(sys.argv) + 1):
    match i:
        case 1:
            # Not enough arguments:
            if len(sys.argv) < 2:
                print("Not enough arguments.")
                print("Syntax: 'python3 ./scanner.py <host>'")
                sys.exit()
            # Attempt to resolve target:
            try:
                target = socket.gethostbyname(sys.argv[1])
                print(f"The target is {target}")
            except:
                print(f"Could not resolve the given host: '{target}'")
                sys.exit()
        case 2:
            # Check that sys.argv[2] is in bounds:
            if len(sys.argv) >= 3:
                match sys.argv[2]:
                    case "-u":
                        protocol = "u"
                        port_flag_index = 3
                    case "-p":
                        port_flag_index = 2
                    case "-t":
                        port_flag_index = 3
            else:
                # Default values remain for port range/ protocol
                pass
        case 3:
            # Check that sys.argv[3] is in bounds:
            if len(sys.argv) >= 4:
                match port_flag_index:
                    case 2:
                        if sys.argv[2] != "-p":
                            continue
                        range_start = int(sys.argv[3])
                        if len(sys.argv) > 4:
                            range_end = int(sys.argv[4])
                        else:
                            range_end = int(sys.argv[3])
                    case 3:
                        if sys.argv[3] != "-p":
                            continue
                        if len(sys.argv) == 4:
                            print(f"Improper syntax. Missing arguments for '{sys.argv[3]}'")
                            sys.exit()
                        elif len(sys.argv) >= 5:
                            range_start = int(sys.argv[4])
                            if len(sys.argv) > 5:
                                range_end = int(sys.argv[5])
                            else:
                                range_end = int(sys.argv[4])                        
            else:
                port_flag_index = None

start_time = datetime.now()

# Banner:
print("*" * 30)
print(f"Scanning target {target} for open ports.")
print(f"Time started: {str(start_time)}")
print("*" * 30)

# Scanning:
try:
    for port in range(range_start, range_end + 1):
        # Create socket based on protocol:
        match protocol:
            case "t":
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            case "u":
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        print(f"\rScanning port {port}", end = "")
        socket.setdefaulttimeout(5)
        result = s.connect_ex((target, port))

        if result == 0: # Result may be different for UDP socket, need to find alternative!
            print(f"\nPort {port} is open!")
            s.close()            

    end_time = datetime.now()
    interval = end_time - start_time
    if interval.seconds <= 0:
        interval_string = f"{str(interval.microseconds)} milliseconds."
    else:
        interval_string = f"{str(interval.seconds)} seconds."
    
    print("\n" + "_" * 30)
    print("\nScan finished.")
    print(f"{range_end - range_start + 1} ports scanned in {interval_string}")
    sys.exit()

except KeyboardInterrupt:
    print(f"\n Exiting port scanner...")
    sys.exit()

except socket.gaierror:
    print(f"The target hostname '{target}' could  not be resolved.")
    print("Quitting...")
    sys.exit()

except socket.error:
    print(f"There was an unknown socket error...")
    print("Quitting...")
    sys.exit()