# -----------------------------------------------------------
# File:   sysman.py
# Author: Andrew Fox  User ID: afox797   Class: CPS 250
# Desc:   This program displays system information specified by the user.
#         Also supports a server mode where clients can obtain system info.
# -----------------------------------------------------------


import argparse
import re
import subprocess
import socket
import sys
import signal
from contextlib import redirect_stdout
from threading import Thread
from datetime import datetime


class SystemUtils:

    # Displays the amount of users and memory available in kilobytes
    def sys_info(self):
        user_regex = r'\d+(?= user)'
        mem_regex = r"(\bMemAvailable:\s*)(\d+)"

        top_process = subprocess.Popen(["top", "-n", "1"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        top_output = top_process.communicate()[0]
        users = re.findall(user_regex, top_output)

        cat_process = subprocess.Popen(["cat", "/proc/meminfo"], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       text=True)
        cat_output = cat_process.communicate()[0]
        mem_available = re.findall(mem_regex, cat_output)

        print("{} users, {} kb available".format(users[0], mem_available[0][1]))

    # Uses information from ps and the /proc directory to display the pid, app name, owner, memory consumed, and
    # cumulative CPU time for each process.
    def ps(self):
        name_regex = r"(Name:\s*)([a-zA-Z]+)"

        ps_process = subprocess.Popen(["ps", "aux"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        psPid_output = subprocess.Popen(["awk", "{print $2}"], stdin=ps_process.stdout, stdout=subprocess.PIPE,
                                        text=True)
        ps_process.wait()
        pid_output = psPid_output.communicate()[0]

        pids = pid_output.split("\n")
        pids.pop(0)
        pids.pop(len(pids) - 1)

        print("{:<8s} {:<15s} {:<15s} {:<8s} {:}".format("PID", "NAME", "USER", "RSS", "TIME"))
        for pid in pids:
            owner_name, app_name = "", ""
            vm = 0
            uptime = "0:00"

            owner_process = subprocess.Popen(["ps", "-u", "-p", f"{pid}"], stdout=subprocess.PIPE,
                                             stderr=subprocess.PIPE, text=True)
            owner_output = subprocess.Popen(["awk", "{print $1, $6, $10}"], stdin=owner_process.stdout,
                                            stdout=subprocess.PIPE, text=True)
            owner_process.wait()

            owners = owner_output.communicate()[0]
            output = "\n".join(owners.splitlines()[-1:]).split(" ")

            if output[0] != "USER":
                owner_name = output[0]
            if output[1] != "RSS":
                vm = output[1]
            if output[2] != "TIME":
                uptime = output[2]

            pid_process = subprocess.Popen(["cat", f"/proc/{pid}/status"], stdout=subprocess.PIPE,
                                           stderr=subprocess.PIPE, text=True)
            pid_output = pid_process.communicate()[0]
            names = re.findall(name_regex, pid_output)
            if len(names) == 1:
                app_name = names[0][1]

            print("{:<8s} {:<15s} {:<15s} {:<8s} {:}".format(str(pid), str(app_name), str(owner_name), str(vm),
                                                             str(uptime)))

    # executes a specified command and displays its output in real time
    def exec(self, command):
        executed_process = subprocess.Popen(command[0].split(" "), stdout=subprocess.PIPE,
                                            stderr=subprocess.PIPE, text=True)
        for line in executed_process.stdout:
            print(f"{line.strip()}")

        executed_process.communicate()


class MonitorThread(Thread):

    def __init__(self, src_ip, log_addr, log_port):
        super().__init__()
        self.src_ip = src_ip
        self.log_addr = log_addr
        self.log_port = log_port

    # monitors tcpdump for matching ip, sends UDP message and prints to stdout if there is a match
    def run(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        monitor_process = subprocess.Popen(["tcpdump", "--immediate-mode", "-l", "-q", "--direction=in", "-n", "ip"],
                                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        for entry in monitor_process.stdout:
            current_time = datetime.now()
            date_time = current_time.strftime("%Y-%m-%d %H:%M:%S")

            results = entry.split(" ")
            size = results[-1]
            ip = results[2]
            trimmed_ip = ip[0:ip.rfind(".")]

            if self.src_ip == trimmed_ip:
                string_to_send = f"{date_time} {self.src_ip} {size}"
                print(string_to_send)
                encoded = string_to_send.encode()
                sock.sendto(bytearray(encoded), (f'{self.log_addr}', int(self.log_port)))


class WorkerThread(Thread):

    def __init__(self, worker_sock, caddr):
        super().__init__()
        self.worker_sock = worker_sock
        self.caddr = caddr

    # handles sysman 'Server Mode' for multiple clients
    def run(self):
        global num_connections
        sys_utils = SystemUtils()
        try:
            with self.worker_sock.makefile('rw', 1024) as sock_file:
                sock_file.write("Welcome to sysman 'Server Mode'.\n"
                                "Commands: SYSINFO, PS, EXEC, QUIT\n")
                sock_file.flush()

                req = sock_file.readline().strip()
                while req != "QUIT":

                    if req == "SYSINFO":
                        with redirect_stdout(sock_file):
                            sys_utils.sys_info()
                        sock_file.flush()

                    elif req == "PS":
                        with redirect_stdout(sock_file):
                            sys_utils.ps()
                        sock_file.flush()

                    elif req[0:4] == "EXEC":
                        raw_command = req[req.index(" ") + 1:len(req)]
                        command = [f"{raw_command}"]
                        with redirect_stdout(sock_file):
                            sys_utils.exec(command)
                        sock_file.flush()

                    req = sock_file.readline().strip()

        except IOError:
            print("I/O Error...")

        self.worker_sock.close()
        num_connections -= 1
        print(f"Connection from {str(self.caddr)} disconnected.\nClients currently connected: {num_connections}")


# Crtl C signal handler
def ctrlc_handler(signal, frame):
    print('Crtl+C detected, shutting down....')
    sys.exit(0)


signal.signal(signal.SIGINT, ctrlc_handler)


def main():
    global num_connections

    # Initialize allowed command line arguments
    parser = argparse.ArgumentParser(description='System information utility')
    parser.add_argument('--sysinfo', action='store_true', required=False,
                        help='displays number of users and amount of memory')
    parser.add_argument('--ps', action='store_true', required=False, help='displays a table of running processes')
    parser.add_argument('--exec', nargs=1, type=str, required=False,
                        help='executes requested command and displays the result')
    parser.add_argument('--listen', nargs=1, type=int, required=False,
                        help='starts the program in server mode, opens a TCP server socket on specified port')
    parser.add_argument('--monitor', nargs=1, required=False,
                        help='if the program is in server mode, this will analyze incoming packets')

    args = parser.parse_args()
    sys_utils = SystemUtils()

    if args.sysinfo:
        sys_utils.sys_info()
    elif args.ps:
        sys_utils.ps()
    elif args.exec:
        sys_utils.exec(args.exec)
    elif args.listen:
        server_mode = True

        if args.monitor:
            monitor_vals = args.monitor[0].split(":")
            monitor_thread = MonitorThread(monitor_vals[0], monitor_vals[1], monitor_vals[2])
            monitor_thread.start()

        port = args.listen[0]

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        sock.bind(('', port))
        sock.listen(1)
        worker_sock = 0

        num_connections = 0

        try:
            while server_mode:
                if server_mode:
                    print(f"Sysman in server mode. Active port: {port} Waiting for connection...")
                    worker_sock, caddr = sock.accept()
                    print("Connection from: " + str(caddr))

                    client_thread = WorkerThread(worker_sock, caddr)
                    client_thread.start()
                    num_connections += 1
                    print(f"Clients currently connected: {num_connections}")

        finally:
            print("Shutting down...")
            if worker_sock:
                worker_sock.close()
            sock.close()


if __name__ == '__main__':
    main()
