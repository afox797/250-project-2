import argparse
import re
import subprocess


class SystemUtils:

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

    def ps(self):
        vm_regex = r"(\bVmRSS:\s*)(\d+)"
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







def main():
    # Initialize allowed command line arguments
    parser = argparse.ArgumentParser(description='System information utility')
    parser.add_argument('--sysinfo', action='store_true', required=False,
                        help='displays number of users and amount of memory')
    parser.add_argument('--ps', action='store_true', required=False, help='displays a table of running processes')
    parser.add_argument('--exec', nargs=1, type=str, required=False, dest='command',
                        help='executes requested command and displays the result')
    parser.add_argument('--listen', nargs=1, type=int, required=False, dest='port',
                        help='starts the program in server mode, opens a TCP server socket on specified port')

    args = parser.parse_args()
    sys_utils = SystemUtils()

    if args.sysinfo:
        sys_utils.sys_info()
    elif args.ps:
        sys_utils.ps()


if __name__ == '__main__':
    main()
