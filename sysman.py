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

    if args.sysinfo:
        sys_utils = SystemUtils()
        sys_utils.sys_info()


if __name__ == '__main__':
    main()
