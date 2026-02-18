from pwninit.plugins import Plugin, arg
from pwn import ssh, log, context, error, success
import os


class Plugin(Plugin):
    name = "pwncollege"
    description = "Connect to pwn.college and download challenge files via SSH"
    provide_args = [
        arg("--host", help="SSH host", default="dojo.pwn.college"),
        arg("--user", help="SSH user", default="hacker"),
    ]

    def provide(self, args, path):
        try:
            s = ssh(host=args.host, user=args.user, timeout=10, cache=False)
        except Exception as e:
            error(f"Failed to establish SSH connection: {e}")

        success("connected to ssh")

        download = log.progress("downloading files")
        try:
            context.log_level = "error"
            files = s.system("ls /challenge").recvall()[:-1]
            files = files.decode().split(" ")
            for f in files:
                if f != "":
                    download.status("Downloading %s" % f)
                    s.download_file("/challenge/" + f, os.path.basename(f))

            libs = s.system(f'ldd %s' % "/challenge/" + files[0]).recvall()
            libs = libs.decode().replace("\t", "").split("\n")[:-1]
            libs = [l.split(" => ")[-1].split(" ")[0] for l in libs]
            for l in libs:
                if "No such file or directory" not in s.system("ls % s" % l).recvall().decode().strip():
                    s.download_file(l, os.path.basename(l))

            context.log_level = "info"
        except Exception as e:
            error(f"Failed to download files via SSH: {e}")

        download.success("Files saved")
        return path
