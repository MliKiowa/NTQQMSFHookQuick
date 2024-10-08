import frida
import sys

def on_message(message, data):
    pass


def main():
    pid = frida.spawn(program="D:\\AppD\\QQNT\\QQ.exe")
    session = frida.attach(pid)
    frida.resume(pid)
    with open("hook-msf.js") as f:
        script = session.create_script(f.read())
        script.on('message', on_message)
        script.load()

    print("[!] Ctrl+D on UNIX, Ctrl+Z on Windows/cmd.exe to detach from instrumented program.\n\n")
    sys.stdin.read()
    session.detach()

if __name__ == '__main__':
    main()
