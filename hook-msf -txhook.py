import frida
import sys
import requests

s = requests.Session()

DOMAIN = "10.1.241.61:6779"
def on_message(message, data):
    if message['type'] == 'send':
        print("[on_message] message:", message['payload'])
        s.post(f"http://{DOMAIN}/packet", json=message['payload'])


def main():
    pid = frida.spawn(program="D:\\AppD\\QQNT\\QQ.exe")
    session = frida.attach(pid)
    frida.resume(pid)
    with open("hook-msf-txhook.js") as f:
        script = session.create_script(f.read())
        script.on('message', on_message)
        script.load()

    print("[!] Ctrl+D on UNIX, Ctrl+Z on Windows/cmd.exe to detach from instrumented program.\n\n")
    sys.stdin.read()
    session.detach()

if __name__ == '__main__':
    main()
