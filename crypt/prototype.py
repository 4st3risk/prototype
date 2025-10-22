import subprocess

process = subprocess.Popen(
    ['ncat', '192.168.53.9', '9090'],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True
)

try:
    command = input(">>>")
    print(f"command is '{command}'")
    process.stdin.write(f"{command}\n")
    process.stdin.flush()

except Exception as e:
    print(f"Error Ocurred: {e}")
finally:
    process.stdin.close()
    process.stdout.close()
    process.stderr.close()
    process.terminate()
    process.wait(timeout=5)
    print("Subprocess terminated.")

