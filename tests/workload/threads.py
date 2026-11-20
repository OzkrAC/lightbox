# Part of the seccomp suite's workload (ROADMAP 8.3): threads, a child
# process, a TCP connection on the loopback and a socket pair.
import socket
import subprocess
import threading

done = []
threads = [threading.Thread(target=done.append, args=(i,)) for i in range(4)]
for t in threads:
    t.start()
for t in threads:
    t.join()
assert sorted(done) == [0, 1, 2, 3]

child = subprocess.run(["sh", "-c", "echo child"], capture_output=True, text=True, check=True)
assert child.stdout.strip() == "child"

with socket.create_server(("127.0.0.1", 0)) as server:
    with socket.create_connection(server.getsockname()) as client:
        peer, _ = server.accept()
        with peer:
            client.sendall(b"x")
            assert peer.recv(1) == b"x"

a, b = socket.socketpair()
with a, b:
    a.sendall(b"y")
    assert b.recv(1) == b"y"

print("threads, a child and sockets")
