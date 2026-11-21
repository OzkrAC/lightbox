// Part of the seccomp suite's workload (ROADMAP 8.3): a worker thread, a
// child process, a file read through libuv's own threads and a TCP
// connection on the loopback.
'use strict';
const { Worker } = require('worker_threads');
const { execFileSync } = require('child_process');
const fs = require('fs');
const net = require('net');

function fail(why) {
  console.error(why);
  process.exit(1);
}

async function main() {
  const answer = await new Promise((resolve, reject) => {
    const worker = new Worker('require("worker_threads").parentPort.postMessage(6 * 7)', { eval: true });
    worker.once('message', resolve);
    worker.once('error', reject);
  });
  if (answer !== 42) fail(`the worker said ${answer}`);

  const child = execFileSync('sh', ['-c', 'echo child']).toString().trim();
  if (child !== 'child') fail(`the child said ${child}`);

  const self = await fs.promises.readFile(__filename, 'utf8');
  if (!self.includes('libuv')) fail('this file did not read back');

  const got = await new Promise((resolve, reject) => {
    const server = net.createServer((socket) => socket.end('x'));
    server.listen(0, '127.0.0.1', () => {
      const client = net.connect(server.address().port, '127.0.0.1');
      client.once('data', (data) => {
        client.destroy();
        server.close();
        resolve(data.toString());
      });
      client.once('error', reject);
    });
  });
  if (got !== 'x') fail(`the socket gave ${got}`);

  console.log('a worker, a child, a file and a socket');
}

main().catch((error) => fail(error));
