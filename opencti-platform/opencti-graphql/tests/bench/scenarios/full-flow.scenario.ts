// Full flow: a connector-shaped bundle (tools/full_flow.py) pushed to a connector queue, split as connectors send
// it, and imported by a real worker (opencti-worker, started here against this platform) until its work is
// complete; then what the platform stores is counted. With app:lockfree_ingestion:enabled (run.py sets it for
// full-flow), the worker imports the messages together through lockfreeImport, and pycti's two modes (one object
// per request, batch) are also compared side by side. Without it (full-flow-today), today's flow.
import { type ChildProcess, spawn } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import conf from '../../../src/config/conf';
import { benchParam, writeResults } from '../bench-utils';

const N = benchParam('N', 1000);
const LOCKFREE = conf.get('app:lockfree_ingestion:enabled') === true || process.env.APP__LOCKFREE_INGESTION__ENABLED === 'true';
const REPO = path.resolve(__dirname, '../../../../..');

const run = (python: string, args: string[], env: Record<string, string>) => new Promise<{ code: number; stderr: string }>((resolve) => {
  let stderr = '';
  const child = spawn(python, args, { env: { ...process.env, ...env }, stdio: ['ignore', 'inherit', 'pipe'] });
  child.stderr.on('data', (data) => {
    stderr += data.toString();
  });
  child.on('close', (code) => resolve({ code: code ?? 1, stderr }));
});

describe('Full flow scenario', () => {
  it('imports a connector bundle through the queue and a real worker', async () => {
    const python = process.env.BENCH_PYTHON as string;
    const script = path.join(REPO, 'benchmarks/ingestion/tools/full_flow.py');
    const out = process.env.BENCH_OUT ?? 'bench-full-flow.json';
    const env = {
      BENCH_OPENCTI_URL: `http://127.0.0.1:${conf.get('app:port')}`,
      BENCH_OPENCTI_TOKEN: conf.get('app:admin:token'),
      BENCH_N: String(N),
      PYTHONPATH: path.join(REPO, 'client-python'),
    };
    // The connector first: a worker picks up new connectors only once a minute
    expect((await run(python, [script, '--register'], env)).code).toBe(0);
    const workerLog = `${out}.worker.log`;
    const worker: ChildProcess = spawn('sh', ['-c', `exec "${python}" worker.py > "${workerLog}" 2>&1`], {
      cwd: path.join(REPO, 'opencti-worker/src'),
      env: { ...process.env, ...env, OPENCTI_URL: env.BENCH_OPENCTI_URL, OPENCTI_TOKEN: env.BENCH_OPENCTI_TOKEN },
    });
    try {
      const deadline = Date.now() + 120000;
      while (!(existsSync(workerLog) && readFileSync(workerLog, 'utf-8').includes('push_5f1e3c7a-9b2d-4e8f-a6c1-0d4b7e9f2a35'))) {
        if (Date.now() > deadline) throw new Error('The worker did not start consuming the connector queue');
        await new Promise((resolve) => {
          setTimeout(resolve, 500);
        });
      }
      const results: Record<string, any> = { params: { n: N, lockfree: LOCKFREE } };
      const queue = await run(python, [script, '--queue', '--out', `${out}.queue.json`], env);
      if (queue.code !== 0) throw new Error(`Queue flow failed:\n${queue.stderr.slice(-4000)}`);
      Object.assign(results, JSON.parse(readFileSync(`${out}.queue.json`, 'utf-8')));
      if (LOCKFREE && process.env.BENCH_MODES !== 'false') { // BENCH_MODES=false: the queue flow only
        const modes = await run(python, [script, '--out', `${out}.modes.json`], env);
        if (modes.code !== 0) throw new Error(`pycti modes failed:\n${modes.stderr.slice(-4000)}`);
        Object.assign(results, JSON.parse(readFileSync(`${out}.modes.json`, 'utf-8')));
      }
      writeResults(LOCKFREE ? 'full-flow' : 'full-flow-today', results);
    } finally {
      worker.kill('SIGTERM');
    }
  });
});
