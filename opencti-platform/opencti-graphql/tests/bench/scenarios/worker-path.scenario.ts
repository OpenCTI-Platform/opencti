// Worker path: pycti imports one-object bundles over HTTP, as push_handler.py does.
// The platform is served by the test global setup; this scenario only starts the Python client against it.
import { spawn } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import conf from '../../../src/config/conf';
import { benchParam, writeResults } from '../bench-utils';

const N = benchParam('N', 500);
const CONCURRENCY = benchParam('CONCURRENCY', 8);

describe('Worker path scenario', () => {
  it('runs the pycti import against the benchmark platform', async () => {
    const python = process.env.BENCH_PYTHON;
    const script = process.env.BENCH_WORKER_SCRIPT;
    if (!python || !script) {
      throw new Error('BENCH_PYTHON and BENCH_WORKER_SCRIPT must be set (use benchmarks/ingestion/run.py)');
    }
    const output = `${process.env.BENCH_OUT ?? 'bench-worker-path.json'}.client.json`;
    const env = {
      ...process.env,
      BENCH_OPENCTI_URL: `http://127.0.0.1:${conf.get('app:port')}`,
      BENCH_OPENCTI_TOKEN: conf.get('app:admin:token'),
      BENCH_N: String(N),
      BENCH_CONCURRENCY: String(CONCURRENCY),
      BENCH_CLIENT_OUT: output,
    };
    let stderr = '';
    const code = await new Promise<number>((resolve) => {
      const child = spawn(python, [script], { env, stdio: ['ignore', 'inherit', 'pipe'] });
      child.stderr.on('data', (data) => {
        stderr += data.toString();
      });
      child.on('close', (exit) => resolve(exit ?? 1));
    });
    if (code !== 0) {
      throw new Error(`Worker path client failed (exit ${code}):\n${stderr.slice(-4000)}`);
    }
    const client = JSON.parse(readFileSync(output, 'utf-8'));
    writeResults('worker-path', { params: { n: N, concurrency: CONCURRENCY }, ...client });
    expect(code).toBe(0);
  });
});
