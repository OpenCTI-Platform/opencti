// Batch import: chunks of objects sent over HTTP to the lockfreeImport mutation (tools/batch_import.py).
// The platform is served by the test global setup, with app:lockfree_ingestion:enabled (run.py sets it); this
// scenario only starts the Python client against it.
import { spawn } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import conf from '../../../src/config/conf';
import { benchParam, writeResults } from '../bench-utils';

const N = benchParam('N', 4000);

describe('Batch import scenario', () => {
  it('runs the batch import client against the benchmark platform', async () => {
    const python = process.env.BENCH_PYTHON;
    const script = process.env.BENCH_BATCH_SCRIPT;
    if (!python || !script) {
      throw new Error('BENCH_PYTHON and BENCH_BATCH_SCRIPT must be set (use benchmarks/ingestion/run.py)');
    }
    const output = `${process.env.BENCH_OUT ?? 'bench-batch-import.json'}.client.json`;
    const env = {
      ...process.env,
      BENCH_OPENCTI_URL: `http://127.0.0.1:${conf.get('app:port')}`,
      BENCH_OPENCTI_TOKEN: conf.get('app:admin:token'),
      BENCH_N: String(N),
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
      throw new Error(`Batch import client failed (exit ${code}):\n${stderr.slice(-4000)}`);
    }
    const client = JSON.parse(readFileSync(output, 'utf-8'));
    writeResults('batch-import', { params: { n: N }, ...client });
    expect(code).toBe(0);
  });
});
