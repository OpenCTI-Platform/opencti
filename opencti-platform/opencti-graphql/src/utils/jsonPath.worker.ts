import { parentPort } from 'worker_threads';
import { JSONPath } from 'jsonpath-plus';
import type { WorkerReply } from './workerPool';

export interface JsonPathQuery {
  path: string;
  json: any;
  wrap?: boolean;
  flatten?: boolean;
}

// The worker stays alive and evaluates one query at a time. Script expressions run here with
// jsonpath-plus default 'safe' evaluation, so a runaway one only blocks this thread until the pool times it out.
parentPort?.on('message', (query: JsonPathQuery) => {
  try {
    const result = JSONPath({ ...query });
    parentPort?.postMessage({ success: true, result } satisfies WorkerReply<unknown>);
  } catch (error) {
    const message: WorkerReply<unknown> = {
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error',
    };
    parentPort?.postMessage(message);
  }
});
