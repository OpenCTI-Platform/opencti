import { GenericContainer, ImageName, Wait, getContainerRuntimeClient, type StartedTestContainer } from 'testcontainers';
import { RedisContainer } from '@testcontainers/redis';
import { RabbitMQContainer } from '@testcontainers/rabbitmq';
import { MinioContainer } from '@testcontainers/minio';

/**
 * PoC testcontainers, phase 0: measure how long each backend takes to be ready and how much memory it uses.
 * Images and settings mirror scripts/ci/docker-compose.yml.
 *
 * node script/poc-testcontainers-measure.ts [iterations]
 * Prints a JSON report on stdout, progress on stderr.
 */

const ITERATIONS = Number(process.argv[2] ?? 3);
const SETTLE_MS = 15000;

type Backend = { name: string; image: string; build: () => GenericContainer };

const elasticsearch = (heap: string) => new GenericContainer('elasticsearch:8.19.23')
  .withEnvironment({ 'discovery.type': 'single-node', 'xpack.security.enabled': 'false', ES_JAVA_OPTS: `-Xms${heap} -Xmx${heap}` })
  .withUlimits({ memlock: { soft: -1, hard: -1 }, nofile: { soft: 65536, hard: 65536 } })
  .withExposedPorts(9200)
  .withWaitStrategy(Wait.forHttp('/_cluster/health?wait_for_status=yellow&timeout=60s', 9200).forStatusCode(200))
  .withStartupTimeout(180000);

const BACKENDS: Backend[] = [
  { name: 'elasticsearch (2G heap, as CI)', image: 'elasticsearch:8.19.23', build: () => elasticsearch('2g') },
  { name: 'elasticsearch (512m heap)', image: 'elasticsearch:8.19.23', build: () => elasticsearch('512m') },
  { name: 'redis', image: 'redis:8.6.7', build: () => new RedisContainer('redis:8.6.7') },
  { name: 'rabbitmq (management)', image: 'rabbitmq:4.3-management', build: () => new RabbitMQContainer('rabbitmq:4.3-management') },
  { name: 'minio (pgsty/silo)', image: 'pgsty/silo:latest', build: () => new MinioContainer('pgsty/silo:latest') },
];

const log = (message: string) => process.stderr.write(`[measure] ${message}\n`);
const elapsed = (start: number) => Math.round(performance.now() - start);
const median = (values: number[]) => [...values].sort((a, b) => a - b)[Math.floor(values.length / 2)];
const summary = (values: number[]) => ({ min: Math.min(...values), median: median(values), max: Math.max(...values) });

// Same figure as `docker stats`: usage without the reclaimable page cache
const memoryMiB = async (container: StartedTestContainer) => {
  const client = await getContainerRuntimeClient();
  const stats = await client.container.getById(container.getId()).stats({ stream: false });
  const usage = stats.memory_stats?.usage ?? 0;
  const details: Record<string, number> = stats.memory_stats?.stats ?? {};
  const cache = details.inactive_file ?? details.total_inactive_file ?? 0;
  return Math.round((usage - cache) / 1024 / 1024);
};

const measureBackend = async (backend: Backend) => {
  const readyMs: number[] = [];
  const memoryAtReadyMiB: number[] = [];
  const memoryAfterSettleMiB: number[] = [];
  for (let i = 0; i < ITERATIONS; i += 1) {
    const start = performance.now();
    const container = await backend.build().start();
    readyMs.push(elapsed(start));
    memoryAtReadyMiB.push(await memoryMiB(container));
    await new Promise((resolve) => setTimeout(resolve, SETTLE_MS));
    memoryAfterSettleMiB.push(await memoryMiB(container));
    await container.stop();
    log(`${backend.name} #${i + 1}: ready in ${readyMs[i]} ms, ${memoryAfterSettleMiB[i]} MiB after settle`);
  }
  return { backend: backend.name, readyMs: summary(readyMs), memoryAtReadyMiB: summary(memoryAtReadyMiB), memoryAfterSettleMiB: summary(memoryAfterSettleMiB) };
};

// The full stack a suite would get: everything started concurrently, ES with a small heap
const measureFullStack = async () => {
  const readyMs: number[] = [];
  const memoryMiBTotal: number[] = [];
  const full = BACKENDS.filter((b) => !b.name.includes('2G'));
  for (let i = 0; i < ITERATIONS; i += 1) {
    const start = performance.now();
    const containers = await Promise.all(full.map((b) => b.build().start()));
    readyMs.push(elapsed(start));
    await new Promise((resolve) => setTimeout(resolve, SETTLE_MS));
    const memories = await Promise.all(containers.map(memoryMiB));
    memoryMiBTotal.push(memories.reduce((a, b) => a + b, 0));
    await Promise.all(containers.map((c) => c.stop()));
    log(`full stack #${i + 1}: ready in ${readyMs[i]} ms, ${memoryMiBTotal[i]} MiB after settle`);
  }
  return { backends: full.map((b) => b.name), readyMs: summary(readyMs), memoryAfterSettleMiB: summary(memoryMiBTotal) };
};

const client = await getContainerRuntimeClient();
const { containerRuntime, node } = client.info;
const environment = {
  node: node.version,
  runtimeHost: containerRuntime.host,
  operatingSystem: containerRuntime.operatingSystem,
  architecture: containerRuntime.architecture,
  cpus: containerRuntime.cpus,
  memoryGiB: Math.round((containerRuntime.memory / 1024 ** 3) * 10) / 10,
  ryukDisabled: process.env.TESTCONTAINERS_RYUK_DISABLED === 'true',
};
log(`runtime: ${JSON.stringify(environment)}`);

// Pull first so that start times measure a warm start, not the download
const pulls: Record<string, number> = {};
for (const image of [...new Set(BACKENDS.map((b) => b.image))]) {
  const start = performance.now();
  await client.image.pull(ImageName.fromString(image));
  pulls[image] = elapsed(start);
  log(`pulled ${image} in ${pulls[image]} ms`);
}

const backends = [];
for (const backend of BACKENDS) {
  backends.push(await measureBackend(backend));
}
const fullStack = await measureFullStack();

process.stdout.write(`${JSON.stringify({ environment, iterations: ITERATIONS, settleMs: SETTLE_MS, pullMs: pulls, backends, fullStack }, null, 2)}\n`);
