import crypto from 'node:crypto';
import http from 'node:http';
import type { AddressInfo } from 'node:net';

/**
 * In-memory XTM Hub implementing the Threat Pulse platform API (contract shared with XTM-Hub/xtm-hub), so that the
 * OpenCTI tests never depend on a real Hub. Validation is as strict as the Hub: any field outside the contract fails.
 */

const OBJECT_TYPES = ['indicator', 'attack_pattern', 'vulnerability', 'intrusion_set', 'malware', 'tool'];
const EVENT_KINDS = ['created', 'sighted', 'detected', 'hunted', 'referenced'];
const SECTORS = ['finance', 'government', 'defense', 'healthcare', 'energy_utilities', 'telecommunications', 'technology',
  'manufacturing', 'transportation', 'retail_consumer', 'education_research', 'non_profit', 'other', 'undisclosed'];
const REGIONS = ['africa', 'asia_pacific', 'europe', 'latin_america', 'middle_east', 'north_america', 'global', 'undisclosed'];
const HASH_REGEX = /^[0-9a-f]{32}$/;
const DAY_MS = 24 * 3600 * 1000;
const RECORD_FIELDS = ['count', 'event_kind', 'hash', 'object_type'];
const BATCH_FIELDS = ['day', 'records', 'region_bucket', 'sector_bucket'];

export interface PulseLedgerRow {
  platformId: string;
  key: string;
  objectType: string;
  eventKind: string;
  day: string;
  sector: string;
  region: string;
  count: number;
}

export interface PulseHubMockRequest {
  operation: string;
  variables: Record<string, any>;
  platformId: string | undefined;
  rawBody: string;
}

class GraphqlError extends Error {
  readonly code: string;

  readonly extensions: Record<string, unknown>;

  constructor(code: string, message: string, extensions: Record<string, unknown> = {}) {
    super(message);
    this.code = code;
    this.extensions = { code, ...extensions };
  }
}

const utcDay = (date: Date) => date.toISOString().slice(0, 10);
const dayToTime = (day: string) => Date.parse(`${day}T00:00:00.000Z`);

const aes = (keyHex: string, inputHex: string, decrypt: boolean) => {
  const key = Buffer.from(keyHex, 'hex');
  const cipher = decrypt ? crypto.createDecipheriv('aes-128-ecb', key, null) : crypto.createCipheriv('aes-128-ecb', key, null);
  cipher.setAutoPadding(false);
  return Buffer.concat([cipher.update(Buffer.from(inputHex, 'hex')), cipher.final()]).toString('hex');
};

export const platformsBucket = (count: number) => {
  if (count >= 250) return '250+';
  if (count >= 100) return '100-249';
  if (count >= 50) return '50-99';
  if (count >= 25) return '25-49';
  if (count >= 10) return '10-24';
  return '5-9';
};

const median = (values: number[]) => {
  const sorted = [...values].sort((a, b) => a - b);
  const middle = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 0 ? (sorted[middle - 1] + sorted[middle]) / 2 : sorted[middle];
};

export class PulseHubMock {
  k = 5;

  readonly requests: PulseHubMockRequest[] = [];

  ledger: PulseLedgerRow[] = [];

  private salts = new Map<string, string>();

  private tokens = new Map<string, string>();

  private platformBuckets = new Map<string, { sector: string; region: string }>();

  private forcedErrors: Array<{ operation: string; code: string }> = [];

  private server: http.Server | undefined;

  private now: () => Date = () => new Date();

  url = '';

  registerPlatform(platformId: string, token: string) {
    this.tokens.set(platformId, token);
  }

  setClock(now: () => Date) {
    this.now = now;
  }

  // The next call of the operation fails with the given GraphQL error code (e.g. PULSE_RATE_LIMITED).
  failNext(operation: string, code: string) {
    this.forcedErrors.push({ operation, code });
  }

  saltOf(day: string) {
    let salt = this.salts.get(day);
    if (!salt) {
      salt = crypto.randomBytes(16).toString('hex');
      this.salts.set(day, salt);
    }
    return salt;
  }

  today() {
    return utcDay(this.now());
  }

  hashOf(stableKey: string, day = this.today()) {
    return aes(this.saltOf(day), stableKey, false);
  }

  // Simulates the contribution of another platform, directly with the stable key.
  seed(rows: Array<Omit<PulseLedgerRow, 'count'> & { count?: number }>) {
    rows.forEach((row) => this.addLedger({ ...row, count: row.count ?? 1 }));
  }

  reset() {
    this.requests.length = 0;
    this.ledger = [];
    this.salts.clear();
    this.platformBuckets.clear();
    this.forcedErrors = [];
    this.now = () => new Date();
  }

  async start(): Promise<string> {
    this.server = http.createServer((req, res) => {
      let raw = '';
      req.on('data', (chunk) => {
        raw += chunk;
      });
      req.on('end', () => {
        const platformId = req.headers['xtm-hub-platform-id'] as string | undefined;
        const token = req.headers['xtm-hub-platform-token'] as string | undefined;
        let payload: unknown;
        try {
          const body = JSON.parse(raw);
          payload = { data: this.execute(body.query, body.variables ?? {}, platformId, token, raw) };
        } catch (error) {
          const graphqlError = error instanceof GraphqlError ? error : new GraphqlError('INTERNAL_SERVER_ERROR', String(error));
          payload = { data: null, errors: [{ message: graphqlError.message, extensions: graphqlError.extensions }] };
        }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(payload));
      });
    });
    await new Promise<void>((resolve) => {
      this.server?.listen(0, '127.0.0.1', () => resolve());
    });
    const { port } = this.server.address() as AddressInfo;
    this.url = `http://127.0.0.1:${port}`;
    return this.url;
  }

  async stop() {
    if (this.server) {
      await new Promise<void>((resolve) => {
        this.server?.close(() => resolve());
      });
      this.server = undefined;
    }
  }

  private execute(query: string, variables: Record<string, any>, platformId: string | undefined, token: string | undefined, rawBody: string) {
    const operation = ['pushPulse', 'pulseLookup', 'pulseSalt', 'pulseTrending', 'pulseBenchmark', 'pulsePurge', 'pulseStatus']
      .find((name) => new RegExp(`\\b${name}\\s*[({]`).test(query));
    if (!operation) {
      throw new GraphqlError('BAD_USER_INPUT', 'Unknown operation');
    }
    this.requests.push({ operation, variables, platformId, rawBody });
    if (!platformId || !token || this.tokens.get(platformId) !== token) {
      throw new GraphqlError('UNAUTHENTICATED', 'Invalid platform token');
    }
    const forced = this.forcedErrors.findIndex((error) => error.operation === operation);
    if (forced >= 0) {
      const [{ code }] = this.forcedErrors.splice(forced, 1);
      throw new GraphqlError(code, `Forced ${code}`, code === 'PULSE_RATE_LIMITED' ? { retry_after_seconds: 60 } : {});
    }
    switch (operation) {
      case 'pulseSalt':
        this.assertDay(variables.day);
        return { pulseSalt: { day: variables.day, salt: this.saltOf(variables.day) } };
      case 'pulseStatus':
        return { pulseStatus: this.status(platformId) };
      case 'pushPulse':
        return { pushPulse: this.push(platformId, variables.input) };
      case 'pulseLookup':
        this.assertReadAccess(platformId);
        return { pulseLookup: this.lookup(platformId, variables.input) };
      case 'pulseTrending':
        this.assertReadAccess(platformId);
        return { pulseTrending: this.trending(variables.input) };
      case 'pulseBenchmark':
        this.assertReadAccess(platformId);
        if (variables.input?.platformId !== platformId) {
          throw new GraphqlError('FORBIDDEN', 'A platform can only read its own benchmark');
        }
        return { pulseBenchmark: this.benchmark(platformId, variables.input) };
      case 'pulsePurge':
        if (variables.platformId !== platformId) {
          throw new GraphqlError('FORBIDDEN', 'A platform can only purge its own contributions');
        }
        return { pulsePurge: this.purge(platformId) };
      default:
        throw new GraphqlError('BAD_USER_INPUT', 'Unknown operation');
    }
  }

  private assertDay(day: unknown) {
    const today = this.today();
    const yesterday = utcDay(new Date(dayToTime(today) - DAY_MS));
    if (day !== today && day !== yesterday) {
      throw new GraphqlError('BAD_USER_INPUT', 'Only the current or the previous UTC day is accepted');
    }
  }

  private assertReadAccess(platformId: string) {
    const since = dayToTime(this.today()) - 30 * DAY_MS;
    const contributed = this.ledger.some((row) => row.platformId === platformId && dayToTime(row.day) >= since);
    if (!contributed) {
      throw new GraphqlError('PULSE_CONTRIBUTION_REQUIRED', 'Reading Threat Pulse requires contributing');
    }
  }

  private addLedger(row: PulseLedgerRow) {
    const existing = this.ledger.find((entry) => entry.platformId === row.platformId && entry.key === row.key && entry.objectType === row.objectType
      && entry.eventKind === row.eventKind && entry.day === row.day && entry.sector === row.sector && entry.region === row.region);
    if (existing) {
      existing.count += row.count;
    } else {
      this.ledger.push({ ...row });
    }
    this.platformBuckets.set(row.platformId, { sector: row.sector, region: row.region });
  }

  private push(platformId: string, input: any) {
    if (!input || Object.keys(input).sort().join(',') !== BATCH_FIELDS.join(',')) {
      throw new GraphqlError('BAD_USER_INPUT', `Unexpected batch fields: ${Object.keys(input ?? {}).join(', ')}`);
    }
    this.assertDay(input.day);
    if (!SECTORS.includes(input.sector_bucket) || !REGIONS.includes(input.region_bucket)) {
      throw new GraphqlError('BAD_USER_INPUT', 'Invalid bucket');
    }
    if (!Array.isArray(input.records) || input.records.length === 0 || input.records.length > 5000) {
      throw new GraphqlError('BAD_USER_INPUT', 'Invalid number of records');
    }
    const seen = new Set<string>();
    input.records.forEach((record: any) => {
      if (Object.keys(record).sort().join(',') !== RECORD_FIELDS.join(',')) {
        throw new GraphqlError('BAD_USER_INPUT', `Unexpected record fields: ${Object.keys(record).join(', ')}`);
      }
      if (!HASH_REGEX.test(record.hash) || !OBJECT_TYPES.includes(record.object_type) || !EVENT_KINDS.includes(record.event_kind)
        || !Number.isInteger(record.count) || record.count < 1 || record.count > 100000) {
        throw new GraphqlError('BAD_USER_INPUT', 'Invalid record');
      }
      const identity = `${record.hash}|${record.object_type}|${record.event_kind}`;
      if (seen.has(identity)) {
        throw new GraphqlError('BAD_USER_INPUT', 'Duplicated record');
      }
      seen.add(identity);
    });
    const salt = this.saltOf(input.day);
    input.records.forEach((record: any) => this.addLedger({
      platformId,
      key: aes(salt, record.hash, true),
      objectType: record.object_type,
      eventKind: record.event_kind,
      day: input.day,
      sector: input.sector_bucket,
      region: input.region_bucket,
      count: record.count,
    }));
    return { accepted: input.records.length, day: input.day };
  }

  private rowsSince(days: number, filter: (row: PulseLedgerRow) => boolean = () => true) {
    const since = dayToTime(this.today()) - (days - 1) * DAY_MS;
    return this.ledger.filter((row) => dayToTime(row.day) >= since && filter(row));
  }

  private distinctPlatforms(rows: PulseLedgerRow[]) {
    return new Set(rows.map((row) => row.platformId)).size;
  }

  private weeklyPlatforms(rows: PulseLedgerRow[], weekOffset: number) {
    const end = dayToTime(this.today()) - weekOffset * 7 * DAY_MS;
    const start = end - 6 * DAY_MS;
    return this.distinctPlatforms(rows.filter((row) => dayToTime(row.day) >= start && dayToTime(row.day) <= end));
  }

  private trendOf(rows: PulseLedgerRow[]) {
    const recent = this.weeklyPlatforms(rows, 0);
    const baseline = (this.weeklyPlatforms(rows, 1) + this.weeklyPlatforms(rows, 2) + this.weeklyPlatforms(rows, 3)) / 3;
    if (recent >= 1.5 * baseline && recent - baseline >= 2) return 'rising';
    if (recent <= 0.67 * baseline && baseline - recent >= 2) return 'falling';
    return 'stable';
  }

  private prevalenceOf(rows: PulseLedgerRow[]) {
    const recentPlatforms = this.distinctPlatforms(this.rowsSince(30, (row) => rows.includes(row)));
    if (recentPlatforms < this.k) return 'rare';
    const active = this.distinctPlatforms(this.rowsSince(30));
    const share = active === 0 ? 0 : recentPlatforms / active;
    if (share >= 0.3) return 'widespread';
    if (share >= 0.1) return 'common';
    if (share >= 0.02) return 'uncommon';
    return 'rare';
  }

  private lookup(platformId: string, input: any) {
    this.assertDay(input?.day);
    if (!OBJECT_TYPES.includes(input.object_type) || !Array.isArray(input.hashes) || input.hashes.length === 0 || input.hashes.length > 1000) {
      throw new GraphqlError('BAD_USER_INPUT', 'Invalid lookup');
    }
    const salt = this.saltOf(input.day);
    const callerSector = this.platformBuckets.get(platformId)?.sector;
    return input.hashes.map((hash: string) => {
      if (!HASH_REGEX.test(hash)) {
        throw new GraphqlError('BAD_USER_INPUT', 'Invalid hash');
      }
      const key = aes(salt, hash, true);
      const rows = this.ledger.filter((row) => row.key === key && row.objectType === input.object_type);
      const platforms = this.distinctPlatforms(rows);
      if (platforms < this.k) {
        return {
          hash,
          published: false,
          prevalence_bucket: null,
          platforms_bucket: null,
          first_seen_network: null,
          last_seen_network: null,
          trend: null,
          trend_series: null,
          sector_trend: null,
          sector_platforms_bucket: null,
        };
      }
      const days = rows.map((row) => row.day).sort();
      const sectorRows = rows.filter((row) => row.sector === callerSector);
      const sectorPlatforms = this.distinctPlatforms(this.rowsSince(30, (row) => sectorRows.includes(row)));
      const series = Array.from({ length: 12 }, (_, index) => this.weeklyPlatforms(rows, 11 - index))
        .map((count) => (count >= this.k ? count : 0));
      return {
        hash,
        published: true,
        prevalence_bucket: this.prevalenceOf(rows),
        platforms_bucket: platformsBucket(platforms),
        first_seen_network: days[0],
        last_seen_network: days[days.length - 1],
        trend: this.trendOf(rows),
        trend_series: series,
        sector_trend: sectorPlatforms >= this.k ? this.trendOf(sectorRows) : null,
        sector_platforms_bucket: sectorPlatforms >= this.k ? platformsBucket(sectorPlatforms) : null,
      };
    });
  }

  private trending(input: any) {
    this.assertDay(input?.day);
    const periodDays = { last_7_days: 7, last_30_days: 30, last_90_days: 90 }[input.period as string];
    if (!periodDays) {
      throw new GraphqlError('BAD_USER_INPUT', 'Invalid period');
    }
    const first = Math.min(200, input.first ?? 50);
    const inBucket = (row: PulseLedgerRow) => (!input.sector_bucket || row.sector === input.sector_bucket)
      && (!input.region_bucket || row.region === input.region_bucket)
      && (!input.object_types || input.object_types.includes(row.objectType));
    const groups = new Map<string, PulseLedgerRow[]>();
    this.ledger.filter(inBucket).forEach((row) => {
      const id = `${row.objectType}|${row.key}`;
      groups.set(id, [...(groups.get(id) ?? []), row]);
    });
    const end = dayToTime(this.today());
    const items = Array.from(groups.values()).flatMap((rows) => {
      const allRows = this.ledger.filter((row) => row.key === rows[0].key && row.objectType === rows[0].objectType);
      const recentRows = rows.filter((row) => dayToTime(row.day) > end - periodDays * DAY_MS);
      const recent = this.distinctPlatforms(recentRows);
      if (recent < this.k || this.distinctPlatforms(allRows) < this.k) {
        return [];
      }
      const previous = rows.filter((row) => dayToTime(row.day) <= end - periodDays * DAY_MS && dayToTime(row.day) > end - 3 * periodDays * DAY_MS);
      const baseline = this.distinctPlatforms(previous) / 2;
      const days = allRows.map((row) => row.day).sort();
      return [{
        key: rows[0].key,
        recent,
        item: {
          hash: aes(this.saltOf(input.day), rows[0].key, false),
          object_type: rows[0].objectType,
          platforms_bucket: platformsBucket(this.distinctPlatforms(allRows)),
          prevalence_bucket: this.prevalenceOf(allRows),
          trend: this.trendOf(rows),
          growth: (recent + 1) / (baseline + 1),
          first_seen_network: days[0],
        },
      }];
    }).sort((a, b) => (b.item.growth - a.item.growth) || (b.recent - a.recent)).slice(0, first);
    return {
      day: input.day,
      period: input.period,
      sector_bucket: input.sector_bucket ?? null,
      region_bucket: input.region_bucket ?? null,
      items: items.map(({ item }) => item),
    };
  }

  private benchmark(platformId: string, input: any) {
    this.assertDay(input?.day);
    const periodDays = { last_7_days: 7, last_30_days: 30, last_90_days: 90 }[input.period as string] ?? 30;
    const buckets = this.platformBuckets.get(platformId) ?? { sector: 'undisclosed', region: 'undisclosed' };
    const rows = this.rowsSince(periodDays);
    const sectorRows = rows.filter((row) => row.sector === buckets.sector);
    const sectorPlatforms = this.distinctPlatforms(sectorRows);
    const sumBy = (source: PulseLedgerRow[], filter: (row: PulseLedgerRow) => boolean) => {
      const sums = new Map<string, number>();
      source.filter(filter).forEach((row) => sums.set(row.platformId, (sums.get(row.platformId) ?? 0) + row.count));
      return sums;
    };
    const metrics = OBJECT_TYPES.flatMap((objectType) => EVENT_KINDS.map((eventKind) => {
      const filter = (row: PulseLedgerRow) => row.objectType === objectType && row.eventKind === eventKind;
      const sectorSums = sumBy(sectorRows, filter);
      const networkSums = sumBy(rows, filter);
      return {
        object_type: objectType,
        event_kind: eventKind,
        platform_count: sectorSums.get(platformId) ?? networkSums.get(platformId) ?? 0,
        sector_median: sectorSums.size >= this.k ? median(Array.from(sectorSums.values())) : null,
        network_median: networkSums.size >= this.k ? median(Array.from(networkSums.values())) : null,
      };
    })).filter((metric) => metric.platform_count > 0 || metric.sector_median !== null);
    const ownKeys = Array.from(new Set(rows.filter((row) => row.platformId === platformId).map((row) => `${row.objectType}|${row.key}`)));
    const topItems = ownKeys.flatMap((id) => {
      const [objectType, key] = id.split('|');
      const sums = sumBy(sectorRows, (row) => row.key === key && row.objectType === objectType);
      if (sums.size < this.k) return [];
      const own = sums.get(platformId) ?? 0;
      const sectorMedian = median(Array.from(sums.values()));
      return [{
        hash: aes(this.saltOf(input.day), key, false),
        object_type: objectType,
        platform_count: own,
        sector_median: sectorMedian,
        ratio: sectorMedian > 0 ? own / sectorMedian : 0,
      }];
    }).sort((a, b) => b.platform_count - a.platform_count).slice(0, 50);
    return {
      period: input.period,
      sector_bucket: buckets.sector,
      region_bucket: buckets.region,
      sector_platforms_bucket: sectorPlatforms >= this.k ? platformsBucket(sectorPlatforms) : null,
      metrics,
      top_items: topItems,
    };
  }

  private status(platformId: string) {
    const active = this.distinctPlatforms(this.rowsSince(30));
    const own = this.ledger.filter((row) => row.platformId === platformId).map((row) => row.day).sort();
    return {
      day: this.today(),
      k_threshold: this.k,
      retention_months: 13,
      contributors_bucket: active < this.k ? '<5' : platformsBucket(active),
      read_access: this.rowsSince(30, (row) => row.platformId === platformId).length > 0,
      last_contribution_day: own.length > 0 ? own[own.length - 1] : null,
    };
  }

  private purge(platformId: string) {
    const before = this.ledger.length;
    this.ledger = this.ledger.filter((row) => row.platformId !== platformId);
    this.platformBuckets.delete(platformId);
    return { success: true, deleted_records: before - this.ledger.length };
  }
}
