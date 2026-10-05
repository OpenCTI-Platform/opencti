import { isIP } from 'node:net';
import type { AuthContext } from '../../types/user';
import type { BasicStoreEntity } from '../../types/store';
import { logApp } from '../../config/conf';
import { RELATION_CREATED_BY, RELATION_GRANTED_TO, RELATION_OBJECT_MARKING } from '../../schema/stixRefRelationship';
import { HUNT_MANAGER_USER } from '../../utils/access';
import type { BasicStoreEntityHunt } from './hunt-types';
import type { BasicStoreEntityHuntRun, HuntHit } from './huntRun/huntRun-types';
import { HUNT_CONFIG } from './hunt-utils';

/** An observable a hit names, as the observable creation takes it. */
export interface HuntHitObservable {
  key: string;
  type: string;
  input: Record<string, unknown>;
}

const HASH_ALGORITHMS: Record<number, string> = { 32: 'MD5', 40: 'SHA-1', 64: 'SHA-256' };
const DOMAIN_PATTERN = /^(?=.{1,253}$)(?:[a-z\d](?:[a-z\d-]{0,61}[a-z\d])?\.)+[a-z]{2,63}$/i;
const MASKED = '[masked';

const usable = (value: string | null | undefined): value is string => {
  return typeof value === 'string' && value.trim().length > 0 && !value.includes(MASKED) && !value.endsWith('...');
};

const addressObservable = (value: string): HuntHitObservable | null => {
  const version = isIP(value);
  if (version === 4) {
    return { key: `IPv4-Addr:${value}`, type: 'IPv4-Addr', input: { IPv4Addr: { value } } };
  }
  return version === 6 ? { key: `IPv6-Addr:${value}`, type: 'IPv6-Addr', input: { IPv6Addr: { value } } } : null;
};

/**
 * The observables of one hit: its addresses, domain, URL, host, account, file hash and command line. A value the
 * platform masked or truncated names nothing and is skipped.
 */
export const extractHitObservables = (hit: HuntHit): HuntHitObservable[] => {
  const observables: HuntHitObservable[] = [];
  [hit.source_ip, hit.destination_ip].forEach((address) => {
    const observable = usable(address) ? addressObservable(address.trim()) : null;
    if (observable) {
      observables.push(observable);
    }
  });
  if (usable(hit.domain) && DOMAIN_PATTERN.test(hit.domain.trim())) {
    const value = hit.domain.trim().toLowerCase();
    observables.push({ key: `Domain-Name:${value}`, type: 'Domain-Name', input: { DomainName: { value } } });
  }
  if (usable(hit.url)) {
    observables.push({ key: `Url:${hit.url.trim()}`, type: 'Url', input: { Url: { value: hit.url.trim() } } });
  }
  if (usable(hit.host)) {
    const value = hit.host.trim();
    observables.push({ key: `Hostname:${value}`, type: 'Hostname', input: { Hostname: { value } } });
  }
  if (usable(hit.user)) {
    const value = hit.user.trim();
    observables.push({ key: `User-Account:${value}`, type: 'User-Account', input: { UserAccount: { account_login: value } } });
  }
  if (usable(hit.file_hash)) {
    const hash = hit.file_hash.trim().toLowerCase();
    const algorithm = /^[a-f\d]+$/.test(hash) ? HASH_ALGORITHMS[hash.length] : undefined;
    if (algorithm) {
      observables.push({ key: `StixFile:${hash}`, type: 'StixFile', input: { StixFile: { hashes: [{ algorithm, hash }] } } });
    }
  }
  if (usable(hit.command_line)) {
    const value = hit.command_line.trim();
    observables.push({ key: `Process:${value}`, type: 'Process', input: { Process: { command_line: value } } });
  }
  return observables;
};

/**
 * One Observed Data per hit of the sample, with the observables it names, in the knowledge graph next to the
 * sightings of the connector: the observation dates are the date of the event (the run window when the hit has none).
 * Observables and observed data are upserted on their deterministic ids, a finalization replayed creates nothing twice.
 * A hit that fails is logged and skipped. Returns the internal ids of the observed data and observables created.
 */
export const createHuntHitObservations = async (context: AuthContext, hunt: BasicStoreEntityHunt, run: BasicStoreEntityHuntRun) => {
  const hits = (run.hit_sample ?? []).slice(0, HUNT_CONFIG.hitObservedDataMaxItems);
  // Loaded on use: the observable and observed data domains import the whole schema, the hunt module is part of it
  const [{ addStixCyberObservable }, { addObservedData }] = await Promise.all([import('../../domain/stixCyberObservable'), import('../../domain/observedData')]);
  const access = {
    objectMarking: run[RELATION_OBJECT_MARKING] ?? [],
    objectOrganization: run[RELATION_GRANTED_TO] ?? [],
    ...(hunt[RELATION_CREATED_BY] ? { createdBy: hunt[RELATION_CREATED_BY] } : {}),
  };
  const observableIds = new Map<string, string>();
  const observedDataIds = new Set<string>();
  for (let index = 0; index < hits.length; index += 1) {
    const hit = hits[index];
    try {
      const extracted = extractHitObservables(hit);
      const objectIds: string[] = [];
      for (let position = 0; position < extracted.length; position += 1) {
        const observable = extracted[position];
        let id = observableIds.get(observable.key);
        if (!id) {
          const created = await addStixCyberObservable(context, HUNT_MANAGER_USER, { type: observable.type, ...observable.input, ...access }) as BasicStoreEntity;
          id = created.internal_id;
          observableIds.set(observable.key, id);
        }
        objectIds.push(id);
      }
      if (objectIds.length > 0) {
        const observedAt = hit.timestamp ?? run.time_window_end ?? run.time_window_start;
        const observedData = await addObservedData(context, HUNT_MANAGER_USER, {
          first_observed: hit.timestamp ?? run.time_window_start ?? observedAt,
          last_observed: observedAt,
          number_observed: 1,
          objects: Array.from(new Set(objectIds)),
          ...access,
        }) as BasicStoreEntity;
        observedDataIds.add(observedData.internal_id);
      }
    } catch (error) {
      logApp.warn('[OPENCTI-MODULE] Hunt hit observation could not be created', { cause: error, runId: run.internal_id, hit: index });
    }
  }
  return { observedDataIds: Array.from(observedDataIds), observableIds: Array.from(new Set(observableIds.values())) };
};
