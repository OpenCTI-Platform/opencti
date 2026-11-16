/**
 * Pure helpers of the remote OpenCTI stream picker (RemoteStreamField): search,
 * order, optional grouping and the filter count shown on each row. Kept apart
 * from the component so they are unit tested without rendering anything.
 */

export interface RemoteStreamOption {
  value: string;
  label: string;
  id: string;
  name: string;
  description?: string | null;
  filters?: string | null;
}

/** Separator a remote platform may use to prefix its stream names with a family. */
const REMOTE_STREAM_GROUP_SEPARATOR = ' · ';

/** Lower case, accents removed, trimmed: what both the query and the stream text are compared on. */
const normalizeStreamSearch = (value?: string | null): string => (value ?? '')
  .normalize('NFD')
  .replace(/[\u0300-\u036f]/g, '')
  .toLowerCase()
  .trim();

/**
 * Keeps the streams whose name or description contains every word of the query,
 * case and accent insensitive. An empty query keeps them all, in their order.
 */
export const filterRemoteStreams = <T extends Pick<RemoteStreamOption, 'name' | 'description'>>(
  streams: T[],
  query: string,
): T[] => {
  const words = normalizeStreamSearch(query).split(/\s+/).filter((word) => word.length > 0);
  if (words.length === 0) return streams;
  return streams.filter((stream) => {
    const text = `${normalizeStreamSearch(stream.name)} ${normalizeStreamSearch(stream.description)}`;
    return words.every((word) => text.includes(word));
  });
};

/** Streams ordered by name, accent and case insensitive, without changing the input. */
export const sortRemoteStreams = <T extends Pick<RemoteStreamOption, 'name'>>(streams: T[]): T[] => [...streams]
  .sort((a, b) => (a.name ?? '').localeCompare(b.name ?? '', undefined, { sensitivity: 'base' }));

/**
 * Splits a name on its first separator. A name without one, or with an empty
 * part on either side, has no group.
 */
export const splitStreamName = (name?: string | null): { group: string | null; title: string } => {
  const value = name ?? '';
  const index = value.indexOf(REMOTE_STREAM_GROUP_SEPARATOR);
  if (index <= 0) return { group: null, title: value };
  const group = value.slice(0, index).trim();
  const title = value.slice(index + REMOTE_STREAM_GROUP_SEPARATOR.length).trim();
  if (group.length === 0 || title.length === 0) return { group: null, title: value };
  return { group, title };
};

/** Group headers only make sense when every stream carries one: a partial grouping would leave orphans. */
export const shouldGroupRemoteStreams = (streams: Pick<RemoteStreamOption, 'name'>[]): boolean => streams.length > 0
  && streams.every((stream) => splitStreamName(stream.name).group !== null);

type SerializedFilterGroup = {
  filters?: unknown[];
  filterGroups?: SerializedFilterGroup[];
};

const countGroupFilters = (group?: SerializedFilterGroup | null): number => {
  if (!group || typeof group !== 'object') return 0;
  const own = Array.isArray(group.filters) ? group.filters.length : 0;
  const nested = Array.isArray(group.filterGroups)
    ? group.filterGroups.reduce((total, child) => total + countGroupFilters(child), 0)
    : 0;
  return own + nested;
};

/** Number of filters of a stream's serialized filter group, nested groups included; 0 when absent or unreadable. */
export const countRemoteStreamFilters = (filters?: string | null): number => {
  if (!filters) return 0;
  try {
    return countGroupFilters(JSON.parse(filters) as SerializedFilterGroup);
  } catch {
    return 0;
  }
};
