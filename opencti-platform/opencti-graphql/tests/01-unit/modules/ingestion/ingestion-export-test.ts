import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../../src/database/cache', () => ({ getEntitiesMapFromCache: vi.fn() }));
vi.mock('../../../../src/database/middleware-loader', () => ({ internalLoadById: vi.fn() }));
vi.mock('../../../../src/modules/internal/mapper-utils', () => ({ convertRepresentationsIds: vi.fn() }));
vi.mock('../../../../src/modules/internal/jsonMapper/jsonMapper-domain', () => ({ findById: vi.fn() }));
vi.mock('../../../../src/modules/ingestion/ingestion-csv-domain', () => ({ findCsvMapperForIngestionById: vi.fn() }));

import { getEntitiesMapFromCache } from '../../../../src/database/cache';
import { findById as findJsonMapperById } from '../../../../src/modules/internal/jsonMapper/jsonMapper-domain';
import { exportCsvFeed, exportJsonFeed } from '../../../../src/modules/ingestion/ingestion-export';
import type { BasicStoreEntityIngestionCsv, BasicStoreEntityIngestionJson } from '../../../../src/modules/ingestion/ingestion-types';
import type { AuthContext, AuthUser } from '../../../../src/types/user';

const context = { source: 'test' } as AuthContext;
const user = { id: 'user-id' } as AuthUser;
const SECRET = 's3cret-value';
const representations = [{ id: 'indicator', type: 'entity', target: { entity_type: 'Indicator' }, attributes: [{ key: 'name', mode: 'simple' }] }];

beforeEach(() => {
  vi.resetAllMocks();
  vi.mocked(getEntitiesMapFromCache).mockResolvedValue(new Map() as never);
});

describe('exportJsonFeed', () => {
  it('blanks the sensitive headers, query attribute defaults and URI secrets, and embeds the mapper', async () => {
    vi.mocked(findJsonMapperById).mockResolvedValue({ name: 'Vendor mapper', variables: '[]', representations: JSON.stringify(representations) } as never);
    const feed = {
      name: 'Vendor API',
      uri: `https://reader:${SECRET}@api.example.com/indicators?apikey=${SECRET}&limit=10`,
      authentication_type: 'none',
      verb: 'get',
      headers: [{ name: 'Accept', value: 'application/json' }, { name: 'Authorization', value: SECRET }],
      query_attributes: [
        { type: 'header', from: 'x-next', to: 'X-Api-Token', default: SECRET, exposed: 'header' },
        { type: 'data', from: '$.key', to: 'api_key', default: SECRET, exposed: 'query_param' },
        { type: 'data', from: '$.next', to: 'cursor', default: 'first', exposed: 'query_param' },
      ],
      json_mapper_id: 'mapper-id',
    } as unknown as BasicStoreEntityIngestionJson;
    const exported = await exportJsonFeed(context, user, feed);
    expect(JSON.stringify(exported)).not.toContain(SECRET);
    expect(exported.uri).toEqual('https://reader@api.example.com/indicators?apikey=&limit=10');
    expect(exported.headers).toEqual([{ name: 'Accept', value: 'application/json' }, { name: 'Authorization', value: '' }]);
    expect(exported.query_attributes.map(({ to, default: value }) => [to, value])).toEqual([['X-Api-Token', ''], ['api_key', ''], ['cursor', 'first']]);
    expect(exported.json_mapper).toEqual({ name: 'Vendor mapper', variables: [], representations });
  });
});

describe('exportCsvFeed', () => {
  it('blanks the URI secrets, never writes the authentication value, and embeds the inline mapper', async () => {
    const mapper = { name: 'Vendor mapper', has_header: true, separator: ';', skipLineChar: null, representations };
    const feed = {
      name: 'Vendor CSV',
      uri: `https://csv.example.com/indicators.csv?token=${SECRET}`,
      authentication_type: 'basic',
      authentication_value: `analyst:${SECRET}`,
      csv_mapper_type: 'inline',
      csv_mapper: JSON.stringify(mapper),
    } as unknown as BasicStoreEntityIngestionCsv;
    const exported = await exportCsvFeed(context, user, feed);
    expect(JSON.stringify(exported)).not.toContain(SECRET);
    expect(exported).not.toHaveProperty('authentication_value');
    expect(exported.uri).toEqual('https://csv.example.com/indicators.csv?token=');
    expect(exported.csv_mapper).toEqual(mapper);
  });
});
