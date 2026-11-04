import { describe, expect, it, vi } from 'vitest';
import { resolveCsvMapperParsed } from '../../../../src/modules/ingestion/ingestion-csv-domain';
import { findById as findCsvMapperById } from '../../../../src/modules/internal/csvMapper/csvMapper-domain';
import { IngestionCsvMapperType } from '../../../../src/generated/graphql';
import type { AuthContext, AuthUser } from '../../../../src/types/user';

vi.mock('../../../../src/modules/internal/csvMapper/csvMapper-domain', async (importOriginal) => {
  const original = await importOriginal<typeof import('../../../../src/modules/internal/csvMapper/csvMapper-domain')>();
  return { ...original, findById: vi.fn() };
});

const context = {} as AuthContext;
const user = { id: 'user--1' } as AuthUser;
const representations = [{ id: 'representation-1', type: 'entity', target: { entity_type: 'City' }, attributes: [] }];

describe('ingestion-csv-domain: resolveCsvMapperParsed', () => {
  it('should parse an inline mapper', async () => {
    const mapper = { name: 'inline mapper', has_header: true, separator: ';', representations };

    const parsed = await resolveCsvMapperParsed(context, user, { csv_mapper_type: IngestionCsvMapperType.Inline, csv_mapper: JSON.stringify(mapper) });

    expect(parsed).toEqual(mapper);
    expect(findCsvMapperById).not.toHaveBeenCalled();
  });

  it('should load a referenced mapper and parse its stringified representations', async () => {
    vi.mocked(findCsvMapperById).mockResolvedValue({ name: 'stored mapper', has_header: false, separator: ',', representations: JSON.stringify(representations) } as any);

    const parsed = await resolveCsvMapperParsed(context, user, { csv_mapper_type: IngestionCsvMapperType.Id, csv_mapper_id: 'mapper-id' });

    expect(findCsvMapperById).toHaveBeenCalledWith(context, user, 'mapper-id');
    expect(parsed).toEqual({ name: 'stored mapper', has_header: false, separator: ',', representations });
  });
});
