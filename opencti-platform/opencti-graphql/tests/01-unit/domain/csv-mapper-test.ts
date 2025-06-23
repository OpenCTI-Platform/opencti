import { describe, it, expect } from 'vitest';
import type { CsvMapperParsed } from '../../../src/modules/internal/csvMapper/csvMapper-types';
import type { AuthContext, AuthUser } from '../../../src/types/user';
import { transformCsvMapperConfig } from '../../../src/modules/internal/csvMapper/csvMapper-domain';

describe('transformCsvMapperConfig', () => {
  it('should transform the CSV Mapper configuration successfully', async () => {
    const configuration: CsvMapperParsed = {
      id: 'debf1d1e-de97-4dd8-abb6-1b22e19468f6',
      name: 'Inline CSV Feed',
      has_header: false,
      separator: ';',
      representations: [
        {
          id: '1a3738ce-a0b2-40fb-a7fc-556e9ab97f43',
          type: 'entity',
          target: {
            entity_type: 'Url',
            column_based: null,
          },
          attributes: [
            {
              key: 'x_opencti_description',
              column: {
                column_name: 'A',
                configuration: null
              },
              default_values: null,
              based_on: null
            },
            {
              key: 'value',
              column: {
                column_name: 'A',
                configuration: null
              },
              default_values: null,
              based_on: null
            }
          ]
        },
        {
          id: 'eb53977e-1bf0-4c9b-8d0a-07e3b298d02b',
          type: 'entity',
          target: {
            entity_type: 'Credential',
            column_based: null,
          },
          attributes: [
            {
              key: 'value',
              column: {
                column_name: 'B',
                configuration: null
              },
              default_values: null,
              based_on: null
            },
            {
              key: 'x_opencti_description',
              column: {
                column_name: 'B',
                configuration: null
              },
              default_values: null,
              based_on: null
            }
          ]
        },
        {
          id: 'f2e9f1ec-f988-40e3-bb8e-aae2a93257c8',
          type: 'relationship',
          target: {
            entity_type: 'related-to',
            column_based: null,
          },
          attributes: [
            {
              key: 'from',
              column: null,
              default_values: null,
              based_on: {
                representations: ['eb53977e-1bf0-4c9b-8d0a-07e3b298d02b']
              }
            },
            {
              key: 'to',
              column: null,
              default_values: null,
              based_on: {
                representations: ['1a3738ce-a0b2-40fb-a7fc-556e9ab97f43']
              }
            }
          ]
        }
      ],
      skipLineChar: ''
    } as unknown as CsvMapperParsed;

    const context: AuthContext = {} as unknown as AuthContext; // Mock
    const user: AuthUser = {} as unknown as AuthUser; // Mock

    const result = await transformCsvMapperConfig(configuration, context, user);

    expect(result).toHaveProperty('representations');
    expect(result.representations.length).toBe(3);
    expect(result.representations[0].id).toBe('1a3738ce-a0b2-40fb-a7fc-556e9ab97f43');
  });
});
