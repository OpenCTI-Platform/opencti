import { describe, expect, it } from 'vitest';
import { buildCsvLines } from '../../../src/http/httpRollingFeed';
import type { BasicStoreEntityFeed } from '../../../src/types/store';

const feed = {
  _index: 'opencti_internal_objects-000001',
  _id: 'internal-id',
  id: 'internal-id',
  sort: [
    9000000000
  ],
  name: 'test',
  description: '',
  filters: '{"mode":"and","filters":[],"filterGroups":[]}',
  separator: ';',
  feed_date_attribute: 'created_at',
  rolling_time: 60,
  include_header: true,
  feed_types: [
    'Indicator'
  ],
  feed_public: false,
  feed_attributes: [
    {
      mappings: [
        {
          attribute: 'name',
          type: 'Indicator'
        }
      ],
      attribute: 'value'
    },
    {
      mappings: [
        {
          attribute: 'description',
          type: 'Indicator'
        }
      ],
      attribute: 'description'
    }
  ],
  authorized_authorities: [
    'TAXIIAPI_SETCOLLECTIONS'
  ],
  confidence: 100,
  restricted_members: [
    {
      id: 'user-id',
      access_right: 'view'
    }
  ],
  entity_type: 'Feed',
  internal_id: 'internal-id',
  standard_id: 'feed--id',
  creator_id: [
    'user-id'
  ],
  base_type: 'ENTITY',
  parent_types: [
    'Basic-Object',
    'Internal-Object'
  ]
} as unknown as BasicStoreEntityFeed;

const elements = [{ _index: 'opencti_stix_domain_objects-000001', _id: 'test-id', id: 'test-id', sort: [1758547930892, 'test-id', 'indicator--id'], standard_id: 'indicator--id', parent_types: ['Basic-Object', 'Stix-Object', 'Stix-Core-Object', 'Stix-Domain-Object'], i_attributes: [{ updated_at: '2025-09-22T13:41:46.875Z', user_id: 'user-id', confidence: 100, name: 'description' }], decay_applied_rule: { decay_rule_id: 'dacay-rule-id', decay_lifetime: 470, decay_pound: 0.35, decay_points: [80, 50], decay_revoke_score: 20 }, pattern: 'fezfzefez', description: 'Triggered risk rules:\n\n|Rule|Severity|Score|\n|----|---|----|\n|Line 2| column 2| column 3|\n|Line 3| column 2| column 3|\n\n**bold test**\n\n*italic test*\n~~strikethrough~~\ntest', valid_from: '2025-09-22T13:32:10.875Z', created_at: '2025-09-22T13:32:10.892Z', revoked: false, decay_base_score_date: '2025-09-22T13:32:10.875Z', base_type: 'ENTITY', updated_at: '2025-09-22T13:41:46.875Z', modified: '2025-09-22T13:41:46.875Z', x_opencti_score: 50, lang: 'en', pattern_type: 'shodan', internal_id: 'test-id', created: '2025-09-22T13:32:10.892Z', confidence: 100, x_opencti_main_observable_type: 'Cryptocurrency-Wallet', x_mitre_platforms: [], decay_next_reaction_date: '2026-06-24T10:51:42.710Z', valid_until: '2026-06-24T10:51:42.710Z', entity_type: 'Indicator', indicator_types: [], name: 'CSV test', creator_id: ['user-id'], x_opencti_detection: false, decay_base_score: 50, x_opencti_stix_ids: [], decay_history: [{ updated_at: '2025-09-22T13:32:10.875Z', score: 50 }] }];

describe('buildCsvLines', () => {
  it('should convert elements to CSV expected format', () => {
    const expectedResultLines: string[] = [
      `CSV test;Triggered risk rules:

|Rule|Severity|Score|
|----|---|----|
|Line 2| column 2| column 3|
|Line 3| column 2| column 3|

**bold test**

*italic test*
~~strikethrough~~
test`,
    ];
    const resultLines = buildCsvLines(elements, feed);
    expect(resultLines).toEqual(expectedResultLines);
  });

  it('should replace double double quotes and ignore separator when formatting', () => {
    const descriptionWithIssues = 'Triggered risk rules:\n\n|Rule|Severity;|Score|\n|----|---|----|\n|Line 2| column" 2| column 3|\n|Line 3| column 2| column 3|\n\n**bold test**\n\n*italic test*\n~~strikethrough~~\n\ntest';
    const elementsWithCaractersToRemove = [{ ...elements[0], description: descriptionWithIssues }];

    const expectedResultLines: string[] = [
      `CSV test;"Triggered risk rules:

|Rule|Severity;|Score|
|----|---|----|
|Line 2| column"" 2| column 3|
|Line 3| column 2| column 3|

**bold test**

*italic test*
~~strikethrough~~

test"`];

    const resultLines = buildCsvLines(elementsWithCaractersToRemove, feed);
    expect(resultLines).toEqual(expectedResultLines);
  });
});
