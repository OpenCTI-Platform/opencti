import { describe, it, expect } from 'vitest';
import '../../../src/modules/index';
import { convertStoreToStix_2_1 } from '../../../src/database/stix-2-1-converter';
import type { StixNarrative } from '../../../src/modules/narrative/narrative-types';
import type { StixChannel } from '../../../src/modules/channel/channel-types';
import type { StixEvent } from '../../../src/modules/event/event-types';
import { NARRATIVE_INSTANCE } from './stix-2-0-converter-fixtures/SDOs/techniques/narrative';
import { CHANNEL_INSTANCE } from './stix-2-0-converter-fixtures/SDOs/arsenal/channel';
import { EVENT_INSTANCE } from './stix-2-0-converter-fixtures/SDOs/entities/event';

// Narrative, Channel and Event store their aliases in `aliases` (see resolveAliasesField),
// not in `x_opencti_aliases`: the STIX 2.1 output must expose them.
describe('STIX 2.1 converter - aliases', () => {
  it('should expose the stored aliases on Narrative', () => {
    const stix = convertStoreToStix_2_1({ ...NARRATIVE_INSTANCE, aliases: ['narrative alias'] } as any) as StixNarrative;
    expect(stix.aliases).toEqual(['narrative alias']);
  });

  it('should expose the stored aliases on Channel', () => {
    const stix = convertStoreToStix_2_1({ ...CHANNEL_INSTANCE, aliases: ['channel alias'] } as any) as StixChannel;
    expect(stix.aliases).toEqual(['channel alias']);
  });

  it('should expose the stored aliases on Event', () => {
    const stix = convertStoreToStix_2_1({ ...EVENT_INSTANCE, aliases: ['event alias'] } as any) as StixEvent;
    expect(stix.aliases).toEqual(['event alias']);
  });
});
