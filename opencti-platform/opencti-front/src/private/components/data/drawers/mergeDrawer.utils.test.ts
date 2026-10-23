import { describe, it, expect } from 'vitest';
import { computeMergePreview, type MergeElement } from './mergeDrawer.utils';

const apt28: MergeElement = { id: 'id-1', entity_type: 'Intrusion-Set', name: 'APT28', aliases: ['Sofacy'] };
const fancyBear: MergeElement = { id: 'id-2', entity_type: 'Intrusion-Set', name: 'Fancy Bear', aliases: ['Sednit', null] };
const strontium: MergeElement = { id: 'id-3', entity_type: 'Intrusion-Set', name: 'Strontium', aliases: null };

describe('Merge drawer preview', () => {
  it('should keep the first element when no element is chosen', () => {
    const preview = computeMergePreview([apt28, fancyBear], null);
    expect(preview.keptElement).toEqual(apt28);
    expect(preview.mergedElements).toEqual([fancyBear]);
    expect(preview.newAliases).toEqual(['Fancy Bear', 'Sofacy', 'Sednit']);
  });

  it('should keep the chosen element', () => {
    const preview = computeMergePreview([apt28, fancyBear, strontium], 'id-2');
    expect(preview.keptElement).toEqual(fancyBear);
    expect(preview.mergedElements).toEqual([apt28, strontium]);
    expect(preview.newAliases).toEqual(['APT28', 'Strontium', 'Sofacy', 'Sednit']);
  });

  it('should use the OpenCTI aliases when the kept element has no STIX aliases', () => {
    const john: MergeElement = { id: 'id-4', entity_type: 'Individual', name: 'John', aliases: null, x_opencti_aliases: ['Johnny'] };
    const jDoe: MergeElement = { id: 'id-5', entity_type: 'Individual', name: 'J. Doe', aliases: null, x_opencti_aliases: ['JD', ''] };
    const preview = computeMergePreview([john, jDoe], null);
    expect(preview.newAliases).toEqual(['J. Doe', 'Johnny', 'JD']);
  });

  it('should return an empty preview when the chosen element is not selected anymore', () => {
    const preview = computeMergePreview([apt28, fancyBear], 'id-unknown');
    expect(preview).toEqual({ keptElement: undefined, mergedElements: [], newAliases: [] });
  });
});
