import { describe, expect, it } from 'vitest';
import { extractRepresentative } from '../../../src/database/entity-representative';
import { ENTITY_TYPE_GROUP } from '../../../src/schema/internalObject';
import { ENTITY_TYPE_CONTAINER_CASE_INCIDENT } from '../../../src/modules/case/case-incident/case-incident-types';
import { ENTITY_TYPE_ATTACK_PATTERN, ENTITY_TYPE_CONTAINER_OPINION } from '../../../src/schema/stixDomainObject';

describe('entity-representative extractRepresentative', () => {
  it('should return an already computed representative as-is', () => {
    const existingRepresentative = { main: 'Restricted', secondary: 'Restricted' };
    const input = {
      entity_type: ENTITY_TYPE_ATTACK_PATTERN,
      name: 'Ignored name',
      representative: existingRepresentative,
    };
    const result = extractRepresentative(input as any);
    expect(result).toEqual(existingRepresentative);
  });

  it('should compute representative for stix core objects', () => {
    const input = {
      entity_type: ENTITY_TYPE_CONTAINER_CASE_INCIDENT,
      name: 'My incident',
      description: 'High-priority case',
    };

    const result = extractRepresentative(input as any);

    expect(result).toEqual({
      main: 'My incident',
      secondary: 'High-priority case',
    });
  });

  it('should compute representative for stix core objects with no description', () => {
    const input = {
      entity_type: ENTITY_TYPE_CONTAINER_OPINION,
      opinion: 'Good',
      name: 'My incident',
    };

    const result = extractRepresentative(input as any);

    expect(result).toEqual({
      main: 'Good',
      secondary: undefined,
    });
  });

  it('should compute representative for internal objects', () => {
    const input = {
      entity_type: ENTITY_TYPE_GROUP,
      name: 'My group',
    };

    const result = extractRepresentative(input as any);

    expect(result).toEqual({
      main: 'My group',
      secondary: undefined,
    });
  });

  it('should fallback to Unknown when no representative source exists', () => {
    const input = {
      entity_type: 'Settings',
    };

    const result = extractRepresentative(input as any);

    expect(result).toEqual({
      main: 'Unknown',
      secondary: undefined,
    });
  });

  it('should compute relationship representative when object is a relationship', () => {
    const input = {
      entity_type: 'related-to',
      fromName: 'APT41',
      toName: 'CVE-2024-0001',
      description: 'Relationship description',
    };

    const result = extractRepresentative(input as any);

    expect(result).toEqual({
      main: 'APT41 ➡️ CVE-2024-0001',
      secondary: 'Relationship description',
    });
  });
});
