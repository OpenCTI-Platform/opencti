import { describe, expect, it } from 'vitest';
import { extractRepresentative } from '../../../src/database/entity-representative';
import { ENTITY_TYPE_GROUP, ENTITY_TYPE_SETTINGS } from '../../../src/schema/internalObject';
import { ENTITY_TYPE_CONTAINER_CASE_INCIDENT } from '../../../src/modules/case/case-incident/case-incident-types';
import { ENTITY_TYPE_ATTACK_PATTERN, ENTITY_TYPE_CONTAINER_OPINION } from '../../../src/schema/stixDomainObject';
import { ENTITY_TYPE_DELETE_OPERATION } from '../../../src/modules/deleteOperation/deleteOperation-types';
import { ENTITY_TYPE_ENTITY_SETTING } from '../../../src/modules/entitySetting/entitySetting-types';
import { ENTITY_TYPE_MANAGER_CONFIGURATION } from '../../../src/modules/managerConfiguration/managerConfiguration-types';
import { ENTITY_TYPE_NEWS_FEED_ITEM } from '../../../src/modules/xtm/hub/news-feed/news-feed-types';

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

  it('should fallback to entity type or Unknown when no representative source exists', () => {
    const input = {
      entity_type: ENTITY_TYPE_SETTINGS,
    };
    const result = extractRepresentative(input as any);
    expect(result).toEqual({
      main: 'Unknown',
      secondary: undefined,
    });
  });

  it('should use title for NewsFeedItem representative', () => {
    const input = {
      entity_type: ENTITY_TYPE_NEWS_FEED_ITEM,
      title: 'Security digest',
      name: 'Ignored',
    };

    const result = extractRepresentative(input as any);

    expect(result).toEqual({
      main: 'Security digest',
      secondary: undefined,
    });
  });

  it('should use main_entity_name for DeleteOperation representative', () => {
    const input = {
      entity_type: ENTITY_TYPE_DELETE_OPERATION,
      main_entity_name: 'Intrusion Set A',
      name: 'Ignored',
    };

    const result = extractRepresentative(input as any);

    expect(result).toEqual({
      main: 'Intrusion Set A',
      secondary: undefined,
    });
  });

  it('should use platform_title for Settings representative', () => {
    const input = {
      entity_type: ENTITY_TYPE_SETTINGS,
      platform_title: 'OpenCTI Platform',
      name: 'Ignored',
    };

    const result = extractRepresentative(input as any);

    expect(result).toEqual({
      main: 'OpenCTI Platform',
      secondary: undefined,
    });
  });

  it('should use target_type for EntitySetting representative', () => {
    const input = {
      entity_type: ENTITY_TYPE_ENTITY_SETTING,
      target_type: 'Report',
      name: 'Ignored',
    };

    const result = extractRepresentative(input as any);

    expect(result).toEqual({
      main: 'Report',
      secondary: undefined,
    });
  });

  it('should use manager_id for ManagerConfiguration representative', () => {
    const input = {
      entity_type: ENTITY_TYPE_MANAGER_CONFIGURATION,
      manager_id: 'rules-manager',
      name: 'Ignored',
    };

    const result = extractRepresentative(input as any);

    expect(result).toEqual({
      main: 'rules-manager',
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
