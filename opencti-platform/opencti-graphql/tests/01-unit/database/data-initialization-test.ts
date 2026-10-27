import { describe, expect, it } from 'vitest';
import { findCapabilityDescription } from '../../../src/database/data-initialization';

describe('findCapabilityDescription', () => {
  it('should find the description of a root capability', () => {
    expect(findCapabilityDescription('CONNECTORAPI')).toBe('Connectors API usage: register, ping, export push ...');
  });

  it('should find the description of a nested capability by its full name', () => {
    expect(findCapabilityDescription('INGESTION_SETINGESTIONS')).toBe('Manage ingestion');
  });

  it('should return undefined for an unknown capability, or a nested one by its short name', () => {
    expect(findCapabilityDescription('UNKNOWN')).toBeUndefined();
    expect(findCapabilityDescription('SETINGESTIONS')).toBeUndefined();
  });
});
