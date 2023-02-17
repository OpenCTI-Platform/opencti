import { describe, expect, it } from 'vitest';
import { generateClusterNodes, generateNatMap } from '../../../src/database/redis';

describe('redis', () => {
  it('should cluster node configuration correctly generated', () => {
    const nodes = generateClusterNodes(['localhost:7000', 'localhost:7001']);
    expect(nodes.length).toBe(2);
    expect(nodes.at(0).host).toBe('localhost');
    expect(nodes.at(0).port).toBe(7000);
    expect(nodes.at(1).host).toBe('localhost');
    expect(nodes.at(1).port).toBe(7001);
  });

  it('should cluster nat map configuration correctly generated', () => {
    const nat = generateNatMap(['10.0.1.230:30001-203.0.113.73:30001', '10.0.1.231:30001-203.0.113.73:30002']);
    const entries = Object.entries(nat);
    expect(entries.length).toBe(2);
    const first = entries.at(0);
    expect(first.at(0)).toBe('10.0.1.230:30001');
    expect(first.at(1).host).toBe('203.0.113.73');
    expect(first.at(1).port).toBe(30001);
    const second = entries.at(1);
    expect(second.at(0)).toBe('10.0.1.231:30001');
    expect(second.at(1).host).toBe('203.0.113.73');
    expect(second.at(1).port).toBe(30002);
  });
});
