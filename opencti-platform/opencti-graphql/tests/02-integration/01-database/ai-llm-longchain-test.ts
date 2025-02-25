import { describe, it, expect } from 'vitest';
import { queryAi } from '../../../src/database/ai-llm-longchain';

describe('Longchain AI test', () => {
  it.skip('should call', async () => {
    // Requires to have ai setup in json config to be run
    const result = await queryAi('Translate "I love programming" into French.');
    expect(result).toBeDefined();
    expect(result.content).toBeDefined();
    expect(result.content.length).toBeGreaterThan(0);
  });
});
