import { describe, it, expect } from 'vitest';
import { convertEventTypes, defenseEventTypesOptions } from './edition';

describe('Function: convertEventTypes', () => {
  it('should convert knowledge and defense matrix event types of a trigger to their options', () => {
    expect(convertEventTypes({ event_types: ['create', 'defense_level_decreased', 'defense_level_increased'] })).toEqual([
      { value: 'create', label: 'Creation' },
      { value: 'defense_level_decreased', label: 'Defense level decreased' },
      { value: 'defense_level_increased', label: 'Defense level increased' },
    ]);
  });

  it('should offer the defense matrix event types', () => {
    expect(defenseEventTypesOptions.map((option) => option.value)).toEqual(['defense_level_decreased', 'defense_level_increased']);
  });
});
