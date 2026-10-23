import { describe, it, expect } from 'vitest';
import {
  addStep,
  areStepsValid,
  buildUpdateActions,
  changeStepKey,
  isTemporalFieldRemoval,
  removeStep,
  setStepInputValue,
  setStepOption,
  setStepSwitchValue,
  setStepValues,
  type UpdateStep,
} from './dataTableToolBarUpdateSteps';

describe('DataTableToolBar update steps', () => {
  it('should never mutate the given steps', () => {
    const steps: UpdateStep[] = [{ type: 'ADD' }];
    const frozen = Object.freeze(steps.map((step) => Object.freeze(step)));
    expect(() => changeStepKey(frozen, 0, 'field', 'object-label')).not.toThrow();
    expect(changeStepKey(frozen, 0, 'field', 'object-label')).not.toBe(frozen);
    expect(frozen).toEqual([{ type: 'ADD' }]);
  });

  it('should add and remove steps', () => {
    const steps = addStep([{ type: 'ADD' }]);
    expect(steps).toEqual([{ type: 'ADD' }, {}]);
    expect(removeStep([{ type: 'ADD' }, { type: 'REPLACE' }, { type: 'REMOVE' }], 1)).toEqual([{ type: 'ADD' }, { type: 'REMOVE' }]);
  });

  describe('changeStepKey', () => {
    it('should only set the type', () => {
      expect(changeStepKey([{ field: 'description', values: ['x'] }], 0, 'type', 'REPLACE'))
        .toEqual([{ type: 'REPLACE', field: 'description', values: ['x'] }]);
    });

    it('should reset the values and set the field type when the field changes', () => {
      expect(changeStepKey([{ type: 'ADD', values: ['old'] }], 0, 'field', 'object-marking'))
        .toEqual([{ type: 'ADD', field: 'object-marking', values: [], fieldType: 'RELATION' }]);
      expect(changeStepKey([{ type: 'REPLACE' }], 0, 'field', 'description'))
        .toEqual([{ type: 'REPLACE', field: 'description', values: [], fieldType: 'ATTRIBUTE' }]);
    });

    it('should give a default value to some fields', () => {
      expect(changeStepKey([{ type: 'REPLACE' }], 0, 'field', 'x_opencti_detection')[0].values).toEqual(['false']);
      expect(changeStepKey([{ type: 'REMOVE' }], 0, 'field', 'start_time')[0].values).toEqual(['']);
      expect(changeStepKey([{ type: 'ADD' }], 0, 'field', 'start_time')[0].values).toEqual([]);
      const definitions = [{ name: 'x_opencti_cf_flag', field_type: 'boolean' }];
      expect(changeStepKey([{ type: 'REPLACE' }], 0, 'field', 'x_opencti_cf_flag', definitions)[0].values).toEqual(['false']);
      expect(changeStepKey([{ type: 'REMOVE' }], 0, 'field', 'x_opencti_cf_flag', definitions)[0].values).toEqual([]);
    });

    it('should create the step when it does not exist yet', () => {
      expect(changeStepKey([], 0, 'type', 'ADD')).toEqual([{ type: 'ADD' }]);
    });
  });

  it('should set values, options, input value and switch value', () => {
    expect(setStepValues([{}], 0, 'one')).toEqual([{ values: ['one'] }]);
    expect(setStepValues([{}], 0, ['one', 'two'])).toEqual([{ values: ['one', 'two'] }]);
    expect(setStepOption([{ options: { a: true } }], 0, 'includeNeighbours', 'yes')).toEqual([{ options: { a: true, includeNeighbours: false } }]);
    expect(setStepOption([{}], 0, 'includeNeighbours', true)).toEqual([{ options: { includeNeighbours: true } }]);
    expect(setStepInputValue([{}], 0, 'apt')).toEqual([{ inputValue: 'apt' }]);
    expect(setStepInputValue([{}], 0, null)).toEqual([{ inputValue: '' }]);
    expect(setStepInputValue([{}], 0, new Date())).toEqual([{ inputValue: '' }]);
    expect(setStepSwitchValue([{}], 0, 'values', true)).toEqual([{ values: ['true'] }]);
  });

  it('should detect the removal of a temporal field', () => {
    expect(isTemporalFieldRemoval({ type: 'REMOVE', field: 'stop_time' })).toEqual(true);
    expect(isTemporalFieldRemoval({ type: 'ADD', field: 'stop_time' })).toEqual(false);
    expect(isTemporalFieldRemoval(undefined)).toEqual(false);
  });

  describe('areStepsValid', () => {
    it('should require a type, a field and at least one value', () => {
      expect(areStepsValid([{ type: 'ADD', field: 'object-label', values: ['id'] }])).toEqual(true);
      expect(areStepsValid([{ type: 'ADD', field: 'object-label', values: [] }])).toEqual(false);
      expect(areStepsValid([{ type: 'ADD', field: 'object-label' }])).toEqual(false);
      expect(areStepsValid([{ type: 'ADD', values: ['id'] }])).toEqual(false);
      expect(areStepsValid([{}])).toEqual(false);
    });

    it('should accept the removal of a custom field without value', () => {
      expect(areStepsValid([{ type: 'REMOVE', field: 'x_opencti_cf_note', values: [] }])).toEqual(true);
    });

    it('should reject empty slots', () => {
      const steps: UpdateStep[] = [];
      steps[1] = { type: 'ADD', field: 'object-label', values: ['id'] };
      expect(areStepsValid(steps)).toEqual(false);
    });
  });

  it('should build the task actions and map the vocabulary fields', () => {
    expect(buildUpdateActions([
      { type: 'ADD', field: 'object-label', fieldType: 'RELATION', values: [{ value: 'id-1' }], options: { includeNeighbours: true } },
      { type: 'REPLACE', field: 'case_severity_ov', fieldType: 'ATTRIBUTE', values: [{ label: 'high', value: 'id-2' }] },
    ])).toEqual([
      { type: 'ADD', context: { field: 'object-label', type: 'RELATION', values: [{ value: 'id-1' }], options: { includeNeighbours: true } } },
      { type: 'REPLACE', context: { field: 'severity', type: 'ATTRIBUTE', values: ['high'], options: undefined } },
    ]);
  });
});
