import { describe, expect, it } from 'vitest';
import { INVESTIGATION_STEP_STATES, resolveTimelineSourceState, toInvestigationStepState } from './timelineSourceStates';

describe('Timeline source states', () => {
  it('should read the engine step states with the seven step states of the program', () => {
    expect(toInvestigationStepState('completed')).toEqual('found');
    expect(toInvestigationStepState('succeeded')).toEqual('found');
    expect(toInvestigationStepState('empty')).toEqual('nothing_found');
    expect(toInvestigationStepState('degraded')).toEqual('partial');
    expect(toInvestigationStepState('ERROR')).toEqual('failed');
    expect(toInvestigationStepState('skipped')).toEqual('not_reached');
    expect(toInvestigationStepState('running')).toEqual('querying');
    expect(toInvestigationStepState('planned')).toEqual('planned');
    expect(toInvestigationStepState('something else')).toBeNull();
    expect(toInvestigationStepState(null)).toBeNull();
  });

  it('should give each step state its fixed label and tone', () => {
    expect(resolveTimelineSourceState({ family: 'investigation_step', state: 'completed' })).toEqual({ label: 'Found', severity: 'low' });
    expect(resolveTimelineSourceState({ family: 'investigation_step', state: 'error' })).toEqual({ label: 'Failed', severity: 'high' });
    expect(resolveTimelineSourceState({ family: 'investigation_step', state: 'skipped' })).toEqual(INVESTIGATION_STEP_STATES.not_reached);
  });

  it('should show nothing for a state no owner labels, never the raw value', () => {
    expect(resolveTimelineSourceState({ family: 'investigation_step', state: 'mystery' })).toBeNull();
    // A family whose owner registered no labels on this platform
    expect(resolveTimelineSourceState({ family: 'hunt_run', state: 'completed', verdict: 'true_positive' })).toBeNull();
    expect(resolveTimelineSourceState(null)).toBeNull();
  });
});
