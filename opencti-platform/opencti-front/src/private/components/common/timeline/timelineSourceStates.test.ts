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

  it('should label hunt runs by their verdict once decided, by the state of the run otherwise', () => {
    expect(resolveTimelineSourceState({ family: 'hunt_run', state: 'completed', verdict: 'true_positive' })).toEqual({ label: 'True positive', severity: 'high' });
    expect(resolveTimelineSourceState({ family: 'hunt_run', state: 'completed', verdict: 'benign' })).toEqual({ label: 'Benign', severity: 'low' });
    expect(resolveTimelineSourceState({ family: 'hunt_run', state: 'completed', verdict: 'pending' })).toEqual({ label: 'Completed', severity: 'low' });
    expect(resolveTimelineSourceState({ family: 'hunt_run', state: 'timeout', verdict: null })).toEqual({ label: 'Timed out', severity: 'high' });
    expect(resolveTimelineSourceState({ family: 'hunt_run', state: 'queued' })).toEqual({ label: 'Queued', severity: 'neutral' });
  });

  it('should label deployments by their validation once proven, by their status otherwise', () => {
    expect(resolveTimelineSourceState({ family: 'deployment', state: 'active', validation: 'missed' })).toEqual({ label: 'Missed', severity: 'high' });
    expect(resolveTimelineSourceState({ family: 'deployment', state: 'active', validation: 'prevented' })).toEqual({ label: 'Prevented', severity: 'low' });
    expect(resolveTimelineSourceState({ family: 'deployment', state: 'deployed', validation: 'not_requested' })).toEqual({ label: 'Deployed', severity: 'low' });
    expect(resolveTimelineSourceState({ family: 'deployment', state: 'expired' })).toEqual({ label: 'Expired', severity: 'neutral', dimmed: true });
  });

  it('should label investigation runs by the state of the run', () => {
    expect(resolveTimelineSourceState({ family: 'investigation_run', state: 'running' })).toEqual({ label: 'Running', severity: 'info' });
    expect(resolveTimelineSourceState({ family: 'investigation_run', state: 'succeeded' })).toEqual({ label: 'Completed', severity: 'low' });
    expect(resolveTimelineSourceState({ family: 'investigation_run', state: 'cancelled' })).toEqual({ label: 'Cancelled', severity: 'neutral', dimmed: true });
  });

  it('should show nothing for a state no owner labels, never the raw value', () => {
    expect(resolveTimelineSourceState({ family: 'investigation_step', state: 'mystery' })).toBeNull();
    expect(resolveTimelineSourceState({ family: 'hunt_run', state: 'constructor' })).toBeNull();
    expect(resolveTimelineSourceState({ family: 'deployment', state: 'unknown', validation: 'requested' })).toBeNull();
    expect(resolveTimelineSourceState({ family: 'unknown_family', state: 'completed' })).toBeNull();
    expect(toInvestigationStepState('toString')).toBeNull();
    expect(resolveTimelineSourceState(null)).toBeNull();
  });
});
