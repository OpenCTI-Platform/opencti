import { describe, expect, it } from 'vitest';
import { createIntl } from 'react-intl';
import { resolveLink } from '../../../../utils/Entity';
import { huntRunKnowledge, huntRunResultLink } from './HuntRunResults';

describe('huntRunResultLink', () => {
  it('should link an object with a route of its own', () => {
    expect(huntRunResultLink({ id: 'sighting-1', entity_type: 'stix-sighting-relationship' }))
      .toEqual(`${resolveLink('stix-sighting-relationship')}/sighting-1`);
  });

  it('should link a relationship without a route under its source entity', () => {
    const relationship = { id: 'rel-1', entity_type: 'uses', from: { id: 'set-1', entity_type: 'Intrusion-Set' } };
    expect(huntRunResultLink(relationship)).toEqual(`${resolveLink('Intrusion-Set')}/set-1/knowledge/relations/rel-1`);
  });

  it('should give no link when neither the result nor its source has a route', () => {
    expect(huntRunResultLink({ id: 'rel-2', entity_type: 'uses' })).toBeNull();
    expect(huntRunResultLink({ id: 'rel-3', entity_type: 'uses', from: { id: 'x', entity_type: 'Unknown-Type' } })).toBeNull();
  });
});

describe('huntRunKnowledge', () => {
  const intl = createIntl({ locale: 'en', messages: {}, onError: () => {} });
  const t = (message: string, options?: { values: Record<string, string | number> }) => intl.formatMessage({ id: message, defaultMessage: message }, options?.values);
  const empty = { sightings: 0, observed_data: 0, observables: 0, others: 0 };
  const completed = { hunt_run_status: 'completed', hits_count: 12, security_platform_id: 'platform-1', hunt: { hunt_type: 'telemetry' } };
  const NO_OBSERVABLE = 'No observable: the hits carried no value of the types to extract, or the hunt connector does not support these types.';
  const NO_SIGHTING = 'No sighting: the hunt names no technique or indicator to sight.';
  const NO_PLATFORM = 'No sighting: the run has no security platform.';

  it('should count what a run produced by kind, in the singular or the plural, the incident included', () => {
    const knowledge = huntRunKnowledge({
      ...completed,
      incident_id: 'incident-1',
      results_summary: { sightings: 2, observed_data: 1, observables: 3, others: 1 },
    }, t);
    expect(knowledge).toEqual({ produced: '2 sightings, 1 observed data, 3 observables, 1 other object, 1 incident', reasons: [] });
  });

  it('should tell the sightings a run created from the ones of the hunt it updated, and hits added to an open incident', () => {
    const knowledge = huntRunKnowledge({
      ...completed,
      incident_id: 'incident-0',
      incident_continued: true,
      sightings_created_count: 1,
      results_summary: { sightings: 3, observed_data: 1, observables: 0, others: 0 },
    }, t);
    expect(knowledge?.produced).toEqual('1 sighting created, 2 sightings updated, 1 observed data, hits added to the open incident');
    const updatedOnly = huntRunKnowledge({ ...completed, sightings_created_count: 0, results_summary: { ...empty, sightings: 2, observables: 1 } }, t);
    expect(updatedOnly?.produced).toEqual('2 sightings updated, 1 observable');
  });

  it('should leave out the kinds a run did not produce', () => {
    const knowledge = huntRunKnowledge({ ...completed, results_summary: { ...empty, sightings: 1, observed_data: 4 } }, t);
    expect(knowledge).toEqual({ produced: '1 sighting, 4 observed data', reasons: [] });
  });

  it('should say why a completed run with hits produced only sightings', () => {
    const knowledge = huntRunKnowledge({ ...completed, results_summary: { ...empty, sightings: 3 } }, t);
    expect(knowledge).toEqual({ produced: '3 sightings', reasons: [NO_OBSERVABLE] });
  });

  it('should say why a completed telemetry run with hits produced nothing', () => {
    expect(huntRunKnowledge({ ...completed, results_summary: empty }, t)).toEqual({ produced: 'Nothing', reasons: [NO_SIGHTING, NO_OBSERVABLE] });
    // A hunt without a type is a detection rule hunt
    expect(huntRunKnowledge({ ...completed, hunt: { hunt_type: null }, results_summary: empty }, t)?.reasons).toEqual([NO_SIGHTING, NO_OBSERVABLE]);
  });

  it('should name the missing security platform as the reason a run with hits sighted nothing', () => {
    expect(huntRunKnowledge({ ...completed, security_platform_id: null, results_summary: { ...empty, observed_data: 2 } }, t))
      .toEqual({ produced: '2 observed data', reasons: [NO_PLATFORM] });
  });

  it('should give no observable reason to an indicator hunt, which extracts no observable type', () => {
    expect(huntRunKnowledge({ ...completed, hunt: { hunt_type: 'indicators' }, results_summary: { ...empty, sightings: 2 } }, t))
      .toEqual({ produced: '2 sightings', reasons: [] });
  });

  it('should give an infrastructure hunt the observable reason only, its runs sighting nothing', () => {
    expect(huntRunKnowledge({ ...completed, hunt: { hunt_type: 'infrastructure' }, results_summary: { ...empty, others: 2 } }, t))
      .toEqual({ produced: '2 other objects', reasons: [NO_OBSERVABLE] });
  });

  it('should give no reason for a run without hits, or of a hunt the user cannot read', () => {
    expect(huntRunKnowledge({ ...completed, hits_count: 0, results_summary: empty }, t)).toEqual({ produced: 'Nothing', reasons: [] });
    expect(huntRunKnowledge({ ...completed, hunt: null, results_summary: empty }, t)).toEqual({ produced: 'Nothing', reasons: [] });
  });

  it('should say nothing about a run that has not completed and produced nothing yet', () => {
    expect(huntRunKnowledge({ hunt_run_status: 'running', hits_count: 0, results_summary: empty }, t)).toBeNull();
    expect(huntRunKnowledge({ hunt_run_status: 'failed', results_summary: { ...empty, sightings: 1 } }, t))
      .toEqual({ produced: '1 sighting', reasons: [] });
  });
});
