import { describe, it, expect } from 'vitest';
import {
  toAssigneeOptions,
  toContainerOptions,
  toExternalReferenceOptions,
  toKillChainPhaseOptions,
  toLabelOptions,
  toStatusOptions,
  toVocabularyOptions,
} from './dataTableToolBarStepOptions';

// The mappers only read a few fields of the query data
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const data = (value: unknown) => value as any;

describe('DataTableToolBar step options', () => {
  it('should sort the containers by type, then by name', () => {
    const options = toContainerOptions(data({
      containers: {
        edges: [
          { node: { id: '1', entity_type: 'Report', representative: { main: 'Zeta report' } } },
          { node: { id: '2', entity_type: 'Grouping', representative: { main: 'Beta grouping' } } },
          { node: { id: '3', entity_type: 'Report', representative: { main: 'Alpha report' } } },
        ],
      },
    }));
    expect(options).toEqual([
      { label: 'Beta grouping', type: 'Grouping', value: '2' },
      { label: 'Alpha report', type: 'Report', value: '3' },
      { label: 'Zeta report', type: 'Report', value: '1' },
    ]);
  });

  it('should return no option when the data is empty', () => {
    expect(toContainerOptions(data({ containers: null }))).toEqual([]);
    expect(toLabelOptions(data(null))).toEqual([]);
  });

  it('should keep the label colors', () => {
    expect(toLabelOptions(data({
      labels: { edges: [{ node: { id: '1', value: 'phishing', color: '#ff0000' } }, { node: { id: '2', value: 'apt', color: '#00ff00' } }] },
    }))).toEqual([
      { label: 'apt', value: '2', color: '#00ff00' },
      { label: 'phishing', value: '1', color: '#ff0000' },
    ]);
  });

  it('should build the external reference labels', () => {
    expect(toExternalReferenceOptions(data({
      externalReferences: {
        edges: [
          { node: { id: '1', source_name: 'mitre-attack', external_id: 'T1566', description: null, url: 'https://attack.mitre.org/T1566' } },
          { node: { id: '2', source_name: 'cve', external_id: 'CVE-2024-1', description: null, url: null } },
        ],
      },
    }))).toEqual([
      { label: '[cve] CVE-2024-1 null', value: '2' },
      { label: '[mitre-attack] T1566 (https://attack.mitre.org/T1566)', value: '1' },
    ]);
  });

  it('should sort the statuses by order', () => {
    expect(toStatusOptions(data({
      statuses: {
        edges: [
          { node: { id: '2', order: 2, template: { name: 'Analyzed', color: '#00ff00' } } },
          { node: { id: '1', order: 1, template: { name: 'New', color: '#0000ff' } } },
        ],
      },
    })).map((option) => option.label)).toEqual(['New', 'Analyzed']);
  });

  it('should sort the kill chain phases by their OpenCTI order', () => {
    expect(toKillChainPhaseOptions(data({
      killChainPhases: {
        edges: [
          { node: { id: '2', kill_chain_name: 'mitre-attack', phase_name: 'execution', x_opencti_order: 4 } },
          { node: { id: '1', kill_chain_name: 'mitre-attack', phase_name: 'reconnaissance', x_opencti_order: 1 } },
        ],
      },
    }))).toEqual([
      { label: '[mitre-attack] reconnaissance', value: '1' },
      { label: '[mitre-attack] execution', value: '2' },
    ]);
  });

  it('should keep the order of the vocabularies and the assignees', () => {
    expect(toVocabularyOptions(data({
      vocabularies: { edges: [{ node: { id: '1', name: 'low' } }, { node: { id: '2', name: 'high' } }] },
    })).map((option) => option.label)).toEqual(['low', 'high']);
    const zoe = { id: '1', name: 'Zoe', entity_type: 'User' };
    const adam = { id: '2', name: 'Adam', entity_type: 'User' };
    expect(toAssigneeOptions(data({ members: { edges: [{ node: zoe }, { node: adam }] } }))).toEqual([
      { label: 'Zoe', value: '1', type: 'User', entity: zoe },
      { label: 'Adam', value: '2', type: 'User', entity: adam },
    ]);
  });
});
