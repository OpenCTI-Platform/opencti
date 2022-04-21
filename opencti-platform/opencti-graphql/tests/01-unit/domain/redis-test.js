// region data
import * as jsonpatch from 'fast-json-patch';
import * as R from 'ramda';

const previous = {
  id: 'attack-pattern--489a7797-01c3-4706-8cd1-ec56a9db3adc',
  type: 'attack-pattern',
  spec_version: '2.1',
  name: 'Spear phishing messages with malicious links',
  labels: ['attack-pattern', 'new-label'],
  description: 'Old description',
  created: '2017-12-14T16:46:06.044Z',
  modified: '2018-10-17T00:14:20.652Z',
  created_by_ref: 'identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5',
  object_marking_refs: ['marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802167', 'marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168'],
  kill_chain_phases: [
    {
      kill_chain_name: 'mitre-delete-attack',
      phase_name: 'to-delete',
      extensions: {
        'extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba': {
          extension_type: 'property-extension',
          id: '13956dbd-8d1d-4777-a476-7c7247b9de81',
          type: 'Kill-Chain-Phase',
          created_at: '2022-04-18T22:47:25.821Z',
          is_inferred: false
        }
      }
    },
    {
      kill_chain_name: 'mitre-pre-attack',
      phase_name: 'launch',
      extensions: {
        'extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba': {
          extension_type: 'property-extension',
          id: '93956dbd-8d1d-4777-a476-7c7247b9de81',
          type: 'Kill-Chain-Phase',
          created_at: '2022-04-18T22:47:25.821Z',
          is_inferred: false,
          order: 20
        }
      }
    }
  ],
  extensions: {
    'extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba': {
      extension_type: 'property-extension',
      id: '93b3ecf3-8b66-4d11-90bb-440b9fc1f278',
      order: 11,
      complex: {
        random: 'from'
      }
    },
  },
};
const after = {
  id: 'attack-pattern--489a7797-01c3-4706-8cd1-ec56a9db3adc',
  type: 'attack-pattern',
  spec_version: '2.1',
  spec_test: '2.1',
  name: 'Spear phishing messages with malicious links',
  labels: ['attack-pattern'],
  description: 'New description',
  created: '2017-12-14T16:46:06.044Z',
  modified: '2018-10-17T00:14:20.652Z',
  created_by_ref: 'identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b6',
  object_marking_refs: [
    'marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802169',
    'marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802170',
    'marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802171'
  ],
  kill_chain_phases: [
    {
      kill_chain_name: 'mitre-pre-attack',
      phase_name: 'launch',
      extensions: {
        'extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba': {
          extension_type: 'property-extension',
          id: '93956dbd-8d1d-4777-a476-7c7247b9de81',
          type: 'Kill-Chain-Phase',
          created_at: '2022-04-18T22:47:25.821Z',
          is_inferred: false,
          order: 22
        }
      }
    }
  ],
  external_references: [
    {
      source_name: 'mitre-pre-attack',
      url: 'https://attack.mitre.org/techniques/T1369',
      external_id: 'T1369',
      extensions: {
        'extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba': {
          extension_type: 'property-extension',
          id: '53aa5bcf-4ce4-405a-bcd3-efc28f2a196e',
          type: 'External-Reference',
          created_at: '2022-04-18T22:47:26.482Z',
          is_inferred: false
        }
      }
    }
  ],
  extensions: {
    'extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba': {
      extension_type: 'property-extension',
      id: '93b3ecf3-8b66-4d11-90bb-440b9fc1f278',
      stix_ids: ['93b3ecf3-8b66-4d11-90bb-440b9fc1f279'],
      order: 12,
      complex: {
        random: 'to'
      }
    },
  },
};
// endregion

test('Should compute merge diff', () => {
  const diff = jsonpatch.compare(previous, after);
  const operationAttributes = R.uniq(diff.map((o) => {
    const parts = o.path.substring(1).split('/');
    // eslint-disable-next-line no-restricted-globals
    return parts.filter((p) => isNaN(Number(p))).join('.');
  }));
  console.log(operationAttributes);
  // expect(diff.replace.description).toEqual('Old description');
});
