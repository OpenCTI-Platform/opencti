import { rebuildInstanceBeforePatch } from '../../../src/utils/patch';
import { STIX_EXT_OCTI } from '../../../src/types/stix-extensions';

const instance = {
  _index: 'opencti_stix_domain_objects-000001',
  id: 'threat-actor--214c643d-8ad5-5911-a08e-7aa9111ff8b6',
  extensions: {
    [STIX_EXT_OCTI]: {
      id: '6bf6c4e3-20f0-4497-bb08-bd2cf59b1e84',
      stix_ids: ['marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41cc'],
    }
  },
  personal_motivations: ['coercion'],
  threat_actor_types: ['crime-syndicate', "criminal'"],
  spec_version: '2.1',
  created: '2021-04-23T22:44:44.554Z',
  confidence: 85,
  description: 'asd awd wadwa',
  created_at: '2021-04-23T22:44:44.554Z',
  revoked: false,
  updated_at: '2021-04-26T18:52:45.914Z',
  name: 'd adsad sadas d',
  modified: '2021-04-26T18:52:45.914Z',
  lang: 'en',
  x_opencti_stix_ids: [],
  object_marking_refs: ['marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da', 'marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41db'],
  created_by_ref: 'b2e2a15f-b1a5-4017-bfeb-3238ce4fbe86',
  labels: ['884506e4-ad4a-49cd-88bc-d40b7069f496'],
};
const patch = {
  replace: {
    confidence: 75,
    extensions: {
      [STIX_EXT_OCTI]: {
        id: '6bf6c4e3-20f0-4497-bb08-bd2cf59b1e83'
      }
    }
  },
  add: {
    object_marking_refs: ['marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da'],
    extensions: {
      [STIX_EXT_OCTI]: {
        stix_ids: ['marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41cc']
      }
    }
  },
  remove: {
    extensions: {
      [STIX_EXT_OCTI]: {
        tests: ['marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41dd']
      }
    }
  },
};
test('Should rebuild instance', () => {
  const rebuildInstance = rebuildInstanceBeforePatch(instance, patch);
  expect(rebuildInstance.extensions[STIX_EXT_OCTI].id).toEqual('6bf6c4e3-20f0-4497-bb08-bd2cf59b1e83');
  expect(rebuildInstance.extensions[STIX_EXT_OCTI].stix_ids).toEqual([]);
  expect(rebuildInstance.extensions[STIX_EXT_OCTI].tests).toEqual(['marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41dd']);
  expect(rebuildInstance.confidence).toEqual(75);
  expect(rebuildInstance.object_marking_refs.length).toEqual(1);
});
