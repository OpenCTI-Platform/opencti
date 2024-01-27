import { describe, expect, it, beforeAll, afterAll } from 'vitest';
import { ADMIN_USER, adminQuery, testContext } from '../../utils/testQuery';
import { csvMapperAreaMalware, csvMapperAreaMalwareDefault } from './default-values/mapper-area-malware';
import { parsingProcess } from '../../../src/parser/csv-parser';
import { mappingProcess } from '../../../src/parser/csv-mapper';
import { ENTITY_TYPE_LOCATION_ADMINISTRATIVE_AREA } from '../../../src/modules/administrativeArea/administrativeArea-types';
import { ENTITY_TYPE_MALWARE } from '../../../src/schema/stixDomainObject';

const ENTITY_SETTINGS_UPDATE = `
  mutation entitySettingsEdit($ids: [ID!]!, $input: [EditInput!]!) {
    entitySettingsFieldPatch(ids: $ids, input: $input) {
      id
    }
  }
`;

const GET_QUERY = `
  query getQuery {
    individuals {
      edges {
        node {
          id
        }
      }
    }
    entitySettings {
      edges {
        node {
          id
          target_type
          attributes_configuration
        }
      }
    }
    killChainPhases {
      edges {
        node {
          id
          phase_name
        }
      }
    }
  }
`;

const mapData = async (fileName, mapper) => {
  const [_, ...records] = await parsingProcess(fileName, mapper.separator);
  return await Promise.all((records.map(async (record) => {
    return await mappingProcess(testContext, ADMIN_USER, mapper, record);
  })));
};

/**
 * /!\
 * To run those tests, we need the data injected by loader-test.
 * So if you want to run only this file follow the steps below:
 * - run 'yarn test:dev loader-test' to inject data in your DB,
 * - after test is done, stop the run,
 * - comment the line 'await elDeleteIndices(...);' in globalSetup.js (DO NOT COMMIT THIS CHANGES),
 * - comment the line 'await createTestUsers();' in globalSetup.js (DO NOT COMMIT THIS CHANGES),
 * - run 'yarn test:dev csv-mapper-test' should be ok
 */
describe('CSV-MAPPER', () => {
  let individual;
  let entitySettingArea;
  let entitySettingMalware;
  let killChainPhases;

  afterAll(async () => {
    await adminQuery(ENTITY_SETTINGS_UPDATE, {
      ids: [entitySettingArea.id],
      input: {
        key: 'attributes_configuration',
        value: entitySettingArea.attributes_configuration
      }
    });
    await adminQuery(ENTITY_SETTINGS_UPDATE, {
      ids: [entitySettingMalware.id],
      input: {
        key: 'attributes_configuration',
        value: entitySettingMalware.attributes_configuration
      }
    });
  });

  beforeAll(async () => {
    const { data } = await adminQuery(GET_QUERY);
    [individual,] = data.individuals.edges.map((e) => e.node);
    const entitySettings = data.entitySettings.edges.map((e) => e.node);
    entitySettingArea = entitySettings.find((setting) => setting.target_type === ENTITY_TYPE_LOCATION_ADMINISTRATIVE_AREA);
    entitySettingMalware = entitySettings.find((setting) => setting.target_type === ENTITY_TYPE_MALWARE);
    killChainPhases = data.killChainPhases.edges.map((e) => e.node);

    const areaDefaultValues = [
      { name: 'createdBy', default_values: [individual.id], mandatory: false },
      { name: 'latitude', default_values: ['1.11'], mandatory: false },
      { name: 'longitude', default_values: ['2.22'], mandatory: false },
      { name: 'description', default_values: ['hello'], mandatory: false }
    ];
    await adminQuery(
      ENTITY_SETTINGS_UPDATE,
      {
        ids: [entitySettingArea.id],
        input: {
          key: 'attributes_configuration',
          value: JSON.stringify(areaDefaultValues)
        }
      }
    );
    const malwareDefaultValues = [
      { name: 'createdBy', default_values: [individual.id], mandatory: false },
      { name: 'killChainPhases', default_values: killChainPhases.map((p) => p.id), mandatory: false },
      { name: 'malware_types', default_values: ['rootkit'], mandatory: false },
      { name: 'implementation_languages', default_values: ['lua', 'perl'], mandatory: false },
      { name: 'architecture_execution_envs', default_values: ['powerpc', 'x86'], mandatory: false },
      { name: 'description', default_values: ['hello'], mandatory: false }
    ];
    await adminQuery(ENTITY_SETTINGS_UPDATE, {
      ids: [entitySettingMalware.id],
      input: {
        key: 'attributes_configuration',
        value: JSON.stringify(malwareDefaultValues)
      }
    });
  });

  describe('Managing default values', () => {
    it('should use default values from settings', async () => {
      const filePath = './tests/02-integration/05-parser/default-values/data.csv';
      const data = (await mapData(filePath, csvMapperAreaMalware)).flat();

      const morbihan = data.find((object) => object.name === 'morbihan');
      const finistere = data.find((object) => object.name === 'finistere');
      const cotesDArmor = data.find((object) => object.name === 'cotes-darmor');
      const ileEtVilaine = data.find((object) => object.name === 'ile-et-vilaine');
      const vador = data.find((object) => object.name === 'vador');
      const octopus = data.find((object) => object.name === 'octopus');

      expect(morbihan).toBeDefined();
      expect(finistere).toBeDefined();
      expect(cotesDArmor).toBeDefined();
      expect(ileEtVilaine).toBeDefined();
      expect(vador).toBeDefined();
      expect(octopus).toBeDefined();

      expect(morbihan.entity_type).toBe('Administrative-Area');
      expect(morbihan.confidence).toBe(100);
      expect(morbihan.description).toBe('56');
      expect(morbihan.latitude).toBe(2);
      expect(morbihan.longitude).toBe(-2);
      expect(morbihan.createdBy.name).toBe('Jean Michel');

      expect(finistere.entity_type).toBe('Administrative-Area');
      expect(finistere.confidence).toBe(undefined);
      expect(finistere.description).toBe('29');
      expect(finistere.latitude).toBe(2);
      expect(finistere.longitude).toBe(-3);
      expect(finistere.createdBy).toBe(individual.id);

      expect(cotesDArmor.entity_type).toBe('Administrative-Area');
      expect(cotesDArmor.confidence).toBe(100);
      expect(cotesDArmor.description).toBe('hello');
      expect(cotesDArmor.latitude).toBe(1);
      expect(cotesDArmor.longitude).toBe(-2);
      expect(cotesDArmor.createdBy).toBe(individual.id);

      expect(ileEtVilaine.entity_type).toBe('Administrative-Area');
      expect(ileEtVilaine.confidence).toBe(50);
      expect(ileEtVilaine.description).toBe('35');
      expect(ileEtVilaine.latitude).toBe(1.11);
      expect(ileEtVilaine.longitude).toBe(2.22);
      expect(ileEtVilaine.createdBy).toBe(individual.id);

      expect(vador.entity_type).toBe('Malware');
      expect(vador.is_family).toBe(true);
      expect(vador.malware_types).toEqual(['ddos']);
      expect(vador.implementation_languages).toEqual(['lua', 'perl']);
      expect(vador.architecture_execution_envs).toEqual(['arm']);
      expect(vador.createdBy).toBe(individual.id);
      expect(vador.killChainPhases.length).toBe(1);
      expect(vador.killChainPhases[0].kill_chain_name).toBe('mitre-attack');
      expect(vador.killChainPhases[0].phase_name).toBe('persistence');
      expect(vador.killChainPhases[0].x_opencti_order).toBe(20);

      expect(octopus.entity_type).toBe('Malware');
      expect(octopus.is_family).toBe(false);
      expect(octopus.malware_types).toEqual(['rootkit']);
      expect(octopus.implementation_languages).toEqual(['lua', 'perl']);
      expect(octopus.architecture_execution_envs).toEqual(['powerpc', 'x86']);
      expect(octopus.createdBy).toBe(individual.id);
      expect(octopus.killChainPhases.length).toBe(killChainPhases.length);
      expect(octopus.killChainPhases).toEqual(killChainPhases.map((p) => p.id));
    });

    it('should use default values from mapper', async () => {
      const filePath = './tests/02-integration/05-parser/default-values/data.csv';
      const killChainPhase = killChainPhases[0];
      const data = (await mapData(
        filePath,
        csvMapperAreaMalwareDefault(individual.id, [killChainPhase.id])
      )).flat();

      const morbihan = data.find((object) => object.name === 'morbihan');
      const finistere = data.find((object) => object.name === 'finistere');
      const cotesDArmor = data.find((object) => object.name === 'cotes-darmor');
      const ileEtVilaine = data.find((object) => object.name === 'ile-et-vilaine');
      const vador = data.find((object) => object.name === 'vador');
      const octopus = data.find((object) => object.name === 'octopus');
      const vadorOnMorbihan = data.find((object) => object.entity_type === 'targets' && object.from.name === 'vador');
      const octopusOnIleEtVilaine = data.find((object) => object.entity_type === 'targets' && object.from.name === 'octopus');

      expect(morbihan).toBeDefined();
      expect(finistere).toBeDefined();
      expect(cotesDArmor).toBeDefined();
      expect(ileEtVilaine).toBeDefined();
      expect(vador).toBeDefined();
      expect(octopus).toBeDefined();
      expect(vadorOnMorbihan).toBeDefined();
      expect(octopusOnIleEtVilaine).toBeDefined();

      expect(morbihan.entity_type).toBe('Administrative-Area');
      expect(morbihan.confidence).toBe(100);
      expect(morbihan.description).toBe('56');
      expect(morbihan.latitude).toBe(2);
      expect(morbihan.longitude).toBe(-2);
      expect(morbihan.createdBy.name).toBe('Jean Michel');

      expect(finistere.entity_type).toBe('Administrative-Area');
      expect(finistere.confidence).toBe(97);
      expect(finistere.description).toBe('29');
      expect(finistere.latitude).toBe(2);
      expect(finistere.longitude).toBe(-3);
      expect(finistere.createdBy.id).toBe(individual.id);

      expect(cotesDArmor.entity_type).toBe('Administrative-Area');
      expect(cotesDArmor.confidence).toBe(100);
      expect(cotesDArmor.description).toBe('hello area');
      expect(cotesDArmor.latitude).toBe(1);
      expect(cotesDArmor.longitude).toBe(-2);
      expect(cotesDArmor.createdBy.id).toBe(individual.id);

      expect(ileEtVilaine.entity_type).toBe('Administrative-Area');
      expect(ileEtVilaine.confidence).toBe(50);
      expect(ileEtVilaine.description).toBe('35');
      expect(ileEtVilaine.latitude).toBe(5.55);
      expect(ileEtVilaine.longitude).toBe(6.66);
      expect(ileEtVilaine.createdBy.id).toBe(individual.id);

      expect(vador.entity_type).toBe('Malware');
      expect(vador.is_family).toBe(true);
      expect(vador.malware_types).toEqual(['ddos']);
      expect(vador.implementation_languages).toEqual(['lua', 'perl']);
      expect(vador.architecture_execution_envs).toEqual(['arm']);
      expect(vador.createdBy).toBe(individual.id);
      expect(vador.killChainPhases.length).toBe(1);
      expect(vador.killChainPhases[0].kill_chain_name).toBe('mitre-attack');
      expect(vador.killChainPhases[0].phase_name).toBe('persistence');
      expect(vador.killChainPhases[0].x_opencti_order).toBe(20);

      expect(vadorOnMorbihan.to.name).toBe('morbihan');
      expect(vadorOnMorbihan.confidence).toBe(77);

      expect(octopus.entity_type).toBe('Malware');
      expect(octopus.is_family).toBe(false);
      expect(octopus.malware_types).toEqual(['ddosssss']);
      expect(octopus.implementation_languages).toEqual(['lua', 'perl']);
      expect(octopus.architecture_execution_envs).toEqual(['armmmm']);
      expect(octopus.createdBy).toBe(individual.id);
      expect(octopus.killChainPhases.length).toBe(1);
      expect(octopus.killChainPhases[0].phase_name).toBe(killChainPhase.phase_name);

      expect(octopusOnIleEtVilaine.to.name).toBe('ile-et-vilaine');
      expect(octopusOnIleEtVilaine.confidence).toBe(77);
    });
  });
});
