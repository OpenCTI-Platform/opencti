import { expect, it, describe } from 'vitest';
import * as R from 'ramda';
import { stixLoadById } from '../../../src/database/middleware';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import data from '../../data/DATA-TEST-STIX2_v2.json';
import {
  ENTITY_TYPE_CONTAINER_OBSERVED_DATA,
  ENTITY_TYPE_CONTAINER_REPORT,
  ENTITY_TYPE_INTRUSION_SET,
  ENTITY_TYPE_MALWARE,
  isStixDomainObject,
  isStixDomainObjectLocation
} from '../../../src/schema/stixDomainObject';
import { isStixRelationship } from '../../../src/schema/stixRelationship';
import { ENTITY_TYPE_MARKING_DEFINITION } from '../../../src/schema/stixMetaObject';
import { convertTypeToStixType } from '../../../src/database/stix-converter';
import { STIX_EXT_OCTI } from '../../../src/types/stix-extensions';

describe('Stix opencti converter', () => {
  const dataMap = new Map(data.objects.map((obj) => [obj.id, obj]));

  const rawDataCompare = async (rawId, standardId) => {
    let rawData = dataMap.get(rawId);
    const stixData = await stixLoadById(testContext, ADMIN_USER, rawId);
    let remainingData = { ...stixData };
    if (stixData.extensions[STIX_EXT_OCTI].type === ENTITY_TYPE_CONTAINER_OBSERVED_DATA) {
      rawData = R.dissoc('objects', rawData);
      rawData = R.dissoc('object_refs', rawData);
      remainingData = R.dissoc('object_refs', remainingData);
    }
    // Testing stix data
    const isReportType = stixData.type === ENTITY_TYPE_CONTAINER_REPORT.toLowerCase();
    const keys = Object.keys(rawData);
    for (let index = 0; index < keys.length; index += 1) {
      const rawKey = keys[index];
      remainingData = R.dissoc(rawKey, remainingData);
      const initialData = rawData[rawKey];
      const refetchData = stixData[rawKey];
      if (rawKey === 'id') { // Because of standard_id generation
        if (standardId) { // Cant be compare for sighting and relationship
          expect(refetchData).toBe(standardId);
        }
      } else if (rawKey === 'kill_chain_phases') {
        expect(refetchData.length).toEqual(initialData.length);
        // expect(refetchData.some((e) => R.includes(e, initialData))).toBeTruthy();
        remainingData = R.dissoc(rawKey, remainingData);
      } else if (rawKey === 'external_references') {
        expect(refetchData.length).toEqual(initialData.length);
        // expect(refetchData.some((e) => R.includes(e, initialData))).toBeTruthy();
        remainingData = R.dissoc(rawKey, remainingData);
      } else if (rawKey === 'modified') {
        // Update will change with current date
        remainingData = R.dissoc(rawKey, remainingData);
      } else if (isReportType && rawKey === 'created') {
        expect(stixData.created).toEqual(rawData.published);
        remainingData = R.dissoc(rawKey, remainingData);
      } else if (rawKey.endsWith('_ref') || rawKey.endsWith('_refs')) {
        const resolvedIds = [];
        const refetchDataAsArray = Array.isArray(refetchData) ? refetchData : [refetchData];
        for (let i = 0; i < refetchDataAsArray.length; i += 1) {
          const refetchElement = refetchDataAsArray[i];
          const stixRef = await stixLoadById(testContext, ADMIN_USER, refetchElement);
          resolvedIds.push(stixRef.id, ...(stixRef.extensions[STIX_EXT_OCTI].stix_ids ?? []));
        }
        const initialDataAsArray = Array.isArray(initialData) ? initialData : [initialData];
        for (let j = 0; j < initialDataAsArray.length; j += 1) {
          const initialId = initialDataAsArray[j];
          expect(resolvedIds).toContainEqual(initialId);
        }
      } else if (rawKey.startsWith('x_') || rawKey === 'definition') {
        // Cant compare old stix version
      } else {
        expect(refetchData).toEqual(initialData);
      }
    }
    // Testing opencti added data
    expect(remainingData.extensions[STIX_EXT_OCTI].id).not.toBeNull();
    const opencti_type = remainingData.extensions[STIX_EXT_OCTI].type;
    expect(convertTypeToStixType(opencti_type)).toEqual(rawData.type);
    expect(remainingData.extensions[STIX_EXT_OCTI].stix_ids).toContainEqual(rawData.id);
    expect(remainingData.extensions[STIX_EXT_OCTI].created_at).not.toBeNull();
    // expect(remainingData.extensions[STIX_EXT_OCTI].updated_at).not.toBeNull();
    // Default value for stix domains and relationships
    if (isStixDomainObject(opencti_type) || isStixRelationship(opencti_type)) {
      expect(remainingData.lang).toEqual('en');
      remainingData = R.dissoc('lang', remainingData);
      expect(remainingData.revoked).not.toBeNull(); // Could be revoked by the manager.
      remainingData = R.dissoc('revoked', remainingData);
      if (remainingData.confidence !== undefined) {
        // expect(remainingData.confidence).toEqual(15); // can't test the confidence value, could be 15 ou 0
        remainingData = R.dissoc('confidence', remainingData);
      }
    }
    // Default values for malware
    if (opencti_type === ENTITY_TYPE_MALWARE || opencti_type === ENTITY_TYPE_INTRUSION_SET) {
      expect(remainingData.first_seen).toBeUndefined();
      remainingData = R.dissoc('first_seen', remainingData);
      expect(remainingData.last_seen).toBeUndefined();
      remainingData = R.dissoc('last_seen', remainingData);
    }
    // Default values for malware
    if (opencti_type === ENTITY_TYPE_MALWARE) {
      expect(remainingData.is_family).toEqual(false);
      remainingData = R.dissoc('is_family', remainingData);
    }
    // Rework on name for marking def
    if (opencti_type === ENTITY_TYPE_MARKING_DEFINITION) {
      const def = R.head(Object.values(rawData.definition));
      expect(remainingData.name).toEqual(def);
      remainingData = R.dissoc('name', remainingData);
    }
    // Handle location properties
    if (isStixDomainObjectLocation(opencti_type)) {
      remainingData = R.pipe(
        R.dissoc('region'),
        R.dissoc('country'),
        R.dissoc('city'),
      )(remainingData);
    }
    // All remaining data must be extensions
    // const remain = R.mergeAll(
    //   Object.entries(remainingData)
    //     .filter(([k]) => !k.startsWith('x_') && k !== 'extensions')
    //     .map(([k, v]) => ({ [k]: v }))
    // );
    // if (!R.isEmpty(remain)) {
    //   console.log('----------- Remain -----------');
    //   console.log(remain);
    // }
    const notExtSize = Object.keys(remainingData)
      .filter((key) => !key.startsWith('x_') && key !== 'extensions').length;
    expect(notExtSize).toEqual(0);
  };

  it('Should stix data correctly generated', async () => {
    await rawDataCompare('attack-pattern--489a7797-01c3-4706-8cd1-ec56a9db3adc', 'attack-pattern--b5c4784e-6ecc-5347-a231-c9739e077dd8');

    // Campaign

    await rawDataCompare('course-of-action--ae56a49d-5281-45c5-ab95-70a1439c338e', 'course-of-action--2d3af28d-aa36-59ad-ac57-65aa27664752');

    // Grouping

    await rawDataCompare('identity--c017f212-546b-4f21-999d-97d3dc558f7b', 'identity--732421a0-8471-52de-8d9f-18c8b260813c');

    await rawDataCompare('incident--0b626d41-1d8d-4b96-86fa-ad49cea2cfd4', 'incident--8658860d-df08-5f41-bf41-106095e48085');

    await rawDataCompare('indicator--a2f7504a-ea0d-48ed-a18d-cbf352fae6cf', 'indicator--4099edd7-1efd-54aa-9736-7bcd7219b78b');

    // Infrastructure

    await rawDataCompare('intrusion-set--18854f55-ac7c-4634-bd9a-352dd07613b7', 'intrusion-set--d12c5319-f308-5fef-9336-20484af42084');

    await rawDataCompare('location--5acd8b26-51c2-4608-86ed-e9edd43ad971', 'location--b8d0549f-de06-5ebd-a6e9-d31a581dba5d');

    await rawDataCompare('malware--faa5b705-cf44-4e50-8472-29e5fec43c3c', 'malware--21c45dbe-54ec-5bb7-b8cd-9f27cc518714');

    // Malware analysis

    await rawDataCompare('note--573f623c-bf68-4f19-9500-d618f0d00af0', undefined); // StandardId is uuidV4

    await rawDataCompare('opinion--fab0d63d-e1be-4771-9c14-043b76f71d4f', undefined); // StandardId is uuidV4

    await rawDataCompare('observed-data--7d258c31-9a26-4543-aecb-2abc5ed366be', 'observed-data--d5c0414a-aeb6-5927-a2ae-e465846c206f');

    await rawDataCompare('report--a445d22a-db0c-4b5d-9ec8-e9ad0b6dbdd7', 'report--f3e554eb-60f5-587c-9191-4f25e9ba9f32');

    // Threat actor

    // Tool

    // Vulnerability

    await rawDataCompare('marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168', 'marking-definition--e8afcdc4-be08-5e57-a3b6-c24d2396d3de');

    // Language Content- Not implemented

    await rawDataCompare('sighting--579a46af-a339-400d-809e-b92101fe7de8', undefined); // StandardId is uuidV4

    await rawDataCompare('relationship--9315a197-fe15-4c96-b77c-edcaa5e22ecb', undefined); // StandardId is uuidV4

    // Cyber observables
    // ...
  });
});
