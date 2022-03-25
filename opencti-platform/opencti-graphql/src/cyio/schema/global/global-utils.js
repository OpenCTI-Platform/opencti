import { buildSelectVariables } from '../utils.js';
import {UserInputError} from "apollo-server-express";

import {
  itAssetPredicateMap,
  locationPredicateMap as assetLocationPredicateMap,
} from '../assets/asset-common/sparql-query.js';
import {computingDevicePredicateMap,attachToComputingDeviceQuery,detachFromComputingDeviceQuery} from '../assets/computing-device/sparql-query.js';
import {hardwarePredicateMap,attachToHardwareQuery, detachFromHardwareQuery} from '../assets/hardware/sparql-query.js';
import {networkPredicateMap,attachToNetworkQuery, detachFromNetworkQuery} from '../assets/network/sparql-query.js';
import {softwarePredicateMap, attachToSoftwareQuery, detachFromSoftwareQuery,} from '../assets/software/sparql-query.js';
import {
  addressPredicateMap, attachToAddressQuery, detachFromAddressQuery,
  externalReferencePredicateMap, attachToExternalReferenceQuery, detachFromExternalReferenceQuery,
  labelPredicateMap, attachToLabelQuery, detachFromLabelQuery,
  notePredicateMap, attachToNoteQuery, detachFromNoteQuery,
  phoneNumberPredicateMap,attachToPhoneNumberQuery, detachFromPhoneNumberQuery,
} from '../global/resolvers/sparql-query.js';

// Replacement for getSubjectIriByIdQuery
export const selectObjectIriByIdQuery = (id, type) => {
  if (!objectMap.hasOwnProperty(type)) {
    let found = false;
    for (let [key, value] of Object.entries(objectMap)) {
      // check for alternate key
      if (value.alternateKey != undefined && type == value.alternateKey) {
        type = key;
        found = true;
        break;
      }
      // check if the GraphQL type name was supplied
      if (type == value.graphQLType) {
        type = key;
        found = true;
        break;
      }
    }
    if (!found) throw new UserInputError(`Unknown object type '${type}'`);
  }
  
  return `
  SELECT DISTINCT ?iri 
  FROM <tag:stardog:api:context:local>
  WHERE {
      ?iri a <${objectMap[type].iriTemplate}> .
      ?iri <http://darklight.ai/ns/common#id> "${id}" .
  }
  `
}
// Replacement for selectObjetByIriQuery
export const selectObjectByIriQuery = (iri, type, select) => {
  if (!iri.startsWith('<')) iri = `<${iri}>`;
  if (!objectMap.hasOwnProperty(type)) {
    let found = false;
    for (let [key, value] of Object.entries(objectMap)) {
      // check for alternate key
      if (value.alternateKey != undefined && type == value.alternateKey) {
        type = key;
        found = true;
        break;
      }
      // check if the GraphQL type name was supplied
      if (type == value.graphQLType) {
        type = key;
        found = true;
        break;
      }
    }
    if (!found) throw new UserInputError(`Unknown object type '${type}'`);
  }

  const predicateMap = objectMap[type].predicateMap;
  if (select === undefined || select === null) select = Object.keys(predicateMap);
  const { selectionClause, predicates } = buildSelectVariables(predicateMap, select);
  return `
  SELECT ${selectionClause}
  FROM <tag:stardog:api:context:local>
  WHERE {
    BIND(${iri} AS ?iri)
    ?iri a <${objectMap[type].iriTemplate}> .
    ${predicates}
  }
  `
}

export const objectMap = {
  // key is the entity_type/object_type
  "address": {
    predicateMap: addressPredicateMap,
    attachQuery: attachToAddressQuery,
    detachQuery: detachFromAddressQuery,
    graphQLType: "CivicAddress",
    iriTemplate: "http://csrc.nist.gov/ns/oscal/common#Address"
  },
  "application-software": {
    predicateMap: softwarePredicateMap,
    attachQuery: attachToSoftwareQuery,
    detachQuery: detachFromSoftwareQuery,
    graphQLType: "ApplicationSoftwareAsset",
    iriTemplate: "http://scap.nist.gov/ns/asset-identification#Software"
  },
  "computing-device": {
    predicateMap: computingDevicePredicateMap,
    attachQuery: attachToComputingDeviceQuery,
    detachQuery: detachFromComputingDeviceQuery,
    graphQLType: "ComputingDeviceAsset",
    iriTemplate: "http://scap.nist.gov/ns/asset-identification#ComputingDevice"
  },
  "external-reference": {
    predicateMap: externalReferencePredicateMap,
    attachQuery: attachToExternalReferenceQuery,
    detachQuery: detachFromExternalReferenceQuery,
    alternateKey: "link",
    graphQLType: "CyioExternalReference",
    iriTemplate: "http://darklight.ai/ns/common#ExternalReference"
  },
  "hardware": {
    predicateMap: hardwarePredicateMap,
    attachQuery: attachToHardwareQuery,
    detachQuery: detachFromHardwareQuery,
    graphQLType: "HardwareAsset",
    iriTemplate: "http://csrc.nist.gov/ns/oscal/common#Hardware"
  },
  "label": {
    predicateMap: labelPredicateMap,
    attachQuery: attachToLabelQuery,
    detachQuery: detachFromLabelQuery,
    graphQLType: "CyioLabel",
    iriTemplate: "http://darklight.ai/ns/common#Label"
  },
  "network": {
    predicateMap: networkPredicateMap,
    attachQuery: attachToNetworkQuery,
    detachQuery: detachFromNetworkQuery,
    graphQLType: "NetworkAsset",
    iriTemplate: "http://scap.nist.gov/ns/asset-identification#Network"
  },
  "note": {
    predicateMap: notePredicateMap,
    attachQuery: attachToNoteQuery,
    detachQuery: detachFromNoteQuery,
    alternateKey: "remark",
    graphQLType: "CyioNote",
    iriTemplate: "http://darklight.ai/ns/common#Note"
  },
  "operating-system": {
    predicateMap: softwarePredicateMap,
    attachQuery: attachToSoftwareQuery,
    detachQuery: detachFromSoftwareQuery,
    graphQLType: "OperatingSystemAsset",
    iriTemplate: "http://scap.nist.gov/ns/asset-identification#OperatingSystem"
  },
  "software": {
    predicateMap: softwarePredicateMap,
    attachQuery: attachToSoftwareQuery,
    detachQuery: detachFromSoftwareQuery,
    graphQLType: "SoftwareAsset",
    iriTemplate: "http://scap.nist.gov/ns/asset-identification#Software"
  },
  "telephone-number": {
    predicateMap: phoneNumberPredicateMap,
    attachQuery: attachToPhoneNumberQuery,
    detachQuery: detachFromPhoneNumberQuery,
    graphQLType: "TelephoneNumber",
    iriTemplate: "http://csrc.nist.gov/ns/oscal/common#TelephoneNumber"
  },
};