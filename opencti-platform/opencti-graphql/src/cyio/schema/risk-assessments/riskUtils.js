import { generateId, OSCAL_NS } from '../utils.js';

export const calculateRiskLevel = (risk) => {
  // calculate the risk level
  let riskLevel = 'unknown';
  let riskScore;
  let baseScore;
  let temporalScore;
  if (risk.cvssV2Base_score !== undefined || risk.cvssV3Base_score !== undefined) {
    baseScore =
      risk.cvssV3Base_score !== undefined ? parseFloat(risk.cvssV3Base_score) : parseFloat(risk.cvssV2Base_score);
  }
  if (risk.cvssV2Temporal_score !== undefined || risk.cvssV3Temporal_score !== undefined) {
    temporalScore =
      risk.cvssV3Temporal_score !== undefined
        ? parseFloat(risk.cvssV3Temporal_score)
        : parseFloat(risk.cvssV2Temporal_score);
  }
  if (baseScore !== undefined) riskScore = baseScore;
  if (temporalScore !== undefined) riskScore = temporalScore;

  if (riskScore !== undefined) {
    if (riskScore <= 10 && riskScore >= 9.0) riskLevel = 'very-high';
    if (riskScore <= 8.9 && riskScore >= 7.0) riskLevel = 'high';
    if (riskScore <= 6.9 && riskScore >= 4.0) riskLevel = 'moderate';
    if (riskScore <= 3.9 && riskScore >= 0.1) riskLevel = 'low';
    if (riskScore === 0) riskLevel = 'very-low';
  }
  return { riskLevel, riskScore };
};

export const getLatestRemediationInfo = (risk) => {
  let responseType;
  let lifeCycle;
  let index = 0;
  if (risk.remediation_timestamp_values !== undefined) {
    if (risk.remediation_timestamp_values.includes(',')) {
      // Determine the index of the latest remediation
      const typeArray = risk.remediation_timestamp_values.split(',');
      const latestTime = typeArray.reduce((max, c) => (c > max ? c : max));
      index = typeArray.indexOf(latestTime);
    }
  }
  if (risk.remediation_type_values !== undefined) {
    if (!risk.remediation_type_values.includes(',')) {
      responseType = risk.remediation_type_values;
    } else {
      const typeArray = risk.remediation_type_values.split(',');
      if (index >= typeArray.length) {
        responseType = typeArray[typeArray.length - 1];
      } else {
        responseType = typeArray[index];
      }
    }
  }
  if (risk.remediation_lifecycle_values !== undefined) {
    if (!risk.remediation_lifecycle_values.includes(',')) {
      lifeCycle = risk.remediation_lifecycle_values;
    } else {
      const typeArray = risk.remediation_lifecycle_values.split(',');
      if (index >= typeArray.length) {
        lifeCycle = typeArray[typeArray.length - 1];
      } else {
        lifeCycle = typeArray[index];
      }
    }
  }
  return { responseType, lifeCycle };
};

export function convertToProperties(item, predicateMap, _customProperties) {
  const propList = [];
  let id;
  let id_material;
  let token;

  for (const [key, value] of Object.entries(predicateMap)) {
    if (value.extension_property === undefined) continue;
    if (!item.hasOwnProperty(key)) continue;
    token = value.extension_property;
    id_material = {
      name: token,
      ns: 'http://csrc.nist.gov/ns/oscal',
      value: Array.isArray(item[key]) ? item[key].toString() : `${item[key]}`,
    };

    id = generateId(id_material, OSCAL_NS);
    const property = {
      id: `${id}`,
      entity_type: 'property',
      prop_name: token,
      ns: 'http://csrc.nist.gov/ns/oscal',
      value: Array.isArray(item[key]) ? item[key].toString() : `${item[key]}`,
      // value: `${item[key]}`,
    };

    propList.push(property);
  }
  if (propList.length > 0) return propList;
  return null;
}
