
export const calculateRiskLevel = (risk) => {
  // calculate the risk level
  let riskLevel = 'unknown', riskScore;
  if (risk.cvssV2Base_score !== undefined || risk.cvssV3Base_score !== undefined) {
    riskScore = risk.cvssV3Base_score !== undefined ? parseFloat(risk.cvssV3Base_score) : parseFloat(risk.cvssV2Base_score) ;
    if (riskScore <= 10 && riskScore >= 9.0) riskLevel = 'very-high';
    if (riskScore <= 8.9 && riskScore >= 7.0) riskLevel = 'high';
    if (riskScore <= 6.9 && riskScore >= 4.0) riskLevel = 'moderate';
    if (riskScore <= 3.9 && riskScore >= 0.1) riskLevel = 'low';
    if (riskScore === 0) riskLevel = 'very-low';
  }
return {riskLevel, riskScore};
}

export const getLatestRemediationInfo = (risk) => {
  let responseType, lifeCycle;
  if (risk.remediation_type_values !== undefined) {
    if (!risk.remediation_type_values.includes(',')) {
      responseType = risk.remediation_type_values;
    } else {
      // TODO: Determine better way to select the right value
      let typeArray = risk.remediation_type_values.split(',');
      responseType = typeArray[0];
    }
  }
  if (risk.remediation_lifecycle_values !== undefined) {
    if (!risk.remediation_lifecycle_values.includes(',')) {
      lifeCycle = risk.remediation_lifecycle_values;
    } else {
      // TODO: Determine better way to select the right value
      let typeArray = risk.remediation_lifecycle_values.split(',');
      lifeCycle = typeArray[0];
    }
  }
  return {responseType, lifeCycle};
}

