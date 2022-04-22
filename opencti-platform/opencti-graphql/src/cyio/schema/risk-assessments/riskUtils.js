
export const calculateRiskLevel = (risk) => {
  // calculate the risk level
  let riskLevel = 'unknown', riskScore, cvss2BaseScore, cvss3BaseScore;

  if (Array.isArray(risk.cvss2_base_score)) {
    let max = Math.max(...risk.cvss2_base_score);
    let index = risk.cvss2_base_score.indexOf(max);
    cvss2BaseScore = risk.cvss2_base_score[index];
  } else { if (risk.cvss2_base_score !== undefined) cvss2BaseScore = risk.cvss2_base_score; }
  
  if (Array.isArray(risk.cvss3_base_score)) {
    let max = Math.max(...risk.cvss3_base_score);
    let index = risk.cvss3_base_score.indexOf(max);
    cvss3BaseScore = risk.cvss3_base_score[index];
  } else {if (risk.cvss3_base_score !== undefined) cvss3BaseScore = risk.cvss3_base_score; }

  if (cvss2BaseScore !== undefined || cvss3BaseScore !== undefined) {
    riskScore = cvss3BaseScore !== undefined ? parseFloat(cvss3BaseScore) : parseFloat(cvss2BaseScore) ;
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
  if (risk.remediation_type !== undefined) {
    if (risk.remediation_type.length === 1) {
      responseType = risk.remediation_type !== undefined ? risk.remediation_type[0] : null;
      lifeCycle = risk.remediation_lifecycle !== undefined ? risk.remediation_lifecycle[0] : null;
    } else {
      let max = risk.remediation_response_date.reduce(function (a,b) {return a > b ? a : b; });
      let index = risk.remediation_response_date.indexOf(max);
      responseType = risk.remediation_type[index];
      lifeCycle = risk.remediation_lifecycle[index];
    }
  }
  return {responseType, lifeCycle};
}

