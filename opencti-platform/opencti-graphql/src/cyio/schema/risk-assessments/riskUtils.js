
export const calculateRiskLevel = (risk) => {
  // calculate the risk level
  let riskLevel, riskScore;
  riskLevel = 'unknown';
  if (risk.cvss20_base_score !== undefined || risk.cvss30_base_score !== undefined) {
    riskScore = risk.cvss30_base_score !== undefined ? parseFloat(risk.cvss30_base_score) : parseFloat(risk.cvss20_base_score) ;
    if (riskScore <= 10 && riskScore >= 9.0) riskLevel = 'very-high';
    if (riskScore <= 8.9 && riskScore >= 7.0) riskLevel = 'high';
    if (riskScore <= 6.9 && riskScore >= 4.0) riskLevel = 'moderate';
    if (riskScore <= 3.9 && riskScore >= 0.1) riskLevel = 'low';
    if (riskScore === 0) riskLevel = 'very-low';
  }
return {riskLevel, riskScore}
}

