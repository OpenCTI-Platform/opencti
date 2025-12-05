export const isValidStixBundle = (bundle: unknown): boolean => {
  if (!bundle || typeof bundle !== 'object' || Array.isArray(bundle)) {
    return false;
  }
  
  const bundleObj = bundle as Record<string, unknown>;
  
  return bundleObj.type === 'bundle' 
    && Array.isArray(bundleObj.objects) 
    && bundleObj.objects.length > 0;
};

export const generateBundleValidationErrorMessage = (bundle: unknown): string => {
  if (!bundle || typeof bundle !== 'object' || Array.isArray(bundle)) {
    return 'Invalid STIX bundle structure: the content does not conform to STIX 2.x format. Expected a JSON object with "type" and "objects" properties.';
  }
  
  const bundleObj = bundle as Record<string, unknown>;
  
  if (!bundleObj.type) {
    return 'Invalid STIX bundle structure: missing "type" property. Expected "type": "bundle".';
  }
  
  if (bundleObj.type !== 'bundle') {
    return `Invalid STIX bundle structure: type must be "bundle", but got "${bundleObj.type}". Please ensure the file is a valid STIX 2.x bundle.`;
  }
  
  if (!bundleObj.objects || !Array.isArray(bundleObj.objects) || bundleObj.objects.length === 0) {
    return 'Invalid STIX bundle structure: missing or empty "objects" array. A valid STIX bundle must contain at least one STIX object.';
  }
  
  return 'Invalid STIX bundle structure: the content does not conform to STIX 2.x format. Please verify the file structure.';
};