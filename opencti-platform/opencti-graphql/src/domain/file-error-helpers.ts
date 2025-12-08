export const isSyntaxOrParsingError = (error: Error): boolean => {
  if (!error) return false;
  return error.name === 'SyntaxError' || error.message?.includes('JSON');
};

export const isFileAccessError = (error: Error): boolean => {
  if (!error) return false;
  const errorWithCode = error as Error & { code?: string };
  return errorWithCode.code === 'ENOENT' 
    || errorWithCode.code === 'NoSuchKey' 
    || error.message?.includes('ENOENT') 
    || error.message?.includes('NoSuchKey');
};

export const hasEncodedSpecialChars = (fileName: string): boolean => {
  if (!fileName || typeof fileName !== 'string') return false;
  // Check for common URL-encoded characters that could cause file system issues
  // %22 = ", %20 = space, %3C = <, %3E = >, %7C = |, etc.
  return /%[0-9A-Fa-f]{2}/.test(fileName);
};

export const sanitizeFileName = (fileName: string): string => {
  if (!fileName || typeof fileName !== 'string') return fileName;
  
  if (!hasEncodedSpecialChars(fileName)) {
    return fileName;
  }
  
  try {
    const decoded = decodeURIComponent(fileName);
    
    // eslint-disable-next-line no-control-regex
    const problematicChars = /[<>:"|?*\x00-\x1f]/;
    if (problematicChars.test(decoded)) {
      // If decoded version has problematic chars, replace them with safe alternatives
      return decoded
        .replace(/[<>]/g, '_')
        .replace(/[:"|?*]/g, '-')
        // eslint-disable-next-line no-control-regex
        .replace(/[\x00-\x1f]/g, '');
    }
    
    return decoded;
  } catch (_err) {
    return fileName;
  }
};

export const generateFileUploadErrorMessage = (error: Error, fileName: string): { message: string; data?: Record<string, unknown> } => {
  if (isFileAccessError(error)) {
    const hasEncodedChars = hasEncodedSpecialChars(fileName);
    
    if (hasEncodedChars) {
      const sanitized = sanitizeFileName(fileName);
      const wasSanitized = sanitized !== fileName;
      
      return {
        message: `Unable to access the file "${fileName}". The filename contains special characters that may be causing access issues. ${wasSanitized ? 'An automatic fix was attempted but failed.' : ''} Please rename the file to use only standard alphanumeric characters (a-z, 0-9, -, _) and try again.`,
        data: { 
          originalFileName: fileName,
          suggestedFileName: sanitized,
          automaticFixAttempted: wasSanitized
        }
      };
    }
    
    return {
      message: `Unable to access the file "${fileName}". The file may not exist, may have been moved, or there may be permission issues. Please verify the file exists and is accessible.`
    };
  }
  
  if (isSyntaxOrParsingError(error)) {
    return {
      message: `Invalid JSON format in file "${fileName}". The file content could not be parsed as valid JSON. Please verify the file contains properly formatted JSON and try again. Error details: ${error.message}`
    };
  }
  
  return {
    message: `Error processing file "${fileName}". ${error.message || 'Unknown error occurred'}. Please verify the file is valid and try again.`
  };
};