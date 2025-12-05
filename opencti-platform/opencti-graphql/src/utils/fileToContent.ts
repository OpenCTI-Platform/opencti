import type { FileHandle } from 'fs/promises';
import { open } from 'fs/promises';
import { streamToString } from '../database/raw-file-storage';
import { sanitizeFileName, hasEncodedSpecialChars } from '../domain/file-error-helpers';
import { logApp } from '../config/conf';

export async function extractContentFrom<T = any>(file: Promise<FileHandle>) {
  let uploadedFile: FileHandle;
  
  try {
    uploadedFile = await file;
  } catch (err) {
    // If file access fails, try to get the path and sanitize it
    const error = err as Error & { path?: string };
    
    if (error.path && hasEncodedSpecialChars(error.path)) {
      const sanitizedPath = sanitizeFileName(error.path);
      try {
        // Attempt to open file with sanitized path
        uploadedFile = await open(sanitizedPath, 'r');
      } catch (retryErr) {
        logApp.warn('[FILE ACCESS] Failed to access file even with sanitized path', {
          originalPath: error.path,
          sanitizedPath,
          originalError: error.message,
          retryError: (retryErr as Error).message
        });
        // Re-throw original error
        throw err;
      }
    } else {
      // Re-throw if not a path issue or no encoded chars
      throw err;
    }
  }
  
  const readStream = uploadedFile.createReadStream();
  const fileContent = await streamToString(readStream);
  return JSON.parse(fileContent.toString()) as T;
}
