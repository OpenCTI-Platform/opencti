import type { FileHandle } from 'fs/promises';
import { streamToString } from '../database/raw-file-storage';

export async function extractContentFrom<T = any>(file: Promise<FileHandle>) {
  const uploadedFile = await file;
  const readStream = uploadedFile.createReadStream();
  const fileContent = await streamToString(readStream);
  return JSON.parse(fileContent.toString()) as T;
}
