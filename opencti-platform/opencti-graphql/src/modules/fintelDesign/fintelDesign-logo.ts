import { downloadFile } from '../../database/raw-file-storage';
import { FunctionalError } from '../../config/errors';
import type { BasicStoreEntityFintelDesign } from './fintelDesign-types';

// The folder the logos are stored in: the logo of a design is stored under its internal id, without extension
export const FINTEL_DESIGN_LOGO_FOLDER = 'fintelDesigns';
export const FINTEL_DESIGN_LOGO_MAX_SIZE = 5 * 1024 * 1024;

export const fintelDesignLogoStorageKey = (internalId: string) => `${FINTEL_DESIGN_LOGO_FOLDER}/${internalId}`;

// The image formats a logo can have, recognized from its bytes: the stored file has no extension and its stored mime type is not
// reliable, so the extension written in the bundle (and checked by the upload when it is imported) is the one of its content
const startsWith = (content: Buffer, signature: number[], offset = 0) => {
  return content.length >= offset + signature.length && signature.every((byte, index) => content[offset + index] === byte);
};
const ascii = (text: string) => [...text].map((char) => char.charCodeAt(0));

export const fintelDesignLogoExtension = (content: Buffer): string | undefined => {
  if (startsWith(content, [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])) {
    return 'png';
  }
  if (startsWith(content, [0xff, 0xd8, 0xff])) {
    return 'jpg';
  }
  if (startsWith(content, ascii('GIF87a')) || startsWith(content, ascii('GIF89a'))) {
    return 'gif';
  }
  if (startsWith(content, ascii('RIFF')) && startsWith(content, ascii('WEBP'), 8)) {
    return 'webp';
  }
  // An SVG is text: an XML document whose root is an svg element, after an optional prolog, comments and doctype
  const head = content.subarray(0, 4096).toString('utf8').replace(/^\uFEFF/, '').trimStart();
  if (head.startsWith('<') && /<svg[\s>]/i.test(head)) {
    return 'svg';
  }
  return undefined;
};

// The logo of a design as the platform stores it, byte for byte. null when the design has no logo.
// Only the design's own key is read: `file_id` points at what the export would write, read by a user who may not read another file.
// A logo missing from the storage, or not its own, is an error: the export would silently lose it.
export const readFintelDesignLogo = async (design: Pick<BasicStoreEntityFintelDesign, 'internal_id' | 'file_id' | 'name'>): Promise<Buffer | null> => {
  if (!design.file_id) {
    return null;
  }
  if (design.file_id !== fintelDesignLogoStorageKey(design.internal_id)) {
    throw FunctionalError('The logo of a fintel design is not its own file', { id: design.internal_id, name: design.name });
  }
  const stream = await downloadFile(design.file_id);
  if (!stream) {
    throw FunctionalError('The logo of a fintel design is missing from the storage', { id: design.internal_id, name: design.name });
  }
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of stream) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    size += buffer.byteLength;
    if (size > FINTEL_DESIGN_LOGO_MAX_SIZE) {
      stream.destroy();
      throw FunctionalError('The logo of a fintel design is too large', { maxFileSize: FINTEL_DESIGN_LOGO_MAX_SIZE, id: design.internal_id, name: design.name });
    }
    chunks.push(buffer);
  }
  return Buffer.concat(chunks);
};
