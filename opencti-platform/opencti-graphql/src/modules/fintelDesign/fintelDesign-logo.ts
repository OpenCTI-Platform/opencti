import { pipeline, type Readable, Transform } from 'node:stream';
import { fileTypeFromBuffer } from 'file-type';
import { downloadFile } from '../../database/raw-file-storage';
import { FunctionalError } from '../../config/errors';
import type { BasicStoreEntityFintelDesign } from './fintelDesign-types';

// The folder the logos are stored in: the logo of a design is stored under its internal id, without extension
export const FINTEL_DESIGN_LOGO_FOLDER = 'fintelDesigns';
// The largest logo a design can have: the largest file a configuration bundle carries, so that any design can be exported and imported back
export const FINTEL_DESIGN_LOGO_MAX_SIZE = 5 * 1024 * 1024;

// The logo being uploaded through a counter that fails as soon as it goes over the limit, so an oversized logo is never stored.
// A pipeline, not a pipe: a refusal destroys the source too, otherwise the temporary file of the upload stays on disk
export const limitFintelDesignLogoStream = (source: Readable): Readable => {
  let size = 0;
  const counter = new Transform({
    transform(chunk, _encoding, callback) {
      size += chunk.length;
      const tooLarge = size > FINTEL_DESIGN_LOGO_MAX_SIZE;
      callback(tooLarge ? FunctionalError('The logo of the fintel design is too large', { maxFileSize: FINTEL_DESIGN_LOGO_MAX_SIZE }) : null, chunk);
    },
  });
  return pipeline(source, counter, () => undefined);
};

export const fintelDesignLogoStorageKey = (internalId: string) => `${FINTEL_DESIGN_LOGO_FOLDER}/${internalId}`;

// The formats a logo can have, recognized from its bytes: the stored file has no extension and its stored mime type is not reliable,
// so the extension written in the bundle (and checked by the upload when it is imported) is the one of its content.
// The images are recognized by file-type; an SVG is text, which file-type does not recognize, and is checked here.
const RASTER_EXTENSIONS = ['png', 'jpg', 'gif', 'webp'];

const svgText = (content: Buffer) => content.toString('utf8').replace(/^\uFEFF/, '');

// Where the root element of the text starts when it is an svg element, -1 otherwise. The text starts with markup, and what comes before
// the root (XML declaration, processing instructions, comments, doctype with its internal subset) is markup that is not an element:
// the first element is the root. A comment is skipped whole, as it may hold any tag. Nothing is parsed nor resolved: no entity, no
// external reference is ever read. An HTML page holding an svg element, or a document whose svg element is commented out, has another
// root. Every scan of the text goes forward only: linear in its length, whatever it holds.
const svgRootIndex = (text: string) => {
  if (!text.trimStart().startsWith('<')) {
    return -1;
  }
  let index = text.indexOf('<');
  while (index !== -1) {
    if (text.startsWith('<!--', index)) {
      const commentEnd = text.indexOf('-->', index + 4);
      index = commentEnd === -1 ? -1 : text.indexOf('<', commentEnd + 3);
    } else if (text.startsWith('<?', index) || text.startsWith('<!', index)) {
      index = text.indexOf('<', index + 2);
    } else {
      return /^<svg[\s/>]/.test(text.slice(index, index + 5)) ? index : -1;
    }
  }
  return -1;
};

// The end of the start tag that begins at `start`, just after its '>': a quoted attribute value may hold '>' or '/>'. -1 when never closed
const startTagEnd = (text: string, start: number) => {
  let quote: string | undefined;
  for (let index = start; index < text.length; index += 1) {
    const char = text[index];
    if (quote) {
      quote = char === quote ? undefined : quote;
    } else if (char === '"' || char === '\'') {
      quote = char;
    } else if (char === '>') {
      return index + 1;
    }
  }
  return -1;
};

// Whether an svg closing tag comes after `start`, outside the comments and the CDATA sections, which may hold one as text
const hasSvgClosingTag = (text: string, start: number) => {
  let index = text.indexOf('<', start);
  while (index !== -1) {
    let next: number;
    if (text.startsWith('<!--', index)) {
      next = text.indexOf('-->', index + 4);
    } else if (text.startsWith('<![CDATA[', index)) {
      next = text.indexOf(']]>', index + 9);
    } else if (/^<\/svg[\s>]/.test(text.slice(index, index + 6))) {
      return true;
    } else {
      next = index + 1;
    }
    // A comment or a CDATA section never closed holds the rest of the text
    if (next === -1) {
      return false;
    }
    index = text.indexOf('<', next);
  }
  return false;
};

// Whether the svg root goes on to its end: its start tag closed on itself, or followed by its closing tag
const isCompleteSvg = (text: string) => {
  const root = svgRootIndex(text);
  const tagEnd = root === -1 ? -1 : startTagEnd(text, root + 4);
  if (tagEnd === -1) {
    return false;
  }
  return text[tagEnd - 2] === '/' || hasSvgClosingTag(text, tagEnd);
};

export const fintelDesignLogoExtension = async (content: Buffer): Promise<string | undefined> => {
  const type = await fileTypeFromBuffer(content);
  if (type && RASTER_EXTENSIONS.includes(type.ext)) {
    return type.ext;
  }
  // An SVG is an XML document whose root is an svg element. The whole document is checked: its size is bounded by the callers,
  // which read FINTEL_DESIGN_LOGO_MAX_SIZE at most
  return svgRootIndex(svgText(content)) === -1 ? undefined : 'svg';
};

// Whether the logo goes on to the end its format sets, so that a browser can show it: a logo cut short (a signature alone, a download
// interrupted) is refused. The structure is checked, not every byte decoded.
// PNG: the IHDR chunk first and the IEND chunk with its CRC, data after it tolerated. JPEG: an end-of-image marker, data after it
// tolerated. GIF: the trailer as the last byte, blanks and NUL padding after it tolerated: the trailer is a byte any image data may hold,
// so it ends the file. WEBP: the RIFF size within the file. SVG: the root closed on itself, or followed by a closing tag outside a comment.
const PNG_END = Buffer.from([0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82]);
const GIF_PADDING = [0x00, 0x09, 0x0a, 0x0d, 0x20];
const GIF_HEADER_SIZE = 13;

const isCompleteGif = (content: Buffer) => {
  let last = content.length - 1;
  while (last > GIF_HEADER_SIZE && GIF_PADDING.includes(content[last])) {
    last -= 1;
  }
  return last > GIF_HEADER_SIZE && content[last] === 0x3b;
};

export const isCompleteFintelDesignLogo = (content: Buffer, extension: string) => {
  switch (extension) {
    case 'png':
      return content.toString('latin1', 12, 16) === 'IHDR' && content.includes(PNG_END, 16);
    case 'jpg':
      return content.lastIndexOf(Buffer.from([0xff, 0xd9])) >= 3;
    case 'gif':
      return isCompleteGif(content);
    case 'webp':
      return content.length >= 12 && content.readUInt32LE(4) >= 4 && content.readUInt32LE(4) + 8 <= content.length;
    case 'svg':
      return isCompleteSvg(svgText(content));
    default:
      return false;
  }
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

// The logo uploaded for a design, read whole before anything is stored: within the limit, in a format recognized from its bytes and going
// on to the end of it. Every logo stored is then one a browser can show and one the import of a configuration bundle takes back:
// the import checks the same, and refuses what the export would carry otherwise
export const readFintelDesignLogoUpload = async (source: Readable): Promise<Buffer> => {
  const chunks: Buffer[] = [];
  for await (const chunk of limitFintelDesignLogoStream(source)) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  const content = Buffer.concat(chunks);
  const extension = await fintelDesignLogoExtension(content);
  if (!extension || !isCompleteFintelDesignLogo(content, extension)) {
    throw FunctionalError('The logo of the fintel design is not a supported image');
  }
  return content;
};
