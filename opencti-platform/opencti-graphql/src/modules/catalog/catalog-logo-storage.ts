import crypto from 'crypto';
import { rawListObjects, rawUpload } from '../../database/raw-file-storage';
import { parseDataUrl } from '../../utils/data-url';
import type { CatalogContractDtoV0 } from './catalog-types';
import { CATALOG_LOGO_VIEW_PATH } from './catalog-http';

export const CATALOG_CONTRACT_LOGOS_DIR = 'catalog-logos';

export type CatalogContractLogoUploadOperation = {
  filename: string;
  s3Key: string;
  body: Buffer;
  logoUri: string;
};

export const listCatalogContractLogos = async () => {
  const result = await rawListObjects(CATALOG_CONTRACT_LOGOS_DIR, false);
  if (!result.Contents) {
    return new Set<string>();
  }
  return new Set<string>(result.Contents.map((object) => {
    return object?.Key?.substring(CATALOG_CONTRACT_LOGOS_DIR.length + 1) ?? '';
  }).filter(Boolean));
};

// https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/MIME_types/Common_types
// List of image mime types commonly supported by browsers
const IMAGE_MIME_TYPES_TO_EXTENSION = {
  'image/apng': '.apng',
  'image/avif': '.avif',
  'image/bmp': '.bmp',
  'image/gif': '.gif',
  'image/jpeg': '.jpg',
  'image/png': '.png',
  'image/svg+xml': '.svg',
  'image/tiff': '.tiff',
  'image/webp': '.webp',
};

const EXTENSION_TO_MIME_TYPES = Object.entries(IMAGE_MIME_TYPES_TO_EXTENSION).reduce((acc, [mimeType, extension]) => {
  acc[extension] = mimeType;
  return acc;
}, {} as Record<string, string>);

const isImageMimeType = (mimeType: string): mimeType is keyof typeof IMAGE_MIME_TYPES_TO_EXTENSION => {
  return Object.keys(IMAGE_MIME_TYPES_TO_EXTENSION).includes(mimeType);
};

const getExtensionFromImageMimeType = (mimeType: keyof typeof IMAGE_MIME_TYPES_TO_EXTENSION) => {
  return IMAGE_MIME_TYPES_TO_EXTENSION[mimeType];
};

export const getMimeTypeFromImageExtension = (extension: string) => {
  return EXTENSION_TO_MIME_TYPES[extension];
};

const CATALOG_CONTRACT_LOGO_MAX_SIZE_BYTES = 20 * 1024 * 1024; // 20MB

const isLikelyBase64 = (payload: string) => {
  const sanitizedPayload = payload.replace(/\s+/g, '');
  if (sanitizedPayload.length === 0 || sanitizedPayload.length % 4 !== 0) {
    return false;
  }
  return /^[A-Za-z0-9+/]*={0,2}$/.test(sanitizedPayload);
};

const computeLogoHash = (logoContent: Buffer) => {
  return crypto.createHash('md5').update(logoContent).digest('hex');
};

export const storeCatalogContractLogo = async (
  contractDto: CatalogContractDtoV0,
  existingLogos: Set<string>,
) => {
  const operationResult = computeCatalogContractLogoUploadOperation(contractDto, existingLogos);
  if (operationResult.result !== 'success' || operationResult.existed) {
    return operationResult;
  }
  if (!operationResult.operation) {
    const error = new Error('Missing logo upload operation');
    return {
      result: 'failed' as const,
      logoUri: null,
      error,
    };
  }

  const uploadResult = await uploadCatalogContractLogoOperation(operationResult.operation);
  if (uploadResult.result === 'failed') {
    return {
      result: 'failed' as const,
      logoUri: null,
      error: uploadResult.error,
    };
  }
  return {
    result: 'success' as const,
    existed: false,
    logoUri: operationResult.logoUri,
    filename: operationResult.filename,
  };
};

export const computeCatalogContractLogoUploadOperation = (
  contractDto: CatalogContractDtoV0,
  existingLogos: Set<string>,
) => {
  const { logo } = contractDto;
  if (!logo) {
    return {
      result: 'no-logo' as const,
      logoUri: null,
    };
  }
  if (!logo.startsWith('data:')) {
    const error = new Error('Unsupported logo data format: not a data URL');
    return {
      result: 'failed' as const,
      logoUri: null,
      error,
    };
  }
  const { mimeType, base64Encoded, data } = parseDataUrl(logo);
  if (!isImageMimeType(mimeType)) {
    const error = new Error('Unsupported logo mime type', {
      cause: {
        mimeType,
      },
    });
    return {
      result: 'failed' as const,
      logoUri: null,
      error,
    };
  }
  let decodedData: Buffer;
  if (base64Encoded) {
    if (!isLikelyBase64(data)) {
      const error = new Error('Unsupported logo data format: invalid base64 payload');
      return {
        result: 'failed' as const,
        logoUri: null,
        error,
      };
    }
    decodedData = Buffer.from(data, 'base64');
  } else {
    try {
      decodedData = Buffer.from(decodeURIComponent(data), 'utf8');
    } catch (err: unknown) {
      const error = new Error('Unsupported logo data format: invalid URL-encoded payload', {
        cause: err,
      });
      return {
        result: 'failed' as const,
        logoUri: null,
        error,
      };
    }
  }
  if (decodedData.byteLength === 0) {
    const error = new Error('Unexpected zero-length logo data');
    return {
      result: 'failed' as const,
      logoUri: null,
      error,
    };
  }
  if (decodedData.byteLength > CATALOG_CONTRACT_LOGO_MAX_SIZE_BYTES) {
    const error = new Error(`Unsupported logo data format: image exceeds max size (${CATALOG_CONTRACT_LOGO_MAX_SIZE_BYTES} bytes)`);
    return {
      result: 'failed' as const,
      logoUri: null,
      error,
    };
  }
  const hash = computeLogoHash(decodedData);
  const extension = getExtensionFromImageMimeType(mimeType);
  const filename = `${hash}${extension}`;
  const s3Key = `${CATALOG_CONTRACT_LOGOS_DIR}/${filename}`;
  const logoUri = CATALOG_LOGO_VIEW_PATH.replace('*file', s3Key);
  if (existingLogos.has(filename)) {
    return {
      result: 'success' as const,
      existed: true,
      logoUri,
      filename,
    };
  }
  const operation: CatalogContractLogoUploadOperation = {
    filename,
    s3Key,
    body: decodedData,
    logoUri,
  };
  return {
    result: 'success' as const,
    existed: false,
    logoUri,
    filename,
    operation,
  };
};

export const uploadCatalogContractLogoOperation = async (operation: CatalogContractLogoUploadOperation) => {
  try {
    await rawUpload(operation.s3Key, operation.body);
  } catch (err: unknown) {
    const error = new Error('Failed to upload logo content to file storage', {
      cause: err,
    });
    return {
      result: 'failed' as const,
      error,
    };
  }
  return {
    result: 'success' as const,
  };
};
