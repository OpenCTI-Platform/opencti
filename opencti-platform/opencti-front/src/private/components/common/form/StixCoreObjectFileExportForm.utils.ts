import { parse } from '../../../../utils/Time';
import { FieldOption } from '../../../../utils/field';

const MAX_ENTITY_NAME_LENGTH = 100;
const MAX_MARKING_LENGTH = 100;
const EXPORT_FILE_SUFFIX_REGEXP = /_\d{8}T\d{4}Z(?:_[A-Z0-9]+(?:-[A-Z0-9]+)*)?$/;

export const sanitizeFileNamePart = (
  input: string | null | undefined,
  fallback: string,
  maxLength: number,
): string => {
  const base = (input ?? '').trim();
  const cleaned = base
    .replace(/[\\/:*?"<>|]+/g, '_')
    .replace(/\s+/g, '_')
    .replace(/_+/g, '_')
    .replace(/^_+|_+$/g, '');

  const value = cleaned || fallback;
  return value.length > maxLength ? value.slice(0, maxLength) : value;
};

export const formatExportUtcTimestamp = (utcIsoDate: string): string => {
  return parse(utcIsoDate).utc().format('YYYYMMDDTHHmm[Z]');
};

export const normalizeMarkingForFileName = (markings?: FieldOption[] | null): string | null => {
  const firstMarking = markings?.[0]?.label;
  if (!firstMarking) {
    return null;
  }

  const normalized = firstMarking
    .trim()
    .toUpperCase()
    // replace any non-alphanumeric character with a hyphen
    .replace(/[^A-Z0-9]+/g, '-')
    // collapse consecutive hyphens
    .replace(/-{2,}/g, '-')
    // strip leading/trailing hyphens
    .replace(/^-+|-+$/g, '');

  if (!normalized) {
    return null;
  }

  return normalized.length > MAX_MARKING_LENGTH ? normalized.slice(0, MAX_MARKING_LENGTH) : normalized;
};

export const normalizeExportSourceEntityName = (fileName?: string | null): string | null => {
  if (!fileName) {
    return null;
  }

  const fileBaseName = fileName.replace(/\.[^./\\]+$/, '');
  // If the selected source is already an export, strip trailing "_timestamp[_marking]"
  // so a new export does not duplicate those segments in the generated filename.
  return fileBaseName.replace(EXPORT_FILE_SUFFIX_REGEXP, '');
};

interface BuildExportFileNameInput {
  entityName?: string | null;
  markings?: FieldOption[] | null;
  utcIsoDate: string;
}

export const buildExportFileName = ({
  entityName,
  markings,
  utcIsoDate,
}: BuildExportFileNameInput): string => {
  const safeEntityName = sanitizeFileNamePart(entityName, 'Export', MAX_ENTITY_NAME_LENGTH);
  const timestamp = formatExportUtcTimestamp(utcIsoDate);
  const marking = normalizeMarkingForFileName(markings);

  if (!marking) {
    return `${safeEntityName}_${timestamp}`;
  }

  return `${safeEntityName}_${timestamp}_${marking}`;
};
