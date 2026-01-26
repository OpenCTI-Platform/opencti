export type ValidationWork = {
  id?: string;
  tracking?: {
    import_expected_number?: number | null;
    import_processed_number?: number | null;
  } | null;
} | null | undefined;

export const computeValidationProgress = <T extends ValidationWork>(validationWork: T) => {
  if (!validationWork) {
    return '';
  }
  if (!validationWork.tracking?.import_expected_number || !validationWork.tracking?.import_processed_number) {
    return '0%';
  }

  return `${Math.floor(100 * (validationWork.tracking.import_processed_number / validationWork.tracking.import_expected_number))}%`;
};
