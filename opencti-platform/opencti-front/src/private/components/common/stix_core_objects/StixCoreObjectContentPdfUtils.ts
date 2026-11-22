// An export asked to a connector is listed as its work until the file is pushed:
// 'wait' until the connector takes it, then 'progress'. Its id is the work id
// (work_...), not a file the storage can serve.
export const isOngoingExport = (file: { uploadStatus?: string | null } | undefined | null) => {
  return file?.uploadStatus === 'wait' || file?.uploadStatus === 'progress';
};

export const isPdfPasswordError = (error: { name?: string; message?: string } | undefined | null) => {
  if (!error) return false;
  const errorName = (error.name ?? '').toLowerCase();
  const errorMessage = (error.message ?? '').toLowerCase();
  return errorName.includes('password')
    || errorMessage.includes('password')
    || errorMessage.includes('no password given');
};
