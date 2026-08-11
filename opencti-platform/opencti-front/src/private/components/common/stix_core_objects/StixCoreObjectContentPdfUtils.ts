export const isPdfPasswordError = (error: { name?: string; message?: string } | undefined | null) => {
  if (!error) return false;
  const errorName = (error.name ?? '').toLowerCase();
  const errorMessage = (error.message ?? '').toLowerCase();
  return errorName.includes('password')
    || errorMessage.includes('password')
    || errorMessage.includes('no password given');
};
