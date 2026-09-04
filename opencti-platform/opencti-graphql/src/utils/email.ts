export const normalizeEmail = (email?: string | null): string => {
  if (!email || typeof email !== 'string') return '';
  return email.trim().toLowerCase();
};
