// The reason of an import that failed its validation: one `path: message` per issue of the Zod error
export const configImportValidationReason = (error: { issues: { path: PropertyKey[]; message: string }[] }) => {
  return error.issues.map((issue) => `${issue.path.map(String).join('.') || 'configuration'}: ${issue.message}`).join(', ');
};
