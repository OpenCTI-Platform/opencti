// The reason of an import that failed its validation: one `path: message` per issue of the Zod error
export const configImportValidationReason = (error: { issues: { path: PropertyKey[]; message: string }[] }) => {
  return error.issues.map((issue) => `${issue.path.map(String).join('.') || 'configuration'}: ${issue.message}`).join(', ');
};

const MAX_COPIES = 100;

// The name itself when it is free, else the first free `name (n)`; undefined when the first copies are all taken
export const freeConfigImportName = async (name: string, isTaken: (candidate: string) => Promise<boolean>) => {
  if (!(await isTaken(name))) {
    return name;
  }
  for (let copy = 1; copy <= MAX_COPIES; copy += 1) {
    const candidate = `${name} (${copy})`;
    // The next candidate depends on this answer
    if (!(await isTaken(candidate))) {
      return candidate;
    }
  }
  return undefined;
};

// An item can have several reasons (the name of its copy, what the import grants, what it leaves out): one per line, the front translates each
export const CONFIG_IMPORT_REASON_SEPARATOR = '\n';
export const joinConfigImportReasons = (reasons: (string | undefined)[]) => {
  const present = reasons.filter((reason): reason is string => !!reason);
  return present.length > 0 ? present.join(CONFIG_IMPORT_REASON_SEPARATOR) : undefined;
};
