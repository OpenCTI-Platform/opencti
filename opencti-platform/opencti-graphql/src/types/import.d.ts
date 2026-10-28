// The convention of the import of a module (themes today): `import<Thing>(context, user, configuration, options)` validates the
// configuration, applies the rules of the module and writes it. It does not throw for a rule violation: it returns the refusal.
// A dry run decides the same result and writes nothing, publishes nothing.
// The export is the other way round: each module owns the format of its configuration, and the schema that validates the import
// is the one the export is built from.
export type ImportMode = 'add' | 'overwrite';

export type ImportStatus = 'created' | 'overwritten' | 'skipped' | 'failed';

export interface ImportOptions {
  mode: ImportMode;
  dryRun?: boolean;
}

export interface ImportResult<TConfiguration = unknown, TCode extends string = string> {
  status: ImportStatus;
  // Why nothing is imported, the codes are the ones of the module
  code?: TCode;
  // The text shown to the user
  reason?: string;
  // Whether the item is already on the platform
  exists: boolean;
  // The configuration once validated, absent when it is invalid
  configuration?: TConfiguration;
}
