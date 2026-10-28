// The convention of the import of a module (themes today): `import<Thing>(context, user, configuration, options)` validates the
// configuration, applies the rules of the module and writes it. It does not throw for a rule violation: it returns the refusal.
// A dry run decides the same result and writes nothing, publishes nothing.
// The export is the other way round: each module owns the format of its configuration, and the schema that validates the import
// is the one the export is built from.
// add: an item that exists is refused. overwrite: it is patched, and an item that does not exist is created.
export type ConfigImportMode = 'add' | 'overwrite';

export type ConfigImportStatus = 'created' | 'overwritten' | 'skipped' | 'failed';

export interface ConfigImportOptions {
  mode: ConfigImportMode;
  dryRun?: boolean;
}

export interface ConfigImportResult<TConfiguration = unknown, TCode extends string = string> {
  status: ConfigImportStatus;
  // Why nothing is imported, the codes are the ones of the module
  code?: TCode;
  // The text shown to the user
  reason?: string;
  // Whether the item is already on the platform
  exists: boolean;
  // The configuration once validated, absent when it is invalid
  configuration?: TConfiguration;
}
