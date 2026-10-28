// The convention of the import of a module (themes today): `import<Thing>(context, user, configuration, options)` validates the
// configuration, applies the rules of the module and writes it. It does not throw for a rule violation: it returns the refusal.
// A dry run decides the same result and writes nothing, publishes nothing.
// The export is the other way round: each module owns the format of its configuration, and the schema that validates the import
// is the one the export is built from.
// add: an item that exists is refused. overwrite: it is patched, and an item that does not exist is created.
// copy: it is created under a free name, and under a new identity when its own exists.
// The enum is the one of the GraphQL schema, which a configuration preset takes by type: ADD is for the import of a single item, no type offers it.
import { ConfigImportMode } from '../../generated/graphql';

export { ConfigImportMode };

export type ConfigImportStatus = 'created' | 'overwritten' | 'skipped' | 'failed';

export interface ConfigImportOptions {
  mode: ConfigImportMode;
  dryRun?: boolean;
}

export interface ConfigImportResult<TConfiguration = unknown, TCode extends string = string> {
  status: ConfigImportStatus;
  // Why nothing is imported, the codes are the ones of the module
  code?: TCode;
  // The text shown to the user: why nothing is imported, or what differs from the configuration (the name of a copy)
  reason?: string;
  // Whether the item is already on the platform
  exists: boolean;
  // The configuration once validated, absent when it is invalid
  configuration?: TConfiguration;
}
