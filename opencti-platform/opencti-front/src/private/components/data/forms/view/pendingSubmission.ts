import { PENDING_ENTITY_PREFIX, PendingObjectData } from '../../../../../utils/hooks/useDeferredCreation';

/**
 * Serialization of the objects prepared in a Form Intake, following the deferred creation
 * contract of the backend (form-pending.ts): roots carry a local id, refs and files; the
 * labels and external references they reference travel in a pool. Anything nobody references
 * (a cancelled dialog) is never serialized.
 */
export type PendingRef = { existing: string } | { pending: string };

export interface PendingFilePayload {
  name: string;
  mime_type?: string;
  uploadIndex: number; // index in the `files` uploads of the submission
  embedded?: boolean; // markdown image pasted in a description, not an attached file
}

export interface PendingObjectPayload {
  id?: string;
  entityType: string;
  input: Record<string, unknown>;
  refs?: Partial<Record<string, PendingRef | PendingRef[]>>;
  files?: PendingFilePayload[];
}

export interface PendingOption {
  value: string;
  isPendingCreation?: boolean;
  pendingInputData?: PendingObjectData;
}

// References are carried by `refs`, uploads by `files`: neither stays in the input.
const REF_KEYS = ['createdBy', 'objectMarking', 'objectLabel', 'externalReferences', 'killChainPhases'];
const UPLOAD_KEYS = ['files', 'embedded', 'file'];
// Only labels and external references can be created on submission.
const PENDING_REF_KEYS = ['objectLabel', 'externalReferences'];

export const isPendingId = (value: unknown): value is string => typeof value === 'string' && value.startsWith(PENDING_ENTITY_PREFIX);

const toIds = (value: unknown): string[] => (Array.isArray(value) ? value : [value]).filter((id): id is string => typeof id === 'string' && id.length > 0);

const omit = (input: Record<string, unknown>, keys: string[]) => Object.fromEntries(Object.entries(input).filter(([key]) => !keys.includes(key)));

export const createPendingCollector = (getPending: (id: string) => PendingObjectData | undefined = () => undefined) => {
  const files: File[] = [];
  const pool = new Map<string, PendingObjectPayload>();

  // The files of a pending object go to the uploads of the submission, the object keeps their index.
  // `embedded[i]` flags the markdown images of its descriptions among its files.
  const takeFiles = (input: Record<string, unknown>): PendingFilePayload[] => {
    const embedded = Array.isArray(input.embedded) ? input.embedded : [];
    return (Array.isArray(input.files) ? input.files as File[] : []).flatMap((file, index) => {
      if (!(file instanceof File)) return [];
      files.push(file);
      return [{
        name: file.name,
        mime_type: file.type || undefined,
        uploadIndex: files.length - 1,
        ...(embedded[index] === true ? { embedded: true } : {}),
      }];
    });
  };

  // A pending id goes to the pool (once), an existing id stays an existing ref.
  const refOf = (id: string): PendingRef => {
    if (!isPendingId(id)) return { existing: id };
    const data = getPending(id);
    if (data && !pool.has(id)) {
      const pooled: PendingObjectPayload = { id, entityType: data.entityType, input: omit(data.input, [...REF_KEYS, ...UPLOAD_KEYS]) };
      const pooledFiles = takeFiles(data.input);
      if (pooledFiles.length > 0) pooled.files = pooledFiles;
      pool.set(id, pooled);
    }
    return { pending: id };
  };

  const root = (option: PendingOption): PendingObjectPayload => {
    const { entityType, input } = option.pendingInputData as PendingObjectData;
    const refs: Record<string, PendingRef | PendingRef[]> = {};
    if (typeof input.createdBy === 'string' && input.createdBy) refs.createdBy = { existing: input.createdBy };
    REF_KEYS.filter((key) => key !== 'createdBy').forEach((key) => {
      const ids = toIds(input[key]);
      if (input[key] !== undefined && ids.length > 0) {
        refs[key] = ids.map((id) => (PENDING_REF_KEYS.includes(key) ? refOf(id) : { existing: id }));
      }
    });
    const pendingFiles = takeFiles(input);
    const payload: PendingObjectPayload = { id: option.value, entityType, input: omit(input, [...REF_KEYS, ...UPLOAD_KEYS]) };
    if (Object.keys(refs).length > 0) payload.refs = refs;
    if (pendingFiles.length > 0) payload.files = pendingFiles;
    return payload;
  };

  return { files, root, refOf, pooled: () => [...pool.values()] };
};

export type PendingCollector = ReturnType<typeof createPendingCollector>;
