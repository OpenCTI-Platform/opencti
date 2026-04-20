import { useCallback, useRef } from 'react';

type StoreTempImagesForEntityFn = (uploadEntityIdOverride?: string) => Promise<string>;

type UseStoreTempImagesForEntityAfterCreateOptions<Response, Values> = {
  getCreatedId: (response: Response) => string | null | undefined;
  getInitialValue: (values: Values) => string;
  patchField: (id: string, value: string) => Promise<void>;
  shouldPatch?: (storedValue: string, initialValue: string) => boolean;
};

type StoreTempImagesCallbacks = {
  onSuccess: () => void;
  onError?: () => void;
};

const defaultShouldPatch = (storedValue: string, initialValue: string) => storedValue !== initialValue;

// On create, temp markdown image tokens cannot be persisted until the new entity id exists.
// This hook stores temp images for that entity, rewrites markdown, then patches the field if needed.
const useStoreTempImagesForEntityAfterCreate = <Response, Values>(
  options: UseStoreTempImagesForEntityAfterCreateOptions<Response, Values>,
) => {
  const { getCreatedId, getInitialValue, patchField, shouldPatch = defaultShouldPatch } = options;
  const storeTempImagesForEntityRef = useRef<StoreTempImagesForEntityFn | null>(null);

  const registerStoreTempImagesForEntity = useCallback((storeTempImagesForEntity: StoreTempImagesForEntityFn) => {
    storeTempImagesForEntityRef.current = storeTempImagesForEntity;
  }, []);

  const storeTempImagesForEntity = useCallback(async (response: Response, values: Values): Promise<void> => {
    const createdEntityId = getCreatedId(response);
    if (!createdEntityId || !storeTempImagesForEntityRef.current) {
      return;
    }

    const initialValue = getInitialValue(values);
    const storedValue = await storeTempImagesForEntityRef.current(createdEntityId);
    if (shouldPatch(storedValue, initialValue)) {
      await patchField(createdEntityId, storedValue);
    }
  }, [getCreatedId, getInitialValue, patchField, shouldPatch]);

  const runAfterStoringTempImagesForEntity = useCallback(async (
    response: Response,
    values: Values,
    callbacks: StoreTempImagesCallbacks,
  ): Promise<void> => {
    try {
      await storeTempImagesForEntity(response, values);
      callbacks.onSuccess();
    } catch {
      callbacks.onError?.();
    }
  }, [storeTempImagesForEntity]);

  const getTempImageFieldProps = useCallback((uploadFileMarkings?: string[]) => {
    return {
      finalizeOnBlur: false as const,
      registerFinalize: registerStoreTempImagesForEntity,
      uploadFileMarkings,
    };
  }, [registerStoreTempImagesForEntity]);

  return {
    registerStoreTempImagesForEntity,
    storeTempImagesForEntity,
    runAfterStoringTempImagesForEntity,
    getTempImageFieldProps,
  };
};

export default useStoreTempImagesForEntityAfterCreate;
