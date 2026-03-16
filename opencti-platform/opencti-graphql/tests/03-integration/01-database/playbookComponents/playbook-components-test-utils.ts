import { v4 as uuid } from 'uuid';
import type { StixObject, StixOpenctiExtension } from '../../../../src/types/stix-2-1-common';
import { STIX_EXT_OCTI } from '../../../../src/types/stix-2-1-extensions';
import type { StixId } from '../../../../src/types/stix-2-0-common';
import type { ExecutorParameters } from '../../../../src/modules/playbook/playbook-types';

type TestBundleObjectArgs<T extends StixObject> = {
  id?: StixId;
  type: string;
  extension?: Partial<StixOpenctiExtension>;
} & Partial<Omit<T, 'extension' | 'id' | 'type'>>;

export const testBundleObject = <T extends StixObject>({
  id,
  type,
  extension,
}: TestBundleObjectArgs<T>): T => {
  return {
    id: id ?? `${type}--${uuid()}`,
    type,
    spec_version: '2.1',
    extensions: {
      [STIX_EXT_OCTI]: {
        extension_type: 'property-extension',
        id,
        type,
        ...extension,
      } as StixOpenctiExtension,
    },
  } as T;
};

type TestExecutorArgs<T extends object> = {
  mainId: string;
  bundleObjects: StixObject[];
  configuration: T;
};

export const testExecutor = <T extends object>({
  mainId,
  bundleObjects,
  configuration,
}: TestExecutorArgs<T>): ExecutorParameters<T> => {
  return {
    eventId: uuid(),
    executionId: uuid(),
    playbookId: uuid(),
    previousPlaybookNodeId: undefined,
    previousStepBundle: null,
    dataInstanceId: mainId,
    bundle: {
      id: `bundle--${uuid()}`,
      spec_version: '2.1',
      type: 'bundle',
      objects: [...bundleObjects],
    },
    playbookNode: {
      id: uuid(),
      component_id: uuid(),
      name: 'Test Playbook node',
      configuration,
    },
  };
};
