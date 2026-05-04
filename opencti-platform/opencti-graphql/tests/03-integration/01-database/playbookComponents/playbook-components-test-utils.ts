import { v4 as uuid } from 'uuid';
import type { CyberObjectExtension, StixBundle, StixObject, StixOpenctiExtension } from '../../../../src/types/stix-2-1-common';
import { STIX_EXT_OCTI, STIX_EXT_OCTI_SCO } from '../../../../src/types/stix-2-1-extensions';
import type { StixId } from '../../../../src/types/stix-2-0-common';
import type { ExecutorParameters } from '../../../../src/modules/playbook/playbook-types';

type TestBundleObjectArgs<T extends StixObject> = {
  id?: StixId;
  type: string;
  octiExtension?: Partial<StixOpenctiExtension>;
  scoExtension?: Partial<CyberObjectExtension>;
} & Partial<Omit<T, 'extensions' | 'id' | 'type'>>;

export const testBundleObject = <T extends StixObject>({
  id,
  type,
  octiExtension,
  scoExtension,
  ...args
}: TestBundleObjectArgs<T>): T => {
  return {
    id: id ?? `${type}--${uuid()}`,
    type,
    spec_version: '2.1',
    ...args,
    extensions: {
      [STIX_EXT_OCTI]: {
        extension_type: 'property-extension',
        id,
        type,
        ...octiExtension,
      },
      ...(scoExtension
        ? {
            [STIX_EXT_OCTI_SCO]: {
              extension_type: 'property-extension',
              ...scoExtension,
            },
          } : {}
      ),
    },
  } as T;
};

type TestExecutorArgs<T extends object> = {
  mainId: string;
  bundle?: StixBundle;
  bundleObjects?: StixObject[];
  configuration: T;
  previousStepBundle?: StixBundle | null;
};

export const testExecutor = <T extends object>({
  mainId,
  bundle,
  bundleObjects = [],
  configuration,
  previousStepBundle = null,
}: TestExecutorArgs<T>): ExecutorParameters<T> => {
  return {
    eventId: uuid(),
    executionId: uuid(),
    playbookId: uuid(),
    previousPlaybookNodeId: undefined,
    previousStepBundle,
    dataInstanceId: mainId,
    bundle: bundle ?? {
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
