import { v4 as uuidv4 } from 'uuid';
import type { StixBundle, StixObject } from '../types/stix-common';
import { STIX_SPEC_VERSION } from '../database/stix';

export const deduplicatedBundleData = (bundles: StixObject[]): StixObject[] => {
  return bundles.filter(
    (obj: StixObject, index, self) => index === self.findIndex(
      (t: StixObject) => {
        return t.id === obj.id;
      }
    )
  );
};

/**
 * Check if bundle object can be added to the current bundle or if a new bundle is required to use upsert feature.
 * Same ids on the one bundle are removed from processing during worker split process.
 * @param objectsToAdd
 * @param bundles
 */
export const canAddObjectToBundle = (objectsToAdd: StixObject[], bundles: StixObject[]): boolean => {
  let canAdd = true;
  for (let i = 0; i < objectsToAdd.length; i += 1) {
    const currentToCheck = objectsToAdd[i];
    const existingObjectWithDifferentContent = bundles.find((item: StixObject) => {
      if (item.id === currentToCheck.id && item.type === currentToCheck.type) {
        return JSON.stringify(item) !== JSON.stringify(currentToCheck);
      }
      return false;
    });
    canAdd = canAdd && !existingObjectWithDifferentContent;
  }
  return canAdd;
};

export class BundleBuilder {
  id: string;

  type: 'bundle';

  objects: StixObject[];

  constructor() {
    this.id = `bundle--${uuidv4()}`;
    this.type = 'bundle';
    this.objects = [];
  }

  canAddObjects(objectsToCheck: StixObject[]) {
    return canAddObjectToBundle(objectsToCheck, this.objects);
  }

  addObject(object: StixObject) {
    this.objects.push(object);
    return this;
  }

  addObjects(objects: StixObject[]) {
    this.objects.push(...objects);
    return this;
  }

  ids() {
    return this.objects.map((o) => o.id);
  }

  build(): StixBundle {
    const deduplicatedObjects = deduplicatedBundleData(this.objects);

    return {
      id: this.id,
      spec_version: STIX_SPEC_VERSION,
      type: this.type,
      objects: deduplicatedObjects
    };
  }
}
