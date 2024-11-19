import { v4 as uuidv4 } from 'uuid';
import * as R from 'ramda';
import type { StixBundle, StixObject } from '../types/stix-common';
import { STIX_SPEC_VERSION } from '../database/stix';
/**
 * Check if bundle object can be added to the current bundle or if a new bundle is required to use upsert feature.
 * If there is the same stix id but with different content => it need to be in another bundle because
 * Same stix id on the one bundle are removed from processing during worker split process (worker see them as duplicate).
 * @param objectsToAdd
 * @param bundles
 */
export const canAddObjectToBundle = (objectsToAdd: StixObject[], bundles: StixObject[]): boolean => {
  const canAdd = true;
  for (let i = 0; i < objectsToAdd.length; i += 1) {
    const currentToCheck = objectsToAdd[i];
    /* const currentToCheckClone = structuredClone(currentToCheck);
    if (currentToCheckClone.extensions) {
      currentToCheckClone.extensions[STIX_EXT_OCTI].converter_csv = undefined;
    }
    const currentItemJson = JSON.stringify(currentToCheckClone); */
    const currentItemJson = JSON.stringify(currentToCheck);
    const existingObjectWithDifferentContent = bundles.find((item) => {
      if (item.id === currentToCheck.id && item.type === currentToCheck.type) {
        /* const itemClone = structuredClone(item);
        if (itemClone.extensions) {
          itemClone.extensions[STIX_EXT_OCTI].converter_csv = undefined;
        }

        const itemAsJson = JSON.stringify(itemClone); */

        /* if (itemAsJson !== currentItemJson) {
          logApp.info('SAME STIX ID with diff content', { itemAsJson, currentItemJson });
        } */

        const itemAsJson = JSON.stringify(item);

        return itemAsJson !== currentItemJson;
      }
      return false;
    });
    if (existingObjectWithDifferentContent) {
      return false;
    }
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
    return {
      id: this.id,
      spec_version: STIX_SPEC_VERSION,
      type: this.type,
      objects: R.uniqBy(R.prop('id'), this.objects)
    };
  }
}
