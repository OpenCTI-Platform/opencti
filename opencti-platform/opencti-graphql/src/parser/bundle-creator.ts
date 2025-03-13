import { v4 as uuidv4 } from 'uuid';
import * as R from 'ramda';
import type { StixBundle, StixObject } from '../types/stix-2-1/stix-2-1-common';
import { STIX_SPEC_VERSION } from '../database/stix';
import { STIX_EXT_OCTI } from '../types/stix-extensions';

export class BundleBuilder {
  id: string;

  type: 'bundle';

  objects: StixObject[];

  hashes: Map<string, string>;

  constructor() {
    this.id = `bundle--${uuidv4()}`;
    this.type = 'bundle';
    this.objects = [];
    this.hashes = new Map();
  }

  /**
   * Check if bundle object can be added to the current bundle or if a new bundle is required to use upsert feature.
   * If there is the same stix id but with different content => it need to be in another bundle because
   * Same stix id on the one bundle are removed from processing during worker split process (worker see them as duplicate).
   * @param objectsToAdd
   */
  canAddObjects(objectsToAdd: StixObject[]) {
    for (let i = 0; i < objectsToAdd.length; i += 1) {
      const currentToCheck = objectsToAdd[i];
      if (this.hashes.has(currentToCheck.id)) {
        const mapContent = this.hashes.get(currentToCheck.id);
        const currentItemJson = JSON.stringify(currentToCheck);
        if (mapContent !== currentItemJson) {
          return false;
        }
      }
    }
    return true;
  }

  addObject(object: StixObject, csvData: string) {
    const key = object.id;
    const value = JSON.stringify(object);
    this.hashes.set(key, value);
    const objectCopy = object;
    if (objectCopy.extensions) {
      objectCopy.extensions[STIX_EXT_OCTI].converter_csv = csvData;
    }
    this.objects.push(objectCopy);
    return this;
  }

  addObjects(objects: StixObject[], csvData: string) {
    for (let i = 0; i < objects.length; i += 1) {
      this.addObject(objects[i], csvData);
    }
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
