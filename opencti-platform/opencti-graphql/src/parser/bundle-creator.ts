import { v4 as uuidv4 } from 'uuid';
import type { StixBundle, StixObject } from '../types/stix-common';
import { STIX_SPEC_VERSION } from '../database/stix';

export const deduplicatedBundleData = (bundles: StixObject[]): StixObject[] => {
  return bundles.filter(
    (obj: StixObject, index, self) => index === self.findIndex(
      (t: StixObject) => {
        if (t.id === obj.id && t.type === obj.type) {
          // Cannot use isStixDomainObject because type is lowercase here and isStixDomainObject is case-sensitive.
          const abstractStixObject = t as any;
          if (abstractStixObject.labels) {
            const stixObject1 = t as any;
            const stixObject2 = obj as any;
            return stixObject1.id === stixObject2.id && stixObject1.labels === stixObject2.labels;
          }
          return t.id === obj.id;
        }
        return t.id === obj.id;
      }
    )
  );
};

export const deduplicatedBundleDataV2 = (bundles: StixObject[]): StixObject[] => {
  return bundles.filter(
    (obj: StixObject, index, self) => index === self.findIndex(
      (t: StixObject) => {
        return t.id === obj.id;
      }
    )
  );
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
    let canAdd = true;
    for (let i = 0; i < objectsToCheck.length; i += 1) {
      const currentToCheck = objectsToCheck[i];
      const existingObjectWithDifferentLabel = this.objects.find((item: StixObject) => {
        if (item.id === currentToCheck.id && item.type === currentToCheck.type) {
          const abstractStixObject = currentToCheck as any;
          if (abstractStixObject.labels) {
            const stixObject1 = currentToCheck as any;
            const stixObject2 = item as any;
            return stixObject1.labels !== stixObject2.labels;
          }
        }
        return false;
      });
      canAdd = canAdd && !existingObjectWithDifferentLabel;
    }
    return canAdd;
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
    const deduplicatedObjects = deduplicatedBundleDataV2(this.objects);

    return {
      id: this.id,
      spec_version: STIX_SPEC_VERSION,
      type: this.type,
      objects: deduplicatedObjects
    };
  }
}
