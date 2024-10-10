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

export class BundleBuilder {
  id: string;

  type: 'bundle';

  objects: StixObject[];

  constructor() {
    this.id = `bundle--${uuidv4()}`;
    this.type = 'bundle';
    this.objects = [];
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
