import { v4 as uuidv4 } from 'uuid';
import * as R from 'ramda';
import { STIX_SPEC_VERSION } from '../database/stix';
export class BundleBuilder {
    constructor() {
        this.id = `bundle--${uuidv4()}`;
        this.type = 'bundle';
        this.objects = [];
    }
    addObject(object) {
        this.objects.push(object);
        return this;
    }
    addObjects(objects) {
        this.objects.push(...objects);
        return this;
    }
    ids() {
        return this.objects.map((o) => o.id);
    }
    build() {
        return {
            id: this.id,
            spec_version: STIX_SPEC_VERSION,
            type: this.type,
            objects: R.uniqBy(R.prop('id'), this.objects)
        };
    }
}
