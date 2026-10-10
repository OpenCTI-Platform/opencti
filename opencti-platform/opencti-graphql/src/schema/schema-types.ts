import { UnsupportedError } from '../config/errors';

// Once read, the types are read-only: a type registered afterwards would be missing from what was already read,
// such as a list of subtypes copied at import time. Reads made by a registration, to resolve the parents of the
// type it registers, do not count.
let usageProtection = false;
let registrationDepth = 0;

export const withinRegistration = <T>(read: () => T): T => {
  registrationDepth += 1;
  try {
    return read();
  } finally {
    registrationDepth -= 1;
  }
};

const protectUsage = () => {
  if (registrationDepth === 0) {
    usageProtection = true;
  }
};

const checkRegistration = (type: string) => {
  if (usageProtection) {
    throw UnsupportedError('Register types use after usage, please check your imports', { type });
  }
};

export const schemaTypesDefinition = {
  types: {} as Record<string, Map<string, void>>,

  // types
  isTypeIncludedIn(type: string, parent: string) {
    protectUsage();
    return this.types[parent]?.has(type) ?? false;
  },
  register(type: string, children: string[]) {
    checkRegistration(type);
    this.types[type] = new Map(children.map((c) => [c, undefined]));
  },
  add(type: string, children: string[] | string) {
    checkRegistration(type);
    const values = Array.isArray(children) ? children : [children];
    const currentMap = this.types[type];
    if (currentMap) {
      values.forEach((v) => currentMap.set(v));
    } else {
      this.types[type] = new Map(values.map((c) => [c, undefined]));
    }
  },
  get(type: string): string[] {
    protectUsage();
    return Array.from(this.types[type].keys());
  },
  hasChildren(type: string): boolean {
    protectUsage();
    return this.types[type]?.size > 0;
  },

};
