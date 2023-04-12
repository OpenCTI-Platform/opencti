export const schemaTypesDefinition = {
  types: {} as Record<string, Map<string, void>>,

  // types
  isTypeIncludedIn(type: string, parent: string) {
    return this.types[parent]?.has(type) ?? false;
  },
  register(type: string, children: string[]) {
    this.types[type] = new Map(children.map((c) => [c, undefined]));
  },
  add(type: string, children: string[] | string) {
    const values = Array.isArray(children) ? children : [children];
    const currentMap = this.types[type];
    if (currentMap) {
      values.forEach((v) => currentMap.set(v));
    } else {
      this.types[type] = new Map(values.map((c) => [c, undefined]));
    }
  },
  get(type: string): string[] {
    return Array.from(this.types[type].keys());
  },

};
