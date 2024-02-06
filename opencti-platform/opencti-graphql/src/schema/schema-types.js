export const schemaTypesDefinition = {
    types: {},
    // types
    isTypeIncludedIn(type, parent) {
        var _a, _b;
        return (_b = (_a = this.types[parent]) === null || _a === void 0 ? void 0 : _a.has(type)) !== null && _b !== void 0 ? _b : false;
    },
    register(type, children) {
        this.types[type] = new Map(children.map((c) => [c, undefined]));
    },
    add(type, children) {
        const values = Array.isArray(children) ? children : [children];
        const currentMap = this.types[type];
        if (currentMap) {
            values.forEach((v) => currentMap.set(v));
        }
        else {
            this.types[type] = new Map(values.map((c) => [c, undefined]));
        }
    },
    get(type) {
        return Array.from(this.types[type].keys());
    },
    hasChildren(type) {
        var _a;
        return ((_a = this.types[type]) === null || _a === void 0 ? void 0 : _a.size) > 0;
    }
};
