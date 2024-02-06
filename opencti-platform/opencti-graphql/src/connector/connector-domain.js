var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { importCsvConnector, importCsvConnectorRuntime } from './importCsv/importCsv-domain';
import { ENABLED_IMPORT_CSV_BUILT_IN_CONNECTOR } from './importCsv/importCsv-configuration';
export const builtInConnectorsRuntime = (context, user) => __awaiter(void 0, void 0, void 0, function* () {
    const builtInConnectors = [];
    if (ENABLED_IMPORT_CSV_BUILT_IN_CONNECTOR) {
        const csvConnector = yield importCsvConnectorRuntime(context, user);
        builtInConnectors.push(csvConnector);
    }
    return builtInConnectors;
});
export const builtInConnectors = () => {
    return [importCsvConnector()];
};
export const builtInConnector = (id) => {
    return builtInConnectors().find((c) => c.id === id);
};
