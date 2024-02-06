var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { IMPORT_CSV_CONNECTOR } from './importCsv';
import { errors } from '../../modules/internal/csvMapper/csvMapper-utils';
export const importCsvConnector = () => {
    return IMPORT_CSV_CONNECTOR;
};
export const importCsvConnectorRuntime = (context, user) => __awaiter(void 0, void 0, void 0, function* () {
    const connector = importCsvConnector();
    const configurations = yield connector.connector_schema_runtime_fn(context, user);
    const configurationsFiltered = [];
    yield Promise.all(configurations.map((c) => __awaiter(void 0, void 0, void 0, function* () {
        const mapperErrors = yield errors(context, user, c);
        if (mapperErrors === null) {
            configurationsFiltered.push(c);
        }
    })));
    return (Object.assign(Object.assign({}, connector), { configurations: configurationsFiltered.map((c) => ({
            id: c.id,
            name: c.name,
            configuration: JSON.stringify(c)
        })) }));
});
