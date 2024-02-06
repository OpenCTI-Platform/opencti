import https from 'node:https';
import axios, {} from 'axios';
import { getPlatformHttpProxies } from '../config/conf';
import { fromBase64, isNotEmptyField } from '../database/utils';
export const getHttpClient = ({ baseURL, headers, rejectUnauthorized, responseType, certificates, auth }) => {
    var _a, _b, _c;
    const proxies = getPlatformHttpProxies();
    const cert = isNotEmptyField(certificates === null || certificates === void 0 ? void 0 : certificates.cert) ? fromBase64(certificates === null || certificates === void 0 ? void 0 : certificates.cert) : undefined;
    const key = isNotEmptyField(certificates === null || certificates === void 0 ? void 0 : certificates.key) ? fromBase64(certificates === null || certificates === void 0 ? void 0 : certificates.key) : undefined;
    const ca = isNotEmptyField(certificates === null || certificates === void 0 ? void 0 : certificates.ca) ? fromBase64(certificates === null || certificates === void 0 ? void 0 : certificates.ca) : undefined;
    const defaultHttpsAgent = new https.Agent({ rejectUnauthorized: rejectUnauthorized === true, cert, key, ca });
    return axios.create({
        baseURL,
        responseType,
        headers,
        auth,
        withCredentials: true,
        httpAgent: (_a = proxies['http:']) === null || _a === void 0 ? void 0 : _a.build(),
        httpsAgent: (_c = (_b = proxies['https:']) === null || _b === void 0 ? void 0 : _b.build()) !== null && _c !== void 0 ? _c : defaultHttpsAgent,
        proxy: false // Disable direct proxy protocol in axios http adapter
    });
};
