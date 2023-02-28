/* eslint-disable no-param-reassign */
import axios from 'axios';

const API_URL = process.env.REACT_APP_API_URL || '';

const BearerToken = () => {
  const accessToken = localStorage.getItem('token');
  return `Bearer ${accessToken}`;
};

const headers = {
  Action: 'application/json',
  'Content-Type': 'application/json',
};

export const scanAxios = axios.create({
  baseURL: API_URL,
  headers: {
    ...headers,
  },
});

scanAxios.interceptors.request.use((config) => {
  const bearer = BearerToken();
  config.headers.Authorization = bearer;
  return config;
});

const analysisAccept = 'application/vnd.dl.vsa.analysis+json;version=1';
export const analysisAxios = axios.create({
  baseURL: API_URL,
  headers: {
    Accept: analysisAccept,
    ...headers,
  },
});

analysisAxios.interceptors.request.use((config) => {
  const bearer = BearerToken();
  config.headers.Authorization = bearer;
  return config;
});

const apiAccept = 'application/vnd.dl.vsa+json;version=1';
export const apiAxios = axios.create({
  baseURL: API_URL,
  headers: {
    Accept: apiAccept,
    ...headers,
  },
});

apiAxios.interceptors.request.use((config) => {
  const bearer = BearerToken();
  config.headers.Authorization = bearer;
  return config;
});

const accountAccept = 'application/vnd.dl.cyio.account+json;version=1';
export const accountAxios = axios.create({
  baseURL: API_URL,
  headers: {
    ...headers,
    Accept: accountAccept,
  },
});

accountAxios.interceptors.request.use((config) => {
  const bearer = BearerToken();
  config.headers.Authorization = bearer;
  return config;
});

const organizationAccept = 'application/vnd.dl.cyio.organization.settings+json;version=1';
export const organizationAxios = axios.create({
  baseURL: API_URL,
  headers: {
    ...headers,
    Accept: organizationAccept,
  },
});

organizationAxios.interceptors.request.use((config) => {
  const bearer = BearerToken();
  config.headers.Authorization = bearer;
  return config;
});

export const { isCancel } = axios;
export const CancelCallToken = axios.CancelToken;
