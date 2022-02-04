/* eslint-disable */

import { apiAxios, accountAxios } from "../utils/axios";
import {toastAxiosError} from "../utils/bakedToast";

export const getAccount = async () => {
  try {
    const response = accountAxios.get(`cyio/account`, {
      headers: {
        Accept: "application/vnd.dl.cyio.account+json;version=1",
        "content-type": "application/vnd.dl.cyio.account+json;version=1",
      },
    });
    return await response;
  } catch (error) {
    toastAxiosError("Fetch Account Error")
    throw error;
  }
};

export const getInformationPageData = (clientID) => {
  try {
    const headers = {
      Accept: "application/vnd.dl.vsa.contextual.counts+json;version=1",
      "Content-Type": "application/vnd.dl.vsa.contextual.counts+json;version=1",
      "X-Cyio-Client": clientID,
    };
    const response = apiAxios.get(`/vsa/contextual-counts`, { headers });
    return response;
  } catch (error) {
    toastAxiosError()
    throw error;
  }
};

export const getCVEProductList = (cve_id, clientID) => {
  try {
    const headers = {
      Accept: "application/vnd.dl.vsa.contextual.cpe+json;version=1",
      "Content-Type": "application/vnd.dl.vsa.contextual.cpe+json;version=1",
      "X-Cyio-Client": clientID,
    };
    const response = apiAxios.get(`/vsa/cpe-list/${cve_id}`, { headers });
    return response;
  } catch (error) {
    toastAxiosError()
    throw error;
  }
};

export const getTrendingChartData = (clientID, analysis_ids) => {
  try {
    const headers = {
      Accept: "application/vnd.dl.vsa.chart.trending+json;version=1",
      "content-type": "application/vnd.dl.vsa.chart.trending+json;version=1",
      "X-Cyio-Client": clientID,
    };
    const response = apiAxios.get(`/vsa/charts/trending`, {
      headers,
      params: { analysis_ids },
      data: null,
    });
    return response;
  } catch (error) {
    toastAxiosError("Fetch Trending Data Error")
    throw error;
  }
};

export const getCVESeverityChartData = (clientID, analysis_ids) => {
  try {
    const headers = {
      Accept: "application/vnd.dl.vsa.chart.cve.severity+json;version=1",
      "content-type":
        "application/vnd.dl.vsa.chart.cve.severity+json;version=1",
      "X-Cyio-Client": clientID,
    };
    const response = apiAxios.get(`/vsa/charts/cve-severity`, {
      headers,
      params: { analysis_ids },
      data: null,
    });
    return response;
  } catch (error) {
    toastAxiosError()
    throw error;
  }
};

export const getSeverityPieChartData = (clientID, analysis_ids) => {
  try {
    const headers = {
      Accept: "application/vnd.vsa.chart.cve.severity.count+json;version=1",
      "content-type":
        "application/vnd.vsa.chart.cve.severity.count+json;version=1",
      "X-Cyio-Client": clientID,
    };
    const response = apiAxios.get(`/vsa/charts/cve-counts-severity`, {
      headers,
      params: { analysis_ids },
      data: null,
      scoring: 'tbc',
    });
    return response;
  } catch (error) {
    toastAxiosError()
    throw error;
  }
};

export const getTopVulnerableHostsChartData = (
  clientID,
  analysis_ids,
  top = 10
) => {
  try {
    const headers = {
      Accept: "application/vnd.vsa.chart.top.vulnerable.host+json;version=1",
      "content-type":
        "application/vnd.vsa.chart.top.vulnerable.host+json;version=1",
      "X-Cyio-Client": clientID,
    };
    const response = apiAxios.get(`/vsa/charts/top-vulnerable-hosts`, {
      headers,
      params: {
        analysis_ids,
        top,
      },
      data: null,
    });
    return response;
  } catch (error) {
    toastAxiosError()
    throw error;
  }
};

export const getTopVulnerableProductsChartData = (
  clientID,
  analysis_ids,
  top = 10
) => {
  try {
    const headers = {
      Accept:
        "application/vnd.vsa.chart.top.vulnerable.products+json;version=1",
      "content-type":
        "application/vnd.vsa.chart.top.vulnerable.products+json;version=1",
      "X-Cyio-Client": clientID,
    };
    const response = apiAxios.get(`/vsa/charts/top-vulnerable-products`, {
      headers,
      params: {
        analysis_ids,
        top,
      },
      data: null,
    });
    return response;
  } catch (error) {
    toastAxiosError()
    throw error;
  }
};

export const getSeverityByWeaknessChartData = (clientID, analysis_ids) => {
  try {
    const headers = {
      Accept: "application/vnd.vsa.chart.cve.severity.weakness+json;version=2",
      "content-type":
        "application/vnd.vsa.chart.cve.severity.weakness+json;version=2",
      "X-Cyio-Client": clientID,
    };
    const response = apiAxios.get(`/vsa/charts/cve-severity-weakness`, {
      headers,
      params: {
        analysis_ids,
      },
      data: null,
    });
    return response;
  } catch (error) {
    toastAxiosError()
    throw error;
  }
};
