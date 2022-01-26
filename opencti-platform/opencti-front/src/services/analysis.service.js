/* eslint-disable */

import { analysisAxios, CancelCallToken } from "../utils/axios";
import { Canceler } from "axios";

export let cancelAllAnalysis;
export let cancelAnalysisProfileData;

const filters = options => {
  const filters = options;

  Object.entries(options).forEach(([key, value]) => {
    if (value === "") {
      delete options[key];
    }
  });
  return filters;
};

const getAnalysisData = (id, option, params, headers) => {
  const bodyParams = params ? filters(params) : "";

  try {
    const response = analysisAxios.get(`vsa/analysis/${id}/${option}`, {
      params: bodyParams,
      headers,
      cancelToken: new CancelCallToken(function executor(c) {
        // An executor function receives a cancel function as a parameter
        cancelAnalysisProfileData = c;
      }),
    });
    return response;
  } catch (error) {
    throw error;
  }
};

export const createNewScanAnalysis = async (id, clientID, formParams) => {
  const headers = {
    "content-type": "application/vnd.dl.vsa.analysis.submission+json;version=1",
    "X-Cyio-Client": clientID,
  };

  try {
    const newScan = analysisAxios.post(`vsa/analysis`, formParams, { headers });
    return await newScan;
  } catch (error) {
    throw error;
  }
};

export const createVulnerabilityAssesmentReport = async (
  id,
  clientID,
  params
) => {
  const headers = {
    "content-type": "application/vnd.dl.vsa.analysis.report+json;version=2",
    "X-Cyio-Client": clientID,
  };

  try {
    const newReport = analysisAxios.post(`/vsa/analysis/${id}/report`, params, {
      headers,
    });
    return await newReport;
  } catch (error) {
    throw error;
  }
};

export const fetchTrendableAnalyses = async (id, clientID) => {
  const headers = {
    Accept: "application/vnd.dl.vsa.trendable.analyses+json;version=1",
    "content-type": "application/vnd.dl.vsa.trendable.analyses+json;version=1",
    "X-Cyio-Client": clientID,
  };
  try {
    const trendableAnalyses = analysisAxios.get(
      `/vsa/analysis/${id}/trendable-analyses`,
      { headers }
    );
    return await trendableAnalyses;
  } catch (error) {
    throw error;
  }
};

export const fetchAllAnalysis = async (clientID, params) => {
  const bodyParams = params ? filters(params) : "";

  try {
    const response = analysisAxios.get("vsa/analysis", {
      params: { ...bodyParams },
      headers: {
        Accept: "application/vnd.dl.vsa.analysis+json;version=1",
        "content-type": "application/vnd.dl.vsa.analysis+json;version=1",
        "X-Cyio-Client": clientID,
      },
      cancelToken: new CancelCallToken(function executor(c) {
        // An executor function receives a cancel function as a parameter
        cancelAllAnalysis = c;
      }),
    });
    return response;
  } catch (error) {
    console.error(error);
  }
};

export const fetchAnalysis = async (id, clientID) => {
  try {
    const response = analysisAxios.get(`vsa/analysis/${id}`, {
      params: { id },
      headers: {
        Accept: "application/vnd.dl.vsa.analysis+json;version=1",
        "content-type": "application/vnd.dl.vsa.analysis+json;version=1",
        "X-Cyio-Client": clientID,
      },
    });
    return await response;
  } catch (error) {
    console.error(error);
  }
};

export const deleteAnalysis = async (id, clientID) => {
  const headers = { "X-Cyio-Client": clientID };
  try {
    const response = analysisAxios.delete(`vsa/analysis/${id}`, { headers });
    return await response;
  } catch (error) {
    throw error;
  }
};

export const exportAnalysisCsv = async (id, clientID) => {
  const headers = {
    "content-type": "application/vnd.dl.vsa.report+json;version=1",
    "X-Cyio-Client": clientID,
  };
  try {
    const response = analysisAxios.post(`vsa/analysis/${id}/export`, null, {
      headers,
    });
    return await response;
  } catch (error) {
    throw error;
  }
};

export const getAnalysisSummary = async (id, clientID) => {
  const headers = {
    Accept: "application/vnd.dl.vsa.analysis.summary+json;version=2",
    "X-Cyio-Client": clientID,
  };
  try {
    const response = analysisAxios.get(`vsa/analysis/${id}/summary`, {
      headers,
    });
    return await response;
  } catch (error) {
    throw error;
  }
};

export const getAnalysisHosts = async (id, clientID, params) => {
  const config = {
    Accept: "application/vnd.dl.vsa.analysis.host+json;version=1",
    "X-Cyio-Client": clientID,
  };
  return getAnalysisData(id, "hosts", params, config);
};

export const getAnalysisWeaknesses = async (id, clientID, params) => {
  const config = {
    Accept: "application/vnd.dl.vsa.analysis.weakness+json;version=1",
    "X-Cyio-Client": clientID,
  };
  return getAnalysisData(id, "weaknesses", params, config);
};

export const getAnalysisVulnerabilities = async (id, clientID, params) => {
  const config = {
    Accept: "application/vnd.dl.vsa.analysis.vulnerability+json;version=1",
    "X-Cyio-Client": clientID,
  };
  return getAnalysisData(id, "vulnerabilities", params, config);
};

export const getAnalysisSoftware = async (id, clientID, params) => {
  const config = {
    Accept: "application/vnd.dl.vsa.analysis.software+json;version=1",
    "X-Cyio-Client": clientID,
  };
  return getAnalysisData(id, "software", params, config);
};

export const getAnalysisFilteredResults = async (id, clientID, params) => {
  const config = {
    Accept: "application/vnd.dl.vsa.filtered-results+json;version=1",
    "X-Cyio-Client": clientID,
  };
  return getAnalysisData(id, "filtered-results", params, config);
};

export const getAnalysisFilteredResultsDetails = async (
  id,
  clientID,
  params
) => {
  const config = {
    Accept: "application/vnd.dl.vsa.filtered-results.details+json;version=1",
    "X-Cyio-Client": clientID,
  };
  return getAnalysisData(id, "filtered-results/details", params, config);
};

export const getAnalysisFilteredResultsWeakness = async (
  id,
  clientID,
  params
) => {
  const config = {
    Accept: "application/vnd.dl.vsa.filtered-results.weaknesses+json;version=1",
    "X-Cyio-Client": clientID,
  };
  return getAnalysisData(id, "filtered-results/weaknesses", params, config);
};

export const getAnalysisFilteredResultsVulnerability = async (
  id,
  clientID,
  params
) => {
  const config = {
    Accept:
      "application/vnd.dl.vsa.filtered-results.vulnerabilities+json;version=2",
    "X-Cyio-Client": clientID,
  };
  return getAnalysisData(
    id,
    "filtered-results/vulnerabilities",
    params,
    config
  );
};

export const getAnalysisStatus = async (id, clientID, params) => {
  const config = { "X-Cyio-Client": clientID };
  return getAnalysisData(id, "status", params, config);
};
