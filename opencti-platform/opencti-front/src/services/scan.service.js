/* eslint-disable */
import { scanAxios } from "../utils/axios";
import updateFileName from "../utils/s3FileName";
import {toastAxiosError} from "../utils/bakedToast";

export const createScan = async (params, clientID, passedConfig) => {
  const bodyParams = {
    path: updateFileName(params.fileId || params.file), // compatability for new file id over file name
    scan_name: params.scan_name,
    vulnerability_range: params.vulnerabilityRange,
    weakness_range: params.weaknessRange,
    vignette: params.vignette,
    notify: params.notify,
    implementation_point: params.implementationPoint,
  };

  const config = {
    headers: {
      "content-type": "application/vnd.dl.vsa.scan.submit+json;version=2",
      "X-Cyio-Client": clientID,
    },
    ...passedConfig,
  };

  try {
    const newScan = scanAxios.post("vsa/scans", bodyParams, config);
    return await newScan;
  } catch (error) {
    toastAxiosError("Scan Create Error")
    throw error;
  }
};

export const fetchAllScans = async (clientID, params) => {
  const bodyParams = params ? filters(params) : "";

  try {
    const response = scanAxios.get("vsa/scans", {
      ...bodyParams,
      headers: {
        Accept: "application/vnd.dl.vsa.scan+json;version=3",
        "Content-Type": "application/vnd.dl.vsa.scan+json;version=3",
        "X-Cyio-Client": clientID,
      },
    });
    return await response;
  } catch (error) {
    toastAxiosError("Fetch Scans Error")
    throw error;
  }
};

export const fetchScan = async (id, clientID) => {
  try {
    const response = scanAxios.get(`vsa/scans/${id}`, {
      headers: {
        Accept: "application/vnd.dl.vsa.scan+json;version=3",
        "content-type": "application/vnd.dl.vsa.scan+json;version=3",
        "X-Cyio-Client": clientID,
      },
    });
    return await response;
  } catch (error) {
    toastAxiosError("Fetch Scan Error")
    throw error;
  }
};

export const updateScan = async (id, clientID, params) => {
  try {
    const response = scanAxios.patch(`vsa/scans/${id}`, params, {
      headers: {
        "X-Cyio-Client": clientID,
        "Content-Type": "application/vnd.dl.vsa.scan+json;version=3"
      },
    });
    return await response;
  } catch (error) {
    toastAxiosError("Update Scan Error")
    throw error;
  }
};

export const deleteScan = async (id, clientID) => {
  const headers = { "X-Cyio-Client": clientID };
  try {
    const response = scanAxios.delete(`vsa/scans/${id}`, { headers });
    return await response;
  } catch (error) {
    toastAxiosError("Scan Delete Error")
    throw error;
  }
};

export const fetchVignettes = async (clientID) => {
  try {
    const headers = {
      Accept: "application/vnd.dl.vsa.vignette+json;version=1",
      "Content-Type": "application/vnd.dl.vsa.vignette+json;version=1",
      "X-Cyio-Client": clientID,
    };
    const response = scanAxios.get(`vsa/vignette`, { headers });
    return await response;
  } catch (error) {
    toastAxiosError("Fetch Vignettes Error")
    throw error;
  }
};
