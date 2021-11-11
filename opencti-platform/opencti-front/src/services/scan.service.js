/* eslint-disable */
import { scanAxios } from "../utils/axios";
import updateFileName from "../utils/s3FileName";


export const createScan = async (params, clientID, passedConfig) => {
  const bodyParams = {
    path: updateFileName(params.file),
    scan_name: params.scan_name,
    vulnerability_range: params.vulnerabilityRange,
    weakness_range: params.weaknessRange,
    vignette: params.vignette,
    notify: params.notify,
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
    throw error;
  }
};

export const updateScanName = async (id, clientID, params) => {
  try {
    const response = scanAxios.put(`vsa/scans/${id}`, params, {
      headers: {
        "X-Cyio-Client": clientID,
      },
    });
    return await response;
  } catch (error) {
    throw error;
  }
};

export const deleteScan = async (id, clientID) => {
  const headers = { "X-Cyio-Client": clientID };
  try {
    const response = scanAxios.delete(`vsa/scans/${id}`, { headers });
    return await response;
  } catch (error) {
    throw error;
  }
};

/* MOVED preSignS3 TO NewVulnerabilityScan Modal due to need of Client ID

export const preSignS3 = async(file: any, callback: any) => {
  const headers = {
    "Accept": "application/vnd.dl.s3.surl.response+json;version=1",
    "Content-Type": "application/vnd.dl.s3.surl.request+json;version=1"
  };
  const bodyParams = {
    file_name: file.name,
    resource_type: 'nessus',
    file_type: file.type
  };
  try {
    scanAxios.post('/s3/presign', bodyParams, { headers }).then(results => {
      callback(results.data);
    })
    .catch(error => {
      console.error(error);
    });
  } catch (error) {
    throw(error);
  }
}
*/

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
    throw error;
  }
};
