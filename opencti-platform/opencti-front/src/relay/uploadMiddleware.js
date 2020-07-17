/* eslint-disable */
import { extractFiles } from "extract-files";

const uploadMiddleware = () => (next) => async (req) => {
  const operations = {
    query: req.operation.text,
    variables: req.variables,
  };
  const { clone: extractedOperations, files } = extractFiles(operations);
  if (files.size) {
    const formData = new FormData();
    formData.append("operations", JSON.stringify(extractedOperations));
    const pathMap = {};
    let i = 0;
    files.forEach((paths) => {
      pathMap[++i] = paths;
    });
    formData.append("map", JSON.stringify(pathMap));

    i = 0;
    files.forEach((paths, file) => {
      formData.append(++i, file, file.name);
    });
    req.fetchOpts.method = "POST";
    req.fetchOpts.body = formData;
  }
  return next(req);
};

export default uploadMiddleware;
