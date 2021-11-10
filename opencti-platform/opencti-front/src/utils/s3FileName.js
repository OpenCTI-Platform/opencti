const updateFileName = (filename) => {
  const updatedFileName = filename.replace(/[^\w\d_\-.]+/gi, '_');
  return updatedFileName;
};

export { updateFileName as default };
