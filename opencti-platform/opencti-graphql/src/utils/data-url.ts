export const parseDataUrl = (dataUrl: string) => {
  const defaultValue = {
    mimeType: '',
    base64Encoded: false,
    data: '',
  };

  if (!dataUrl.startsWith('data:')) {
    return defaultValue;
  }

  const metadataAndData = dataUrl.slice(5);
  const separatorIndex = metadataAndData.indexOf(',');
  if (separatorIndex < 0) {
    return defaultValue;
  }

  const metadata = metadataAndData.slice(0, separatorIndex);
  const data = metadataAndData.slice(separatorIndex + 1);
  const metadataParts = metadata
    .split(';')
    .map((part) => part.trim())
    .filter((part) => part.length > 0);

  const mimeType = metadataParts[0]?.includes('/') ? metadataParts[0].toLowerCase() : '';
  const base64Encoded = metadataParts.some((part) => part.toLowerCase() === 'base64');
  return {
    mimeType,
    base64Encoded,
    data,
  };
};
