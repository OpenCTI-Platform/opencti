/**
 * Helper to make HTTP GET requests using fetch.
 * @remarks This helper is not seen by coverage tools — use only when needed.
 * @param url
 * @param headers
 */
export const httpGet = async (url: string, headers?: Record<string, string>): Promise<{ statusCode: number; body: string }> => {
  const res = await fetch(url, { headers });
  const body = await res.text();
  return { statusCode: res.status, body };
};

/**
 * Helper to make HTTP POST requests using fetch.
 * @remarks This helper is not seen by coverage tools — use only when needed.
 * @param url
 * @param data
 * @param headers
 */
export const httpPost = async (url: string, data?: Record<string, unknown>, headers?: Record<string, string>): Promise<{ statusCode: number; body: string }> => {
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...headers },
    body: data ? JSON.stringify(data) : undefined,
  });
  const body = await res.text();
  return { statusCode: res.status, body };
};
