import { describe, expect, it } from 'vitest';
import { API_URI, generateBasicAuth, USER_EDITOR } from '../../utils/testQuery';
import { basePath } from '../../../src/config/conf';

const get = (route: string, file: string, authorization: string) => fetch(`${API_URI}${basePath}/storage/${route}/${file}`, {
  headers: { authorization },
});

describe('Storage routes: file not found or restricted', () => {
  it.each(['get', 'view', 'html', 'encrypted'])('/storage/%s answers 404 for a file that does not exist', async (route) => {
    const res = await get(route, 'import/global/does-not-exist.pdf', generateBasicAuth());
    expect(res.status).toBe(404);
    expect(((await res.json()) as { error: string }).error).toBe('File not found or restricted');
  });

  it('answers the same 404 for a restricted path as for a missing one', async () => {
    const editor = generateBasicAuth(USER_EDITOR.email, USER_EDITOR.password);
    const res = await get('get', 'support/does-not-exist.zip', editor);
    expect(res.status).toBe(404);
    expect(((await res.json()) as { error: string }).error).toBe('File not found or restricted');
  });
});
