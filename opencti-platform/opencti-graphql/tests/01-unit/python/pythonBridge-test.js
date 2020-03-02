import { head } from 'ramda';
import { checkPythonStix2, createStixPattern, execPython3, extractObservables } from '../../../src/python/pythonBridge';

test('Check if python is well configured', async () => {
  const check = await checkPythonStix2();
  expect(check).not.toBeNull();
  expect(check.status).toEqual('success');
  // noinspection ES6MissingAwait
  expect(execPython3('/missing')).rejects.toThrow(undefined);
  // noinspection ES6MissingAwait
  expect(createStixPattern('fail')).resolves.toEqual(null);
  // noinspection ES6MissingAwait
  expect(extractObservables('fail')).resolves.toEqual(null);
});

test('Check extractObservables bad pattern', async () => {
  const check = await extractObservables('bad pattern');
  expect(check).toBeNull();
});

test('Check domain pattern', async () => {
  const check = await extractObservables("[domain-name:value = 'smbc.jp-bankq.com']");
  expect(check).not.toBeNull();
  expect(check.length).toEqual(1);
  expect(head(check).type).toEqual('Domain');
  expect(head(check).value).toEqual('smbc.jp-bankq.com');
});

test('Check hash pattern', async () => {
  const check = await extractObservables(
    "[file:hashes.SHA256 = 'e9b45212395f4c2d6908fe0d2ad04713fae3dee8aaacfd52b3f89de7fdb54b88']"
  );
  expect(check).not.toBeNull();
  expect(check.length).toEqual(1);
  expect(head(check).type).toEqual('File-SHA256');
  expect(head(check).value).toEqual('e9b45212395f4c2d6908fe0d2ad04713fae3dee8aaacfd52b3f89de7fdb54b88');
});

test('Check createStixPattern bad pattern', async () => {
  let check = await createStixPattern('TYPE', 'VALUE');
  expect(check).toBeNull();
  check = await createStixPattern('file-Sha256', 'c2d6908fe0d2ad04713');
  expect(check).toBeNull();
});

test('Check createStixPattern hash', async () => {
  const check = await createStixPattern(
    'file-sha256',
    'e9b45212395f4c2d6908fe0d2ad04713fae3dee8aaacfd52b3f89de7fdb54b88'
  );
  expect(check).toEqual("[file:hashes.SHA256 = 'e9b45212395f4c2d6908fe0d2ad04713fae3dee8aaacfd52b3f89de7fdb54b88']");
});
