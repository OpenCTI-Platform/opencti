import { checkPythonStix2, createStixPattern, execPython3 } from '../../../src/python/pythonBridge';

test('Check if python is well configured', async () => {
  const check = await checkPythonStix2();
  expect(check).not.toBeNull();
  expect(check.status).toEqual('success');
  // noinspection ES6MissingAwait
  expect(execPython3('/missing')).rejects.toThrow(undefined);
  // noinspection ES6MissingAwait
  expect(createStixPattern('fail')).resolves.toEqual(null);
});

test('Check createStixPattern bad pattern', async () => {
  let check = await createStixPattern('TYPE', 'VALUE');
  expect(check).toBeNull();
  check = await createStixPattern('File_shaa256', 'c2d6908fe0d2ad04713');
  expect(check).toBeNull();
});

test('Check createStixPattern hash', async () => {
  const check = await createStixPattern(
    'File_sha256',
    'e9b45212395f4c2d6908fe0d2ad04713fae3dee8aaacfd52b3f89de7fdb54b88'
  );
  expect(check).toEqual("[file:hashes.'SHA-256' = 'e9b45212395f4c2d6908fe0d2ad04713fae3dee8aaacfd52b3f89de7fdb54b88']");
});
