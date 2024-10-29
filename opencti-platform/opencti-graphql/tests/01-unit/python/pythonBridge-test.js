import { expect, it } from 'vitest';
import { checkIndicatorSyntax, checkPythonAvailability, createStixPattern, execChildPython } from '../../../src/python/pythonBridge';
import { ADMIN_USER, testContext } from '../../utils/testQuery';

it('Check if python is well configured', async () => {
  const check = await checkPythonAvailability(testContext, ADMIN_USER);
  expect(check).not.toBeNull();
  expect(check).toEqual("[text:value = 'test']");
  // noinspection ES6MissingAwait
  expect(execChildPython(testContext, ADMIN_USER, '/missing')).rejects.toThrow('Cannot execute Python with empty script path or name');
  // noinspection ES6MissingAwait
  expect(createStixPattern(testContext, ADMIN_USER, 'fail')).resolves.toEqual(null);
});

it('Check createStixPattern bad pattern', async () => {
  let check = await createStixPattern(testContext, ADMIN_USER, 'TYPE', 'VALUE');
  expect(check).toBeNull();
  check = await createStixPattern(testContext, ADMIN_USER, 'File_shaa256', 'c2d6908fe0d2ad04713');
  expect(check).toBeNull();
  check = await createStixPattern(testContext, ADMIN_USER, 'File_MD5__File_sha256', 'c2d6908fe0d2ad04713__c2d6908fe0d2ad04713');
  expect(check).toBeNull();
});

it('Check createStixPattern hash', async () => {
  const check = await createStixPattern(
    testContext,
    ADMIN_USER,
    'File_sha256',
    'e9b45212395f4c2d6908fe0d2ad04713fae3dee8aaacfd52b3f89de7fdb54b88'
  );
  expect(check).toEqual("[file:hashes.'SHA-256' = 'e9b45212395f4c2d6908fe0d2ad04713fae3dee8aaacfd52b3f89de7fdb54b88']");
});

it('Check stix indicator syntax', async () => {
  const check = await checkIndicatorSyntax(testContext, ADMIN_USER, 'stix', '[ipv4-addr:value = \'195.206.105.217\']');
  expect(check).toEqual(true);
});

it('Check stix indicator bad pattern', async () => {
  const check = await checkIndicatorSyntax(testContext, ADMIN_USER, 'stix', '5.206.105.217');
  expect(check).toEqual(false);
});

it('Check yara indicator syntax', async () => {
  const correctYaraPattern = `rule CrowdStrike_CSA_240859_02 : av_eliminator 
{
    meta:
        copyright = "(c) 2024 CrowdStrike Inc."
        description = "AvEliminator log strings and constants"
        reports = "CSA-240859"
        version = "202407260716"
        last_modified = "2024-07-26"
        malware_family = "AvEliminator"
    strings:
        $pdb = "A:\\\\Current\\\\AvEleminator\\\\Bin\\\\AVEleminatorDrv.pdb"
        $driver = "\\\\Driver\\\\mselemx" wide
        $log1 = "+++++++++++++++++T E S T++++++++++++++++++"
        $log2 = "[%s] System range start is %p, code mapped at %p\\r\\n"
        $log3 = "[%s] Current Process : %lu (%p) Current Thread : %lu (%p)\\r\\n"
        $log4 = "[%s] KeGetCurrentIrql=%s\\r\\n"
        $log5 = "ObRegisterCallbacks() failed! status: %i"
        $log6 = "Disable_protection"
    condition:
        uint16(0) == 0x5a4d and
        (3 of ($log*) or $pdb or $driver)
}`;
  const check = await checkIndicatorSyntax(testContext, ADMIN_USER, 'yara', correctYaraPattern);
  expect(check).toEqual(true);
});

it('Check yara indicator bad pattern', async () => {
  const check = await checkIndicatorSyntax(testContext, ADMIN_USER, 'yara', 'rule aa');
  expect(check).toEqual(false);
});
