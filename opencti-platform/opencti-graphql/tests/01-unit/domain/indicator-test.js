import { extractObservablesFromIndicatorPattern } from '../../../src/utils/syntax';
import * as C from '../../../src/schema/stixCyberObservable';

test('should observables correctly extracted', async () => {
  // simpleHash
  const simpleHash = extractObservablesFromIndicatorPattern("[file:hashes.'SHA-256' = '4bac27393bdd9777ce02453256c5577cd02275510b2227f473d03f533924f877']");
  expect(simpleHash.length).toEqual(1);
  expect(simpleHash[0].type).toEqual(C.ENTITY_HASHED_OBSERVABLE_STIX_FILE);
  expect(simpleHash[0].hashes['SHA-256']).toEqual('4bac27393bdd9777ce02453256c5577cd02275510b2227f473d03f533924f877');
  // multipleHashes
  const multipleHashes = extractObservablesFromIndicatorPattern("[file:hashes.'SHA-256' = 'bf07a7fbb825fc0aae7bf4a1177b2b31fcf8a3feeaf7092761e18c859ee52a9c' OR file:hashes.MD5 = 'cead3f77f6cda6ec00f57d76c9a6879f']");
  expect(multipleHashes.length).toEqual(2);
  expect(multipleHashes[0].type).toEqual(C.ENTITY_HASHED_OBSERVABLE_STIX_FILE);
  expect(multipleHashes[0].hashes['SHA-256']).toEqual('bf07a7fbb825fc0aae7bf4a1177b2b31fcf8a3feeaf7092761e18c859ee52a9c');
  expect(multipleHashes[1].type).toEqual(C.ENTITY_HASHED_OBSERVABLE_STIX_FILE);
  expect(multipleHashes[1].hashes.MD5).toEqual('cead3f77f6cda6ec00f57d76c9a6879f');
  // simpleipv4
  const simpleipv4 = extractObservablesFromIndicatorPattern("[ipv4-addr:value = '183.89.215.254']");
  expect(simpleipv4.length).toEqual(1);
  expect(simpleipv4[0].type).toEqual(C.ENTITY_IPV4_ADDR);
  expect(simpleipv4[0].value).toEqual('183.89.215.254');
  // domainAndIp
  const domainAndIp = extractObservablesFromIndicatorPattern("[domain-name:value = '5z8.info' AND domain-name:resolves_to_refs[*].value = '198.51.100.1']");
  expect(domainAndIp.length).toEqual(1);
  expect(domainAndIp[0].type).toEqual(C.ENTITY_DOMAIN_NAME);
  expect(domainAndIp[0].value).toEqual('5z8.info');
  // domainAndHostname
  const domainAndHostname = extractObservablesFromIndicatorPattern("[domain-name:value = '5z8.info' OR domain-name:value = 'www.5z8.info']");
  expect(domainAndHostname.length).toEqual(2);
  expect(domainAndHostname[0].type).toEqual(C.ENTITY_DOMAIN_NAME);
  expect(domainAndHostname[0].value).toEqual('5z8.info');
  expect(domainAndHostname[1].type).toEqual(C.ENTITY_DOMAIN_NAME);
  expect(domainAndHostname[1].value).toEqual('www.5z8.info');
  // simpleEmailAddress
  const simpleEmailAddress = extractObservablesFromIndicatorPattern("[email-message:sender_ref.value = 'jdoe@example.com' AND email-message:subject = 'Conference Info']");
  expect(simpleEmailAddress.length).toEqual(1);
  expect(simpleEmailAddress[0].type).toEqual(C.ENTITY_EMAIL_MESSAGE);
  expect(simpleEmailAddress[0].subject).toEqual('Conference Info');
  // simpleUrl
  const simpleUrl = extractObservablesFromIndicatorPattern("[url:value = 'http://localhost.com']");
  expect(simpleUrl.length).toEqual(1);
  expect(simpleUrl[0].type).toEqual(C.ENTITY_URL);
  expect(simpleUrl[0].value).toEqual('http://localhost.com');
  // Unknown type
  const unknown = extractObservablesFromIndicatorPattern("[x-company-type:value = 'http://localhost.com']");
  expect(unknown.length).toEqual(0);
});
