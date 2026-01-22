import { describe, expect, it } from 'vitest';
import { cleanupIndicatorPattern, extractObservablesFromIndicatorPattern, STIX_PATTERN_TYPE, validateObservableGeneration } from '../../../src/utils/syntax';
import * as C from '../../../src/schema/stixCyberObservable';
import { computeValidPeriod, computeValidTTL, DEFAULT_INDICATOR_TTL } from '../../../src/modules/indicator/indicator-utils';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import { MARKING_TLP_AMBER, MARKING_TLP_GREEN, MARKING_TLP_RED } from '../../../src/schema/identifier';
import { FALLBACK_DECAY_RULE } from '../../../src/modules/decayRule/decayRule-domain';

const DEFAULT_PARAM = { name: 'indicator', pattern_type: 'stix', pattern: 'undefined' };

describe('indicator utils', () => {
  it('should observables correctly extracted', async () => {
    // simpleHash
    const simpleHash = extractObservablesFromIndicatorPattern('[file:hashes.\'SHA-256\' = \'4bac27393bdd9777ce02453256c5577cd02275510b2227f473d03f533924f877\']');
    expect(simpleHash.length).toEqual(1);
    expect(simpleHash[0].type).toEqual(C.ENTITY_HASHED_OBSERVABLE_STIX_FILE);
    expect(simpleHash[0].hashes['SHA-256']).toEqual('4bac27393bdd9777ce02453256c5577cd02275510b2227f473d03f533924f877');
    // multipleHashes
    const multipleHashes = extractObservablesFromIndicatorPattern('[file:hashes.\'SHA-256\' = \'bf07a7fbb825fc0aae7bf4a1177b2b31fcf8a3feeaf7092761e18c859ee52a9c\' OR file:hashes.MD5 = \'cead3f77f6cda6ec00f57d76c9a6879f\']');
    expect(multipleHashes.length).toEqual(2);
    expect(multipleHashes[0].type).toEqual(C.ENTITY_HASHED_OBSERVABLE_STIX_FILE);
    expect(multipleHashes[0].hashes['SHA-256']).toEqual('bf07a7fbb825fc0aae7bf4a1177b2b31fcf8a3feeaf7092761e18c859ee52a9c');
    expect(multipleHashes[1].type).toEqual(C.ENTITY_HASHED_OBSERVABLE_STIX_FILE);
    expect(multipleHashes[1].hashes.MD5).toEqual('cead3f77f6cda6ec00f57d76c9a6879f');
    // simpleipv4
    const simpleipv4 = extractObservablesFromIndicatorPattern('[ipv4-addr:value = \'183.89.215.254\']');
    expect(simpleipv4.length).toEqual(1);
    expect(simpleipv4[0].type).toEqual(C.ENTITY_IPV4_ADDR);
    expect(simpleipv4[0].value).toEqual('183.89.215.254');
    // domainAndIp
    const domainAndIp = extractObservablesFromIndicatorPattern('[domain-name:value = \'5z8.info\' AND domain-name:resolves_to_refs[*].value = \'198.51.100.1\']');
    expect(domainAndIp.length).toEqual(1);
    expect(domainAndIp[0].type).toEqual(C.ENTITY_DOMAIN_NAME);
    expect(domainAndIp[0].value).toEqual('5z8.info');
    // domainAndHostname
    const domainAndHostname = extractObservablesFromIndicatorPattern('[domain-name:value = \'5z8.info\' OR domain-name:value = \'www.5z8.info\']');
    expect(domainAndHostname.length).toEqual(2);
    expect(domainAndHostname[0].type).toEqual(C.ENTITY_DOMAIN_NAME);
    expect(domainAndHostname[0].value).toEqual('5z8.info');
    expect(domainAndHostname[1].type).toEqual(C.ENTITY_DOMAIN_NAME);
    expect(domainAndHostname[1].value).toEqual('www.5z8.info');
    // simpleEmailAddress
    const simpleEmailMessage = extractObservablesFromIndicatorPattern('[email-message:sender_ref.value = \'jdoe@example.com\' AND email-message:subject = \'Conference Info\']');
    expect(simpleEmailMessage.length).toEqual(1);
    expect(simpleEmailMessage[0].type).toEqual(C.ENTITY_EMAIL_MESSAGE);
    expect(simpleEmailMessage[0].subject).toEqual('Conference Info'); // we only extract the subject, without the sender_ref
    // simpleUrl
    const simpleUrl = extractObservablesFromIndicatorPattern('[url:value = \'http://localhost.com\']');
    expect(simpleUrl.length).toEqual(1);
    expect(simpleUrl[0].type).toEqual(C.ENTITY_URL);
    expect(simpleUrl[0].value).toEqual('http://localhost.com');
    // network traffic
    const networkTrafficPort = extractObservablesFromIndicatorPattern('[network-traffic:dst_ref.value = \'127.0.0.1\' AND network-traffic:dst_port = 443]');
    expect(networkTrafficPort.length).toEqual(1);
    expect(networkTrafficPort[0].type).toEqual(C.ENTITY_NETWORK_TRAFFIC);
    expect(networkTrafficPort[0].dst_port).toEqual('443'); // we only extract dst_port, not dst_ref

    const networkTrafficIP = extractObservablesFromIndicatorPattern('[network-traffic:dst_ref.type = \'ipv4-addr\' AND network-traffic:dst_ref.value = \'203.0.113.33/32\']');
    expect(networkTrafficIP.length).toEqual(0); // we don't know how to extract dst_ref for now
    // Unknown type
    const unknown = extractObservablesFromIndicatorPattern('[x-company-type:value = \'http://localhost.com\']');
    expect(unknown.length).toEqual(0);
  });
  it('should validate observables extracted before creation', async () => {
    const networkTrafficWithDstRef = validateObservableGeneration(C.ENTITY_NETWORK_TRAFFIC, "[network-traffic:dst_ref.type = 'ipv4-addr' AND network-traffic:dst_ref.value = '203.0.113.33/32']");
    expect(networkTrafficWithDstRef).toBeFalsy();
    const networkTrafficWithDstRefAndPort = validateObservableGeneration(C.ENTITY_NETWORK_TRAFFIC, "[network-traffic:dst_ref.value = '127.0.0.1' AND network-traffic:dst_port = 443]");
    expect(networkTrafficWithDstRefAndPort).toBeFalsy();
    const emailMessageWithFromRef = validateObservableGeneration(C.ENTITY_EMAIL_MESSAGE, "[email-message:sender_ref.value = 'jdoe@example.com' AND email-message:subject = 'Bad subject'");
    expect(emailMessageWithFromRef).toBeFalsy();
    const emailMessageSubject = validateObservableGeneration(C.ENTITY_EMAIL_MESSAGE, "[email-message:subject = 'Bad subject']");
    expect(emailMessageSubject).toBeTruthy();
  });
  it('should indicator cleaned', async () => {
    const testIndicatorPattern = (from: string, expectation: string) => {
      const formattedPattern = cleanupIndicatorPattern(STIX_PATTERN_TYPE, from);
      expect(formattedPattern).toBe(expectation);
    };
    testIndicatorPattern(
      '[ipv4-addr:value   =   \'198.51.100.1/32\']',
      '[ipv4-addr:value = \'198.51.100.1/32\']'
    );
    testIndicatorPattern(
      ' [   file:extensions.\'windows-pebinary-ext\'.sections[*].entropy   > 7.0    ]  ',
      '[file:extensions.\'windows-pebinary-ext\'.sections[*].entropy > 7.0]'
    );
    testIndicatorPattern(
      '[    network-traffic:dst_ref.value = \'phones-luxury   at.ply.gg\' AND     network-traffic:dst_port    =     12864     ]',
      '[network-traffic:dst_ref.value = \'phones-luxury   at.ply.gg\' AND network-traffic:dst_port = 12864]'
    );
    testIndicatorPattern(
      '[ network-traffic:src_ref.value = \'203.0.113.10\' AND network-traffic:dst_ref.value = \'198.51.100.58\' ]',
      '[network-traffic:src_ref.value = \'203.0.113.10\' AND network-traffic:dst_ref.value = \'198.51.100.58\']'
    );
    testIndicatorPattern(
      '([ipv4-addr:value = \'198.51.100.1/32\' OR ipv4-addr:value = \'203.0.113.33/32\' OR ipv6-addr:value = \'2001:0db8:dead:beef:dead:beef:dead:0001/128\'] FOLLOWEDBY [domain-name:value = \'example.com\']) WITHIN   600    SECONDS   ',
      '([ipv4-addr:value = \'198.51.100.1/32\' OR ipv4-addr:value = \'203.0.113.33/32\' OR ipv6-addr:value = \'2001:0db8:dead:beef:dead:beef:dead:0001/128\'] FOLLOWEDBY [domain-name:value = \'example.com\']) WITHIN 600 SECONDS'
    );
    testIndicatorPattern(
      '[file:hashes.MD5 = \'8b510662d51cbf365f5de1666eeb7f65\' OR file:hashes.\'SHA-1\' = \'be496dec5b552d81b8ff30572bb0ff4f65dd6e29\' OR file:hashes.\'SHA-256\' = \'1263998c8c9571df6994c790f9de03d14bef16820171950d58d1071f89093b8c\']',
      '[file:hashes.MD5 = \'8b510662d51cbf365f5de1666eeb7f65\' OR file:hashes.\'SHA-1\' = \'be496dec5b552d81b8ff30572bb0ff4f65dd6e29\' OR file:hashes.\'SHA-256\' = \'1263998c8c9571df6994c790f9de03d14bef16820171950d58d1071f89093b8c\']'
    );
  });
  it('should valid_from default', async () => {
    const { validFrom } = await computeValidPeriod({ ...DEFAULT_PARAM }, FALLBACK_DECAY_RULE.decay_lifetime);
    expect(validFrom).toBeDefined();
  });
  it('should valid_from created', async () => {
    const { validFrom, validUntil } = await computeValidPeriod({
      ...DEFAULT_PARAM,
      created: '2023-01-21T17:57:09.266Z'
    }, FALLBACK_DECAY_RULE.decay_lifetime);
    expect(validFrom.toISOString()).toBe('2023-01-21T17:57:09.266Z');
    expect(validUntil.toISOString()).toBe('2024-05-05T17:57:09.266Z');
  });
  it('should valid_from and revoked', async () => {
    const { validFrom, validUntil, revoked } = await computeValidPeriod({
      ...DEFAULT_PARAM,
      revoked: true,
      created: '2023-01-21T17:57:09.266Z'
    }, FALLBACK_DECAY_RULE.decay_lifetime);
    expect(revoked).toBe(true);
    expect(validFrom.toISOString()).toBe('2023-01-21T17:57:09.266Z');
    expect(validUntil.toISOString()).toBe('2023-01-21T17:57:10.266Z');
  });
  it('should valid_from itself', async () => {
    const { validFrom, validUntil } = await computeValidPeriod({
      ...DEFAULT_PARAM,
      valid_from: '2023-02-21T17:57:09.266Z',
      created: '2023-01-21T17:57:09.266Z'
    }, FALLBACK_DECAY_RULE.decay_lifetime);
    expect(validFrom.toISOString()).toBe('2023-02-21T17:57:09.266Z');
    expect(validUntil.toISOString()).toBe('2024-06-05T17:57:09.266Z');
  });
  it('should ttl default', async () => {
    let ttl = await computeValidTTL(testContext, ADMIN_USER, { ...DEFAULT_PARAM });
    expect(ttl).toBe(DEFAULT_INDICATOR_TTL);
    ttl = await computeValidTTL(testContext, ADMIN_USER, { ...DEFAULT_PARAM, objectMarking: [] });
    expect(ttl).toBe(DEFAULT_INDICATOR_TTL);
    ttl = await computeValidTTL(testContext, ADMIN_USER, {
      ...DEFAULT_PARAM,
      x_opencti_main_observable_type: 'wrong'
    });
    expect(ttl).toBe(DEFAULT_INDICATOR_TTL);
    ttl = await computeValidTTL(testContext, ADMIN_USER, { ...DEFAULT_PARAM, objectMarking: ['invalid'] });
    expect(ttl).toBe(DEFAULT_INDICATOR_TTL);
  });
  it('should ttl File', async () => {
    const ttl = await computeValidTTL(testContext, ADMIN_USER, {
      ...DEFAULT_PARAM,
      x_opencti_main_observable_type: 'File',
      objectMarking: [MARKING_TLP_GREEN],
    });
    expect(ttl).toBe(365);
  });
  it('should ttl Url', async () => {
    const ttl = await computeValidTTL(testContext, ADMIN_USER, {
      ...DEFAULT_PARAM,
      x_opencti_main_observable_type: 'Url',
      objectMarking: [MARKING_TLP_AMBER],
    });
    expect(ttl).toBe(180);
  });
  it('should ttl Url ordered', async () => {
    const ttl = await computeValidTTL(testContext, ADMIN_USER, {
      ...DEFAULT_PARAM,
      x_opencti_main_observable_type: 'Url',
      objectMarking: [MARKING_TLP_GREEN, MARKING_TLP_RED],
    });
    expect(ttl).toBe(180);
  });
  it('should ttl IPv6', async () => {
    const ttl = await computeValidTTL(testContext, ADMIN_USER, {
      ...DEFAULT_PARAM,
      x_opencti_main_observable_type: 'IPv6-Addr',
      objectMarking: [MARKING_TLP_RED],
    });
    expect(ttl).toBe(60);
  });
});
