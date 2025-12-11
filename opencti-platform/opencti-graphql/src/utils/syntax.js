import antlr4 from '../stixpattern/STIXAntlr';
import * as C from '../schema/stixCyberObservable';
import STIXPatternLexer from '../stixpattern/STIXPatternLexer';
import STIXPatternParser from '../stixpattern/STIXPatternParser';
import STIXPatternListener from '../stixpattern/STIXPatternListener';
import { isFieldContributingToStandardId } from '../schema/identifier';
import { BASE_TYPE_ENTITY } from '../schema/general';
import { pascalize } from '../database/utils';

export const STIX_PATTERN_TYPE = 'stix';

const unflatten = (data) => {
  const result = {};
  // eslint-disable-next-line no-restricted-syntax,guard-for-in
  for (const i in data) {
    const keys = i.split('.');
    keys.reduce((r, e, j) => {
      // eslint-disable-next-line no-nested-ternary,no-param-reassign,no-return-assign
      return r[e] || (r[e] = Number.isNaN(Number(keys[j + 1])) ? (keys.length - 1 === j ? data[i] : {}) : []);
    }, result);
  }
  return result;
};

const parsePattern = (pattern) => {
  const chars = new antlr4.InputStream(pattern);
  const lexer = new STIXPatternLexer(chars);
  const tokens = new antlr4.CommonTokenStream(lexer);
  const parser = new STIXPatternParser(tokens);
  parser.removeErrorListeners();
  return { parser, parsedPattern: parser.pattern() };
};

export const extractObservablesFromIndicatorPattern = (pattern) => {
  const observables = [];
  class ObservableBuilder extends STIXPatternListener {
    enterPropTestEqual() {
      this.element = {};
    }

    enterObjectType(ctx) {
      if (this.element) {
        let formattedType = `${ctx.getText().split('-').map((e) => pascalize(e)).join('-')}`;
        if (formattedType === 'File') {
          formattedType = 'StixFile';
        }
        if (formattedType === 'Ipv4-Addr') {
          formattedType = 'IPv4-Addr';
        }
        if (formattedType === 'Ipv6-Addr') {
          formattedType = 'IPv6-Addr';
        }
        if (formattedType === 'Ssh-Key') {
          formattedType = 'SSH-Key';
        }
        this.element.type = formattedType;
      }
    }

    enterFirstPathComponent(ctx) {
      const key = ctx.getText();
      if (this.element) {
        const instance = { entity_type: this.element.type, base_type: BASE_TYPE_ENTITY };
        try {
          if (isFieldContributingToStandardId(instance, [key])) {
            this.element.component = key;
          } else {
            this.element = undefined;
          }
        } catch {
          // Type unknown
          this.element = undefined;
        }
      }
    }

    enterKeyPathStep(ctx) {
      const text = ctx.getText();
      if (this.element) {
        this.element.component += text.replaceAll('\'', '');
      }
    }

    enterPrimitiveLiteral(ctx) {
      if (this.element) {
        const val = ctx.getText().replaceAll('\'', '');
        const data = { type: this.element.type, [this.element.component]: val };
        const unflat = unflatten(data);
        observables.push(unflat);
      }
    }
  }
  const { parsedPattern } = parsePattern(pattern);
  antlr4.tree.ParseTreeWalker.DEFAULT.walk(new ObservableBuilder(), parsedPattern);
  return observables;
};

export const validateObservableGeneration = (observableType, indicatorPattern) => {
  if (observableType === C.ENTITY_NETWORK_TRAFFIC && (indicatorPattern.includes('dst_ref') || indicatorPattern.includes('src_ref'))) {
    return false; // we can't create this type of observables (issue #5293)
  }
  if (observableType === C.ENTITY_EMAIL_MESSAGE && (indicatorPattern.includes('from_ref') || indicatorPattern.includes('sender_ref'))) {
    return false; // we can't create this type of observables (issue #5293)
  }
  return true;
};

export const extractValidObservablesFromIndicatorPattern = (pattern) => {
  const observables = extractObservablesFromIndicatorPattern(pattern);
  return observables.filter((obs) => validateObservableGeneration(obs.type, pattern));
};

export const cleanupIndicatorPattern = (patternType, pattern) => {
  if (pattern && patternType.toLowerCase() === STIX_PATTERN_TYPE) {
    const grabInterestingTokens = (ctx, parser, acc) => {
      const operators = [...parser.symbolicNames, '=', '!=', '<', '>', '<=', '>='];
      const numberOfTokens = ctx.getChildCount();
      for (let i = 0; i < numberOfTokens; i += 1) {
        const child = ctx.getChild(i);
        const subCount = child.getChildCount();
        if (subCount > 0) {
          grabInterestingTokens(child, parser, acc);
        } else if (operators.includes(child.getText())) {
          acc.push(` ${child.getText()} `);
        } else {
          acc.push(child.getText());
        }
      }
    };
    const { parser, parsedPattern } = parsePattern(pattern);
    const patternContext = parsedPattern.getChild(0);
    const patternTokens = [];
    grabInterestingTokens(patternContext, parser, patternTokens);
    return patternTokens.join('').trim();
  }
  // For other pattern type, cleanup is not yet implemented
  return pattern;
};

export const systemChecker = /^\d{0,10}$/;
export const domainChecker = /^(?=.{1,253}$)(?!-)(?:[^\s.](?:[^\s.]{0,61}[^\s.])?\.)+[^\s.]{2,63}$/;
export const hostnameChecker = /^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-_]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-_]*[A-Za-z0-9])$/;
export const emailChecker = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
export const ipv6Checker = /^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))(?:\/([0-9]|[1-9][0-9]|1[0-1][0-9]|12[0-8]))?$/;
export const macAddrChecker = /^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/;
export const ipv4Checker = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?:\/([0-9]|[1-2][0-9]|3[0-2]))?$/;
export const cpeChecker = /^cpe:\/\/[a-zA-Z0-9_./:-]+|^cpe:\/[a-zA-Z0-9_./:-]+$/;
export const fintelTemplateVariableNameChecker = /^[A-Za-z0-9_-]+$/;
export const imeiChecker = /(^[0-9]{15,16})$/;
export const iccidChecker = /(^[0-9]{18,22})$/;
export const imsiChecker = /(^[0-9]{14,15})$/;

export const checkObservableSyntax = (observableType, observableData) => {
  switch (observableType) {
    case C.ENTITY_AUTONOMOUS_SYSTEM:
      if (!systemChecker.test(observableData.number)) return 'Must be numeric';
      break;
    case C.ENTITY_DOMAIN_NAME:
      if (!domainChecker.test(observableData.value)) return 'Valid domain name';
      break;
    case C.ENTITY_HASHED_OBSERVABLE_STIX_FILE:
    case C.ENTITY_HASHED_OBSERVABLE_ARTIFACT:
      if (observableData.hashes && observableData.hashes.MD5) {
        const md5Checker = /^[a-fA-F0-9]{32}$/;
        if (!md5Checker.test(observableData.hashes.MD5)) return 'Valid MD5 hash';
      }
      if (observableData.hashes && observableData.hashes['SHA-1']) {
        const sha1Checker = /^[a-fA-F0-9]{40}$/;
        if (!sha1Checker.test(observableData.hashes['SHA-1'])) return 'Valid SHA-1 hash';
      }
      if (observableData.hashes && observableData.hashes['SHA-256']) {
        const sha256checker = /^[a-fA-F0-9]{64}$/;
        if (!sha256checker.test(observableData.hashes['SHA-256'])) return 'Valid SHA-256 hash';
      }
      if (observableData.hashes && observableData.hashes['SHA-512']) {
        const sha512checker = /^[a-fA-F0-9]{128}$/;
        if (!sha512checker.test(observableData.hashes['SHA-512'])) return 'Valid SHA-512 hash';
      }
      break;
    case C.ENTITY_HOSTNAME:
      if (!hostnameChecker.test(observableData.value)) return 'Valid hostname';
      break;
    case C.ENTITY_EMAIL_ADDR:
      if (!emailChecker.test(observableData.value)) return 'Valid email address';
      break;
    case C.ENTITY_IPV4_ADDR:
      if (!ipv4Checker.test(observableData.value)) return 'Valid IPv4 address';
      break;
    case C.ENTITY_IPV6_ADDR:
      if (!ipv6Checker.test(observableData.value)) return 'Valid IPv6 address';
      break;
    case C.ENTITY_MAC_ADDR:
      if (!macAddrChecker.test(observableData.value)) return 'Valid MAC address';
      break;
    case C.ENTITY_SOFTWARE:
      if (!observableData.name && !cpeChecker.test(observableData.cpe) && !observableData.swid) return 'Valid Software attributes';
      break;
    case C.ENTITY_IMEI:
      if (!imeiChecker.test(observableData.value)) return 'Valid IMEI';
      break;
    case C.ENTITY_ICCID:
      if (!iccidChecker.test(observableData.value)) return 'Valid ICCID';
      break;
    case C.ENTITY_IMSI:
      if (!imsiChecker.test(observableData.value)) return 'Valid IMSI';
      break;
    default:
      return true;
  }
  return true;
};
