import antlr4 from 'antlr4';
import * as C from '../schema/stixCyberObservable';
import STIXPatternLexer from '../stixpattern/STIXPatternLexer';
import STIXPatternParser from '../stixpattern/STIXPatternParser';
import STIXPatternListener from '../stixpattern/STIXPatternListener';
import { isFieldContributingToStandardId } from '../schema/identifier';
import { BASE_TYPE_ENTITY } from '../schema/general';
import { pascalize } from '../database/utils';

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
  const chars = new antlr4.InputStream(pattern);
  const lexer = new STIXPatternLexer(chars);
  const tokens = new antlr4.CommonTokenStream(lexer);
  const parser = new STIXPatternParser(tokens);
  antlr4.tree.ParseTreeWalker.DEFAULT.walk(new ObservableBuilder(), parser.pattern());
  return observables;
};

const systemChecker = /^\d{0,10}$/;
const domainChecker = /^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\\-]*[A-Za-z0-9])$/;
const hostnameChecker = /^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-_]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-_]*[A-Za-z0-9])$/;
const emailChecker = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
const ipv6Checker = /^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))(?:\/([0-9]|[1-9][0-9]|1[0-1][0-9]|12[0-8]))?$/;
const macAddrChecker = /^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/;
const ipv4Checker = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?:\/([0-9]|[1-2][0-9]|3[0-2]))?$/;

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
    default:
      return true;
  }
  return true;
};
