import { describe, it, expect } from 'vitest';
import { formatEmailsForApi, formatEmailsForFront } from '@components/settings/dissemination_lists/DisseminationListUtils';

const EXPECTED_RESULT_FOR_API = ['example1@email.com', 'sample.account@email.com'];
const EXPECTED_RESULT_FOR_FRONT = 'example1@email.com\nsample.account@email.com';

describe('Function: formatEmailsForApi', () => {
  it('should parse line', () => {
    const input = 'example1@email.com\nsample.account@email.com';
    expect(formatEmailsForApi(input)).toEqual(EXPECTED_RESULT_FOR_API);
  });
  it('should parse white space', () => {
    const input = 'example1@email.com      \nsample.account@email.com';
    expect(formatEmailsForApi(input)).toEqual(EXPECTED_RESULT_FOR_API);
  });
});

describe('Function: formatEmailsForFront', () => {
  it('should parse api result', () => {
    expect(formatEmailsForFront(EXPECTED_RESULT_FOR_API)).toEqual(EXPECTED_RESULT_FOR_FRONT);
  });
});
