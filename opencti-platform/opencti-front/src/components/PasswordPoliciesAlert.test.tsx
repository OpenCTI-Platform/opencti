import { describe, expect, it } from 'vitest';
import { screen } from '@testing-library/react';
import testRender from '../utils/tests/test-render';
import PasswordPoliciesAlert, { countDigits, countLowercase, countSymbols, countUppercase, countWords } from './PasswordPoliciesAlert';

describe('countSymbols', () => {
  it('returns 0 for an empty string', () => expect(countSymbols('')).toBe(0));
  it('returns 0 for alphanumeric only', () => expect(countSymbols('abc123')).toBe(0));
  it('counts a single symbol', () => expect(countSymbols('abc!')).toBe(1));
  it('counts multiple symbols', () => expect(countSymbols('a!b@c#')).toBe(3));
  it('counts spaces as symbols', () => expect(countSymbols('hello world')).toBe(1));
  it('counts unicode special chars', () => expect(countSymbols('café')).toBe(1));
});

describe('countDigits', () => {
  it('returns 0 for an empty string', () => expect(countDigits('')).toBe(0));
  it('returns 0 when no digits', () => expect(countDigits('abc')).toBe(0));
  it('counts a single digit', () => expect(countDigits('a1b')).toBe(1));
  it('counts multiple digits', () => expect(countDigits('a12b34')).toBe(4));
});

describe('countWords', () => {
  it('returns 0 for an empty string', () => expect(countWords('')).toBe(0));
  it('returns 1 for a single word', () => expect(countWords('hello')).toBe(1));
  it('splits on space', () => expect(countWords('hello world')).toBe(2));
  it('splits on hyphen', () => expect(countWords('hello-world')).toBe(2));
  it('splits on multiple separators', () => expect(countWords('one two-three')).toBe(3));
  it('ignores leading/trailing separators', () => expect(countWords(' hello ')).toBe(1));
  it('collapses consecutive separators', () => expect(countWords('one  two')).toBe(2));
});

describe('countLowercase', () => {
  it('returns 0 for an empty string', () => expect(countLowercase('')).toBe(0));
  it('returns 0 for uppercase only', () => expect(countLowercase('ABC')).toBe(0));
  it('counts lowercase letters', () => expect(countLowercase('aAbBcC')).toBe(3));
  it('ignores digits and symbols', () => expect(countLowercase('a1!b')).toBe(2));
});

describe('countUppercase', () => {
  it('returns 0 for an empty string', () => expect(countUppercase('')).toBe(0));
  it('returns 0 for lowercase only', () => expect(countUppercase('abc')).toBe(0));
  it('counts uppercase letters', () => expect(countUppercase('aAbBcC')).toBe(3));
  it('ignores digits and symbols', () => expect(countUppercase('A1!B')).toBe(2));
});

describe('PasswordPoliciesAlert', () => {
  it('renders nothing when all policies are zero', () => {
    const { container } = testRender(
      <PasswordPoliciesAlert policies={{ minLength: 0, maxLength: 0, minSymbols: 0, minNumbers: 0, minWords: 0, minLowercase: 0, minUppercase: 0 }} />,
    );
    expect(container).toBeEmptyDOMElement();
  });

  it('renders nothing when policies object is empty', () => {
    const { container } = testRender(<PasswordPoliciesAlert policies={{}} />);
    expect(container).toBeEmptyDOMElement();
  });

  it('renders nothing when all policies are null', () => {
    const { container } = testRender(
      <PasswordPoliciesAlert policies={{ minLength: null, maxLength: null }} />,
    );
    expect(container).toBeEmptyDOMElement();
  });

  it('renders the alert title when at least one policy is active', () => {
    testRender(<PasswordPoliciesAlert policies={{ minLength: 8 }} />);
    expect(screen.getByText('Password security policies')).toBeInTheDocument();
  });

  it('renders only the active policy lines', () => {
    testRender(<PasswordPoliciesAlert policies={{ minLength: 8, minUppercase: 2 }} />);
    expect(screen.getByText(/Number of chars must be greater or equals to/)).toBeInTheDocument();
    expect(screen.getByText(/Number of uppercase chars must be greater or equals to/)).toBeInTheDocument();
    expect(screen.queryByText(/Number of chars must be lower or equals to/)).not.toBeInTheDocument();
    expect(screen.queryByText(/Number of symbols must be greater or equals to/)).not.toBeInTheDocument();
  });

  it('renders the policy value next to each rule', () => {
    testRender(<PasswordPoliciesAlert policies={{ minNumbers: 3 }} />);
    expect(screen.getByText(/3/)).toBeInTheDocument();
  });

  it('renders all policy lines when all are set', () => {
    testRender(
      <PasswordPoliciesAlert
        policies={{ minLength: 8, maxLength: 64, minSymbols: 1, minNumbers: 2, minWords: 3, minLowercase: 1, minUppercase: 1 }}
      />,
    );
    expect(screen.getByText(/Number of chars must be greater or equals to/)).toBeInTheDocument();
    expect(screen.getByText(/Number of chars must be lower or equals to/)).toBeInTheDocument();
    expect(screen.getByText(/Number of symbols must be greater or equals to/)).toBeInTheDocument();
    expect(screen.getByText(/Number of digits must be greater or equals to/)).toBeInTheDocument();
    expect(screen.getByText(/Number of words/)).toBeInTheDocument();
    expect(screen.getByText(/Number of lowercase chars must be greater or equals to/)).toBeInTheDocument();
    expect(screen.getByText(/Number of uppercase chars must be greater or equals to/)).toBeInTheDocument();
  });
});
