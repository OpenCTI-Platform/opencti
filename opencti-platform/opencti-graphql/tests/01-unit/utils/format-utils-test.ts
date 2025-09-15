import { describe, expect, it } from 'vitest';
import { checkScore } from '../../../src/utils/format';
import { normalizeUrl } from '../../../src/schema/identifier';

describe('checkScoreValue tests', () => {
  it('should throw validationError for score > 100', () => {
    expect(() => checkScore(110))
      .toThrowError('The score should be an integer between 0 and 100');
  });
  it('should throw validationError for score < 0', () => {
    expect(() => checkScore(-3))
      .toThrowError('The score should be an integer between 0 and 100');
  });
  it('should throw validationError for non integer score', () => {
    expect(() => checkScore(0.5))
      .toThrowError('The score should be an integer between 0 and 100');
  });
  it('should return true if score is undefined', () => {
    const check = checkScore(undefined);
    expect(check).toEqual(true);
  });
  it('should return true if score is an integer between 0 and 100', () => {
    const check = checkScore(40);
    expect(check).toEqual(true);
  });
  it('should return true if score is correct string', () => {
    const check = checkScore('40');
    expect(check).toEqual(true);
  });
  it('should return true if score is correct string', () => {
    const check = checkScore('0');
    expect(check).toEqual(true);
  });
  it('should throw validationError for non integer score', () => {
    expect(() => checkScore('0.5'))
      .toThrowError('The score should be an integer between 0 and 100');
  });
});

describe('normalizeUrl tests', () => {
  it('should not modify a URL without a trailing slash', () => {
    expect(normalizeUrl('https://www.example.com')).to.equal('https://www.example.com');
  });

  it('should remove a trailing slash from a URL', () => {
    expect(normalizeUrl('https://www.example.com/')).to.equal('https://www.example.com');
  });

  it('should remove multiple trailing slashes from a URL', () => {
    expect(normalizeUrl('https://www.example.com///')).to.equal('https://www.example.com');
  });

  it('should handle an empty URL', () => {
    expect(normalizeUrl('')).to.equal('');
  });

  it('should not remove query parameters from a URL', () => {
    expect(normalizeUrl('https://www.example.com/path?query=param')).to.equal('https://www.example.com/path?query=param');
  });

  it('should not remove a fragment from a URL', () => {
    expect(normalizeUrl('https://www.example.com/path#fragment')).to.equal('https://www.example.com/path#fragment');
  });
});
