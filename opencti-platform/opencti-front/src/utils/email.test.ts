import { describe, it, expect } from 'vitest';
import { parseEmailList } from './email';

describe('Function: parseEmailList', () => {
  it('should return matching emails from outlook-like input ("Recipient name" <email@address>)', () => {
    const input = '"Alice Doe" <alice.doe@example.com>; "Bob Doe" <bob.doe@example.com>;"Candice Doe" <candice.doe@example.com>';
    expect(parseEmailList(input)).toEqual([
      'alice.doe@example.com',
      'bob.doe@example.com',
      'candice.doe@example.com',
    ]);
  });

  it('should return matching emails from gmail-like input (comma separated emails)', () => {
    const input = 'alice.doe@example.com, bob.doe@example.com, candice.doe@example.com';
    expect(parseEmailList(input)).toEqual([
      'alice.doe@example.com',
      'bob.doe@example.com',
      'candice.doe@example.com',
    ]);
  });

  it('should return matching emails from a list of 10k outlook-like emails', () => {
    const expectedResult: string[] = [];
    const fakeEmailList = Array.from({ length: 10000 }, (_, i) => {
      const firstName = `FirstName${i + 1}`;
      const lastName = `LastName${i + 1}`;
      const email = `${firstName.toLowerCase()}.${lastName.toLowerCase()}@example.com`;
      expectedResult.push(email);
      return `"${firstName} ${lastName}" <${email}>`;
    }).join('; ');

    expect(parseEmailList(fakeEmailList)).toEqual(expectedResult);
  });
});
