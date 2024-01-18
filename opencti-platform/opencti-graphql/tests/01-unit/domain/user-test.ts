import { describe, expect, it } from 'vitest';
import { testContext } from '../../utils/testQuery';
import { checkPasswordInlinePolicy, computeUserEffectiveConfidenceLevel } from '../../../src/domain/user';

describe('password checker', () => {
  it('should no policy applied', async () => {
    const policy = {};
    expect(checkPasswordInlinePolicy(testContext, policy, '').length).toBe(1);
    expect(checkPasswordInlinePolicy(testContext, policy, 'a').length).toBe(0);
    expect(checkPasswordInlinePolicy(testContext, policy, '!').length).toBe(0);
  });
  it('should password_policy_min_length policy applied', async () => {
    expect(checkPasswordInlinePolicy(testContext, { password_policy_min_length: 4 }, '123').length).toBe(1);
    expect(checkPasswordInlinePolicy(testContext, { password_policy_min_length: 4 }, '1234').length).toBe(0);
  });
  it('should password_policy_max_length policy applied', async () => {
    expect(checkPasswordInlinePolicy(testContext, { password_policy_max_length: 0 }, '123').length).toBe(0);
    expect(checkPasswordInlinePolicy(testContext, { password_policy_max_length: 2 }, '123').length).toBe(1);
    expect(checkPasswordInlinePolicy(testContext, { password_policy_max_length: 4 }, '1234').length).toBe(0);
    expect(checkPasswordInlinePolicy(testContext, { password_policy_max_length: 4 }, '12345').length).toBe(1);
  });
  it('should password_policy_min_symbols policy applied', async () => {
    expect(checkPasswordInlinePolicy(testContext, { password_policy_min_symbols: 4 }, '123é').length).toBe(1);
    expect(checkPasswordInlinePolicy(testContext, { password_policy_min_symbols: 4 }, '1!2!3$4$').length).toBe(0);
  });
  it('should password_policy_min_numbers policy applied', async () => {
    expect(checkPasswordInlinePolicy(testContext, { password_policy_min_numbers: 1 }, 'aaa').length).toBe(1);
    expect(checkPasswordInlinePolicy(testContext, { password_policy_min_numbers: 4 }, 'a1a2a3a4').length).toBe(0);
  });
  it('should password_policy_min_words policy applied', async () => {
    expect(checkPasswordInlinePolicy(testContext, { password_policy_min_words: 2 }, 'hello').length).toBe(1);
    expect(checkPasswordInlinePolicy(testContext, { password_policy_min_words: 2 }, 'hello-world').length).toBe(0);
    expect(checkPasswordInlinePolicy(testContext, { password_policy_min_words: 2 }, 'hello|world').length).toBe(0);
    expect(checkPasswordInlinePolicy(testContext, { password_policy_min_words: 2 }, 'hello_world').length).toBe(0);
    expect(checkPasswordInlinePolicy(testContext, { password_policy_min_words: 2 }, 'hello world').length).toBe(0);
  });
  it('should password_policy_min_lowercase policy applied', async () => {
    expect(checkPasswordInlinePolicy(testContext, { password_policy_min_lowercase: 4 }, 'AAAA').length).toBe(1);
    expect(checkPasswordInlinePolicy(testContext, { password_policy_min_lowercase: 4 }, 'aaaa').length).toBe(0);
  });
  it('should password_policy_min_uppercase policy applied', async () => {
    expect(checkPasswordInlinePolicy(testContext, { password_policy_min_uppercase: 4 }, 'aXaaXa').length).toBe(1);
    expect(checkPasswordInlinePolicy(testContext, { password_policy_min_uppercase: 4 }, 'AxAxAxA)').length).toBe(0);
  });
  it('should complex policy applied', async () => {
    const policy01 = {
      password_policy_min_length: 10,
      password_policy_min_symbols: 2,
      password_policy_min_numbers: 3,
      password_policy_min_words: 3,
      password_policy_min_lowercase: 2,
      password_policy_min_uppercase: 2,
    };
    expect(checkPasswordInlinePolicy(testContext, policy01, 'aXa77&&2aXa').length).toBe(1);
    expect(checkPasswordInlinePolicy(testContext, policy01, 'ab-CD-&^123').length).toBe(0);
    const policy02 = {
      password_policy_min_length: 4,
      password_policy_min_symbols: 1,
      password_policy_min_numbers: 2,
      password_policy_min_words: 0,
      password_policy_min_lowercase: 0,
      password_policy_min_uppercase: 0,
    };
    expect(checkPasswordInlinePolicy(testContext, policy02, 'test!').length).toBe(1);
    const policy03 = {
      password_policy_min_length: 2,
      password_policy_max_length: 5,
      password_policy_min_symbols: 1,
      password_policy_min_numbers: 0,
      password_policy_min_words: 0,
      password_policy_min_lowercase: 2,
      password_policy_min_uppercase: 1,
    };
    expect(checkPasswordInlinePolicy(testContext, policy03, 'julA').length).toBe(1);
    expect(checkPasswordInlinePolicy(testContext, policy03, 'ju!lA').length).toBe(0);
  });
});

describe('Effective max confidence level', () => {
  it("user's confidence level overrides groups and orgs", async () => {
    // minimal subset of a real User
    const userA = {
      user_confidence_level: {
        max_confidence: 30,
        overrides: [],
      },
      groups: [{
        group_confidence_level: {
          max_confidence: 70,
          overrides: [],
        }
      },
      {
        group_confidence_level: {
          max_confidence: 80,
          overrides: [],
        }
      }],
      organizations: []
    };
    expect(computeUserEffectiveConfidenceLevel(userA)).toEqual({ max_confidence: 30, overrides: [] }); // user overrides

    const userB = {
      user_confidence_level: null,
      groups: [{
        group_confidence_level: {
          max_confidence: 70,
          overrides: [],
        }
      },
      {
        group_confidence_level: {
          max_confidence: 80,
          overrides: [],
        }
      }],
      organizations: []
    };
    expect(computeUserEffectiveConfidenceLevel(userB)).toEqual({ max_confidence: 70, overrides: [] }); // lowest of groups

    const userC = {
      user_confidence_level: null,
      groups: [{
        group_confidence_level: {
          max_confidence: 70,
          overrides: [],
        }
      },
      {
        group_confidence_level: {
          max_confidence: 80,
          overrides: [],
        }
      }],
      organizations: [{
        org_confidence_level: {
          max_confidence: 90,
          overrides: [],
        }
      },
      {
        org_confidence_level: {
          max_confidence: 40,
          overrides: [],
        }
      }]
    };
    expect(computeUserEffectiveConfidenceLevel(userC)).toEqual({ max_confidence: 40, overrides: [] }); // lowest of groups and orgs

    const userD = {
      user_confidence_level: null,
      groups: [{
        group_confidence_level: null
      }],
      organizations: [{
        org_confidence_level: null
      }]
    };
    expect(computeUserEffectiveConfidenceLevel(userD)).toBeNull(); // nothing set
  });
});
