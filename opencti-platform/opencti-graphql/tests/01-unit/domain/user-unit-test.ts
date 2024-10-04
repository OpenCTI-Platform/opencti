import { describe, expect, it } from 'vitest';
import { testContext } from '../../utils/testQuery';
import {checkPasswordInlinePolicy, isSensitiveChangesAllowed} from '../../../src/domain/user';

describe.skip('password checker', () => {
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

describe('isSensitiveChangesAllowed use case coverage', () => {
  it('should user with one role and not is_sensitive_changes_allow set be allow change sensitive conf', async () => {

    //subset of role data
    const roles =
        [ {
          "base_type": "ENTITY",
          "confidence": 100,
          "created_at": "2024-08-06T13:30:04.478Z",
          "description": "Administrator role that bypass every capabilities",
          "entity_type": "Role",
          "id": "57312f0e-f276-44f8-97d3-88191ee57e1a",
          "internal_id": "57312f0e-f276-44f8-97d3-88191ee57e1a",
          "name": "Administrator",
          "updated_at": "2024-08-06T13:30:04.478Z"
        }
  ]

    const result = isSensitiveChangesAllowed(roles);
    expect(result, 'Role without is_sensitive_changes_allow field should be isSensitiveChangesAllowed=true').toBeTruthy();
  });

  it('should user with one role is_sensitive_changes_allow=true be allow change sensitive conf', async () => {
    //subset of role data
    const roles =
        [{
            "base_type": "ENTITY",
            "confidence": 100,
            "created_at": "2024-08-06T13:30:04.478Z",
            "description": "Administrator role that bypass every capabilities",
            "entity_type": "Role",
            "id": "57312f0e-f276-44f8-97d3-88191ee57e1a",
            "internal_id": "57312f0e-f276-44f8-97d3-88191ee57e1a",
            "name": "Administrator",
            "updated_at": "2024-08-06T13:30:04.478Z",
            "is_sensitive_changes_allow": true
          }
        ]

    const result = isSensitiveChangesAllowed(roles);
    expect(result, 'Role with is_sensitive_changes_allow field true should be isSensitiveChangesAllowed=true').toBeTruthy();

  });

  it('should user with one role is_sensitive_changes_allow=false not be allow change sensitive conf', async () => {
    //subset of role data
    const roles =
        [{
            "base_type": "ENTITY",
            "confidence": 100,
            "created_at": "2024-08-06T13:30:04.478Z",
            "description": "Administrator role that bypass every capabilities",
            "entity_type": "Role",
            "id": "57312f0e-f276-44f8-97d3-88191ee57e1a",
            "internal_id": "57312f0e-f276-44f8-97d3-88191ee57e1a",
            "name": "Administrator",
            "updated_at": "2024-08-06T13:30:04.478Z",
            "is_sensitive_changes_allow": false
          }
        ]

    const result = isSensitiveChangesAllowed(roles);
    expect(result, 'Role with is_sensitive_changes_allow field false should be isSensitiveChangesAllowed=false').toBeFalsy();
  });

  it('should user with 2 roles one without is_sensitive_changes_allow, the other is false', async () => {
    //subset of role data
    const roles =
        [{
            "base_type": "ENTITY",
            "confidence": 100,
            "created_at": "2024-08-06T13:30:04.478Z",
            "description": "Administrator role that bypass every capabilities",
            "entity_type": "Role",
            "id": "57312f0e-f276-44f8-97d3-88191ee57e1a",
            "internal_id": "57312f0e-f276-44f8-97d3-88191ee57e1a",
            "name": "Administrator",
            "updated_at": "2024-08-06T13:30:04.478Z",
          },
          {
            "_index": "opencti_internal_objects-000001",
            "base_type": "ENTITY",
            "confidence": 100,
            "created_at": "2024-08-06T13:30:04.478Z",
            "description": "Administrator role that bypass every capabilities",
            "entity_type": "Role",
            "id": "57312f0e-f276-44f8-97d3-88191ee57e1a",
            "internal_id": "57312f0e-f276-44f8-97d3-88191ee57e1a",
            "name": "Administrator",
            "updated_at": "2024-08-06T13:30:04.478Z",
            "is_sensitive_changes_allow": false
          }
        ]

    const result = isSensitiveChangesAllowed(roles);
    expect(result, 'Role with one is_sensitive_changes_allow true should be isSensitiveChangesAllowed=true').toBeTruthy();
  });

  it('should user with 2 roles one without is_sensitive_changes_allow, the other is true', async () => {
    //subset of role data
    const roles =
        [{
            "base_type": "ENTITY",
            "confidence": 100,
            "created_at": "2024-08-06T13:30:04.478Z",
            "description": "Administrator role that bypass every capabilities",
            "entity_type": "Role",
            "id": "57312f0e-f276-44f8-97d3-88191ee57e1a",
            "internal_id": "57312f0e-f276-44f8-97d3-88191ee57e1a",
            "name": "Administrator",
            "updated_at": "2024-08-06T13:30:04.478Z",
          },
          {
            "_index": "opencti_internal_objects-000001",
            "base_type": "ENTITY",
            "confidence": 100,
            "created_at": "2024-08-06T13:30:04.478Z",
            "description": "Administrator role that bypass every capabilities",
            "entity_type": "Role",
            "id": "57312f0e-f276-44f8-97d3-88191ee57e1a",
            "internal_id": "57312f0e-f276-44f8-97d3-88191ee57e1a",
            "name": "Administrator",
            "updated_at": "2024-08-06T13:30:04.478Z",
            "is_sensitive_changes_allow": true
          }
        ]

    const result = isSensitiveChangesAllowed(roles);
    expect(result, 'Role with one is_sensitive_changes_allow true should be isSensitiveChangesAllowed=true').toBeTruthy();
  });

  it('should user with 2 roles all with is_sensitive_changes_allow set to false', async () => {
    //subset of role data
    const roles =
        [{
            "base_type": "ENTITY",
            "confidence": 100,
            "created_at": "2024-08-06T13:30:04.478Z",
            "description": "Administrator role that bypass every capabilities",
            "entity_type": "Role",
            "id": "57312f0e-f276-44f8-97d3-88191ee57e1a",
            "internal_id": "57312f0e-f276-44f8-97d3-88191ee57e1a",
            "name": "Administrator",
            "updated_at": "2024-08-06T13:30:04.478Z",
            "is_sensitive_changes_allow": false
          },
          {
            "_index": "opencti_internal_objects-000001",
            "base_type": "ENTITY",
            "confidence": 100,
            "created_at": "2024-08-06T13:30:04.478Z",
            "description": "Administrator role that bypass every capabilities",
            "entity_type": "Role",
            "id": "57312f0e-f276-44f8-97d3-88191ee57e1a",
            "internal_id": "57312f0e-f276-44f8-97d3-88191ee57e1a",
            "name": "Administrator",
            "updated_at": "2024-08-06T13:30:04.478Z",
            "is_sensitive_changes_allow": false
          }
        ]

    const result = isSensitiveChangesAllowed(roles);
    expect(result, 'Role with all is_sensitive_changes_allow field false should be isSensitiveChangesAllowed=false').toBeFalsy();
  });

});