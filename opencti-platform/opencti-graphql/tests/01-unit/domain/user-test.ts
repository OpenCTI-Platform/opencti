import { describe, expect, it } from 'vitest';
import { testContext } from '../../utils/testQuery';
import { checkPasswordInlinePolicy, isSensitiveChangesAllowed } from '../../../src/domain/user';
import { OPENCTI_ADMIN_UUID } from '../../../src/schema/general';

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

describe('isSensitiveChangesAllowed use case coverage', () => {
  const NOT_INFRA_ADMIN_USER_ID = '1c0925fe-ab65-42a1-8e96-ee6dc7fab4fa';

  it('should user with one role and not can_manage_sensitive_config set be allow change sensitive conf', async () => {
    // subset of role data
    const roles = [{
      base_type: 'ENTITY',
      confidence: 100,
      created_at: '2024-08-06T13:30:04.478Z',
      description: 'Administrator role that bypass every capabilities',
      entity_type: 'Role',
      id: '57312f0e-f276-44f8-97d3-88191ee57e1a',
      internal_id: '57312f0e-f276-44f8-97d3-88191ee57e1a',
      name: 'Administrator',
      updated_at: '2024-08-06T13:30:04.478Z'
    }
    ];

    const result = isSensitiveChangesAllowed(NOT_INFRA_ADMIN_USER_ID, roles);
    expect(result, 'Role without can_manage_sensitive_config field should be isSensitiveChangesAllowed=true').toBeTruthy();
  });

  it('should user with one role can_manage_sensitive_config=true be allow change sensitive conf', async () => {
    // subset of role data
    const roles = [{
      base_type: 'ENTITY',
      confidence: 100,
      created_at: '2024-08-06T13:30:04.478Z',
      description: 'Administrator role that bypass every capabilities',
      entity_type: 'Role',
      id: '57312f0e-f276-44f8-97d3-88191ee57e1a',
      internal_id: '57312f0e-f276-44f8-97d3-88191ee57e1a',
      name: 'Administrator',
      updated_at: '2024-08-06T13:30:04.478Z',
      can_manage_sensitive_config: true
    }
    ];

    const result = isSensitiveChangesAllowed(NOT_INFRA_ADMIN_USER_ID, roles);
    expect(result, 'Role with can_manage_sensitive_config field true should be isSensitiveChangesAllowed=true').toBeTruthy();
  });

  it('should user with one role can_manage_sensitive_config=false not be allow change sensitive conf', async () => {
    // subset of role data
    const roles = [{
      base_type: 'ENTITY',
      confidence: 100,
      created_at: '2024-08-06T13:30:04.478Z',
      description: 'Administrator role that bypass every capabilities',
      entity_type: 'Role',
      id: '57312f0e-f276-44f8-97d3-88191ee57e1a',
      internal_id: '57312f0e-f276-44f8-97d3-88191ee57e1a',
      name: 'Administrator',
      updated_at: '2024-08-06T13:30:04.478Z',
      can_manage_sensitive_config: false
    }
    ];

    const result = isSensitiveChangesAllowed(NOT_INFRA_ADMIN_USER_ID, roles);
    expect(result, 'Role with can_manage_sensitive_config field false should be isSensitiveChangesAllowed=false').toBeFalsy();
  });

  it('should user with 2 roles one without can_manage_sensitive_config, the other is false', async () => {
    // subset of role data
    const roles = [{
      base_type: 'ENTITY',
      confidence: 100,
      created_at: '2024-08-06T13:30:04.478Z',
      description: 'Administrator role that bypass every capabilities',
      entity_type: 'Role',
      id: '57312f0e-f276-44f8-97d3-88191ee57e1a',
      internal_id: '57312f0e-f276-44f8-97d3-88191ee57e1a',
      name: 'Administrator',
      updated_at: '2024-08-06T13:30:04.478Z',
    },
    {
      _index: 'opencti_internal_objects-000001',
      base_type: 'ENTITY',
      confidence: 100,
      created_at: '2024-08-06T13:30:04.478Z',
      description: 'Administrator role that bypass every capabilities',
      entity_type: 'Role',
      id: '57312f0e-f276-44f8-97d3-88191ee57e1a',
      internal_id: '57312f0e-f276-44f8-97d3-88191ee57e1a',
      name: 'Administrator',
      updated_at: '2024-08-06T13:30:04.478Z',
      can_manage_sensitive_config: false
    }
    ];

    const result = isSensitiveChangesAllowed(NOT_INFRA_ADMIN_USER_ID, roles);
    expect(result, 'Role with one can_manage_sensitive_config true should be isSensitiveChangesAllowed=true').toBeTruthy();
  });

  it('should user with 2 roles one without can_manage_sensitive_config, the other is true', async () => {
    // subset of role data
    const roles = [{
      base_type: 'ENTITY',
      confidence: 100,
      created_at: '2024-08-06T13:30:04.478Z',
      description: 'Administrator role that bypass every capabilities',
      entity_type: 'Role',
      id: '57312f0e-f276-44f8-97d3-88191ee57e1a',
      internal_id: '57312f0e-f276-44f8-97d3-88191ee57e1a',
      name: 'Administrator',
      updated_at: '2024-08-06T13:30:04.478Z',
    },
    {
      _index: 'opencti_internal_objects-000001',
      base_type: 'ENTITY',
      confidence: 100,
      created_at: '2024-08-06T13:30:04.478Z',
      description: 'Administrator role that bypass every capabilities',
      entity_type: 'Role',
      id: '57312f0e-f276-44f8-97d3-88191ee57e1a',
      internal_id: '57312f0e-f276-44f8-97d3-88191ee57e1a',
      name: 'Administrator',
      updated_at: '2024-08-06T13:30:04.478Z',
      can_manage_sensitive_config: true
    }
    ];

    const result = isSensitiveChangesAllowed(NOT_INFRA_ADMIN_USER_ID, roles);
    expect(result, 'Role with one can_manage_sensitive_config true should be isSensitiveChangesAllowed=true').toBeTruthy();
  });

  it('should user with 2 roles all with can_manage_sensitive_config set to false', async () => {
    // subset of role data
    const roles = [{
      base_type: 'ENTITY',
      confidence: 100,
      created_at: '2024-08-06T13:30:04.478Z',
      description: 'Administrator role that bypass every capabilities',
      entity_type: 'Role',
      id: '57312f0e-f276-44f8-97d3-88191ee57e1a',
      internal_id: '57312f0e-f276-44f8-97d3-88191ee57e1a',
      name: 'Administrator',
      updated_at: '2024-08-06T13:30:04.478Z',
      can_manage_sensitive_config: false
    },
    {
      _index: 'opencti_internal_objects-000001',
      base_type: 'ENTITY',
      confidence: 100,
      created_at: '2024-08-06T13:30:04.478Z',
      description: 'Administrator role that bypass every capabilities',
      entity_type: 'Role',
      id: '57312f0e-f276-44f8-97d3-88191ee57e1a',
      internal_id: '57312f0e-f276-44f8-97d3-88191ee57e1a',
      name: 'Administrator',
      updated_at: '2024-08-06T13:30:04.478Z',
      can_manage_sensitive_config: false
    }
    ];

    const result = isSensitiveChangesAllowed(NOT_INFRA_ADMIN_USER_ID, roles);
    expect(result, 'Role with all can_manage_sensitive_config field false should be isSensitiveChangesAllowed=false').toBeFalsy();
  });

  it('should INFRA admin bypass sensitive conf', async () => {
    // subset of role data
    const roles = [{
      base_type: 'ENTITY',
      confidence: 100,
      created_at: '2024-08-06T13:30:04.478Z',
      description: 'Administrator role that bypass every capabilities',
      entity_type: 'Role',
      id: '57312f0e-f276-44f8-97d3-88191ee57e1a',
      internal_id: '57312f0e-f276-44f8-97d3-88191ee57e1a',
      name: 'Administrator',
      updated_at: '2024-08-06T13:30:04.478Z',
      can_manage_sensitive_config: false
    },
    {
      _index: 'opencti_internal_objects-000001',
      base_type: 'ENTITY',
      confidence: 100,
      created_at: '2024-08-06T13:30:04.478Z',
      description: 'Administrator role that bypass every capabilities',
      entity_type: 'Role',
      id: '57312f0e-f276-44f8-97d3-88191ee57e1a',
      internal_id: '57312f0e-f276-44f8-97d3-88191ee57e1a',
      name: 'Administrator',
      updated_at: '2024-08-06T13:30:04.478Z',
      can_manage_sensitive_config: false
    }
    ];

    const result = isSensitiveChangesAllowed(OPENCTI_ADMIN_UUID, roles);
    expect(result, 'OPENCTI_ADMIN_UUID should be always isSensitiveChangesAllowed=true').toBeTruthy();
  });

  it('should INFRA user with 2 roles one without can_manage_sensitive_config, the other is true', async () => {
    // subset of role data
    const roles = [{
      base_type: 'ENTITY',
      confidence: 100,
      created_at: '2024-08-06T13:30:04.478Z',
      description: 'Administrator role that bypass every capabilities',
      entity_type: 'Role',
      id: '57312f0e-f276-44f8-97d3-88191ee57e1a',
      internal_id: '57312f0e-f276-44f8-97d3-88191ee57e1a',
      name: 'Administrator',
      updated_at: '2024-08-06T13:30:04.478Z',
    },
    {
      _index: 'opencti_internal_objects-000001',
      base_type: 'ENTITY',
      confidence: 100,
      created_at: '2024-08-06T13:30:04.478Z',
      description: 'Administrator role that bypass every capabilities',
      entity_type: 'Role',
      id: '57312f0e-f276-44f8-97d3-88191ee57e1a',
      internal_id: '57312f0e-f276-44f8-97d3-88191ee57e1a',
      name: 'Administrator',
      updated_at: '2024-08-06T13:30:04.478Z',
      can_manage_sensitive_config: true
    }
    ];

    const result = isSensitiveChangesAllowed(OPENCTI_ADMIN_UUID, roles);
    expect(result, 'OPENCTI_ADMIN_UUID should be always isSensitiveChangesAllowed=true').toBeTruthy();
  });

  it('should INFRA admin bypass sensitive conf with zero role', async () => {
    // subset of role data
    const roles: any[] = [];
    const result = isSensitiveChangesAllowed(OPENCTI_ADMIN_UUID, roles);
    expect(result, 'OPENCTI_ADMIN_UUID should be always isSensitiveChangesAllowed=true').toBeTruthy();
  });

  it('should a user with zero role be isSensitiveChangesAllowed=false', async () => {
    // subset of role data
    const roles: any[] = [];
    const result = isSensitiveChangesAllowed(NOT_INFRA_ADMIN_USER_ID, roles);
    expect(result, 'A user with no role should be isSensitiveChangesAllowed=false').toBeFalsy();
  });
});
