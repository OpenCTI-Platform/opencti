import { describe, expect, it, vi } from 'vitest';
import { getEntityValidatorCreation, getEntityValidatorUpdate, registerEntityValidator } from '../../../src/schema/validator-register';
import { testContext } from '../../utils/testQuery';
import { SYSTEM_USER } from '../../../src/utils/access';

describe('Entity validator registry', () => {
  it('should accept an input only when every validator registered for its type accepts it', async () => {
    const type = 'Validator-Register-Test';
    const first = vi.fn(async (_context: unknown, _user: unknown, instance: Record<string, unknown>) => instance.first !== 'refused');
    const second = vi.fn(async (_context: unknown, _user: unknown, instance: Record<string, unknown>) => instance.second !== 'refused');
    const update = vi.fn(async () => true);
    registerEntityValidator(type, { validatorCreation: first });
    registerEntityValidator(type, { validatorCreation: second, validatorUpdate: update });
    const validatorCreation = getEntityValidatorCreation(type);
    expect(await validatorCreation?.(testContext, SYSTEM_USER, {})).toBe(true);
    expect(first).toHaveBeenCalledTimes(1);
    expect(second).toHaveBeenCalledTimes(1);
    expect(await validatorCreation?.(testContext, SYSTEM_USER, { second: 'refused' })).toBe(false);
    // A validator refusing the input stops the chain
    expect(await validatorCreation?.(testContext, SYSTEM_USER, { first: 'refused' })).toBe(false);
    expect(second).toHaveBeenCalledTimes(2);
    expect(getEntityValidatorUpdate(type)).toBe(update);
  });
});
