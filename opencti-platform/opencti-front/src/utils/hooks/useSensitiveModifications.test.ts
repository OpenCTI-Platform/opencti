import { describe, it, expect } from 'vitest';
import { UserContextType } from './useAuth';
import { createMockUserContext, testRenderHook } from '../tests/test-render';
import useSensitiveModifications from './useSensitiveModifications';

describe('Hook: useSensitiveModifications', () => {
  const baseUserContext = {
    me: { can_manage_sensitive_config: false },
    settings: { platform_protected_sensitive_config: { enabled: true } },
  } as unknown as UserContextType;

  it('should be allowed if sensitive config disabled', () => {
    const { hook } = testRenderHook(
      () => useSensitiveModifications(),
      {
        userContext: createMockUserContext({
          ...baseUserContext,
          settings: {
            platform_protected_sensitive_config: {
              enabled: false,
            },
          },
        }),
      },
    );
    const { isAllowed, isSensitive } = hook.result.current;
    expect(isAllowed).toEqual(true);
    expect(isSensitive).toEqual(false);
  });
  it('should be allowed if can managed sensitive', () => {
    const { hook } = testRenderHook(
      () => useSensitiveModifications(),
      {
        userContext: createMockUserContext({
          ...baseUserContext,
          me: { can_manage_sensitive_config: true },
        }),
      },
    );
    const { isAllowed } = hook.result.current;
    expect(isAllowed).toEqual(true);
  });
  it('should not be allowed if cannot managed sensitive', () => {
    const { hook } = testRenderHook(
      () => useSensitiveModifications(),
      {
        userContext: createMockUserContext({
          ...baseUserContext,
          me: { can_manage_sensitive_config: false },
        }),
      },
    );
    const { isAllowed } = hook.result.current;
    expect(isAllowed).toEqual(false);
  });
  it('should not be sensitive if sensitive config enabled but markings config is not', () => {
    const { hook } = testRenderHook(
      () => useSensitiveModifications('markings'),
      {
        userContext: createMockUserContext({
          ...baseUserContext,
          me: { can_manage_sensitive_config: true },
          settings: {
            platform_protected_sensitive_config: {
              enabled: true,
              markings: {
                enabled: false,
              },
            },
          },
        }),
      },
    );
    const { isSensitive } = hook.result.current;
    expect(isSensitive).toEqual(false);
  });
});
