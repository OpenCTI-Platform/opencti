import React from 'react';
import { render } from '@testing-library/react';
import { IntlShape, useIntl } from 'react-intl';
import { beforeEach, describe, expect, it } from 'vitest';
import AppIntlProvider from './AppIntlProvider';
import { UserContext } from '../utils/hooks/useAuth';
import { createMockUserContext } from '../utils/tests/test-render';

const intlRenders: IntlShape[] = [];

const IntlProbe = () => {
  intlRenders.push(useIntl());
  return null;
};

const userContext = createMockUserContext();

// A new settings object on every call, like a parent re-rendering with its own literal.
const providerTree = (platformTranslations: string) => (
  <UserContext.Provider value={userContext}>
    <AppIntlProvider settings={{ platform_language: 'auto', platform_translations: platformTranslations }}>
      <IntlProbe />
    </AppIntlProvider>
  </UserContext.Provider>
);

const lastIntl = () => intlRenders[intlRenders.length - 1];

describe('AppIntlProvider', () => {
  beforeEach(() => {
    intlRenders.length = 0;
  });

  it('keeps the same intl object when it re-renders with the same translations', () => {
    const { rerender } = render(providerTree('{}'));
    const first = lastIntl();

    rerender(providerTree('{}'));

    expect(intlRenders.length).toBeGreaterThan(1);
    expect(lastIntl()).toBe(first);
  });

  it('builds a new intl object when the platform translations change', () => {
    const { rerender } = render(providerTree('{}'));
    const first = lastIntl();

    rerender(providerTree(JSON.stringify({ 'en-us': { Dashboard: 'Home' } })));

    expect(lastIntl()).not.toBe(first);
    expect(lastIntl().messages.Dashboard).toBe('Home');
  });
});
