import React from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';
import testRender from '../../../../utils/tests/test-render';
import EmailTemplateAttributesSidebar from './EmailTemplateAttributesSidebar';

let lockoutFlag = false;
vi.mock('../../../../utils/hooks/useHelper', () => ({
  default: () => ({ isFeatureEnable: (flag: string) => flag === 'LOCAL_AUTH_LOCKOUT' && lockoutFlag }),
}));

describe('EmailTemplateAttributesSidebar', () => {
  beforeEach(() => {
    lockoutFlag = false;
  });

  it('shows the variables of the recipient and of the platform', () => {
    testRender(<EmailTemplateAttributesSidebar />);
    expect(screen.getByText('Attributes of the user')).toBeInTheDocument();
    expect(screen.getByText('$user.firstname (First name)')).toBeInTheDocument();
    expect(screen.getByText('$settings.platform_url (Platform URL)')).toBeInTheDocument();
  });

  it('hides the variables of the locked user and of the lock without the local authentication lockout', () => {
    testRender(<EmailTemplateAttributesSidebar />);
    expect(screen.queryByText('Attributes of the locked user')).not.toBeInTheDocument();
    expect(screen.queryByText('Attributes of the lock')).not.toBeInTheDocument();
    expect(screen.queryByText(/\$locked_user\./)).not.toBeInTheDocument();
  });

  it('shows the variables of the locked user and of the lock with the local authentication lockout', () => {
    lockoutFlag = true;
    testRender(<EmailTemplateAttributesSidebar />);
    expect(screen.getByText('Attributes of the locked user')).toBeInTheDocument();
    expect(screen.getByText('Attributes of the lock')).toBeInTheDocument();
    ['$locked_user.firstname (First name)', '$locked_user.lastname (Last name)', '$locked_user.name (Name)', '$locked_user.user_email (Email)',
      '$lock.date (Date of the lock)', '$lock.attempts (Failed attempts)', '$lock.type (Temporary or permanent)',
      '$lock.end_date (End of a temporary lock)', '$lock.unlock (When the account is unlocked)',
    ].forEach((variable) => expect(screen.getByText(variable)).toBeInTheDocument());
  });
});
