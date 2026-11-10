import React from 'react';
import { describe, expect, it } from 'vitest';
import { screen } from '@testing-library/react';
import testRender from '../../../../../utils/tests/test-render';
import ConfigPresetResultLine from './ConfigPresetResultLine';

describe('ConfigPresetResultLine', () => {
  it.each([['CREATED', 'Created'], ['OVERWRITTEN', 'Overwritten'], ['SKIPPED', 'Skipped'], ['FAILED', 'Failed']])('renders the status %s', (status, text) => {
    testRender(<ConfigPresetResultLine label="Banner" status={status} />);
    expect(screen.getByText('Banner')).toBeInTheDocument();
    expect(screen.getByText(text)).toBeInTheDocument();
  });

  it('shows a reason that is not known as the backend returns it', () => {
    testRender(<ConfigPresetResultLine label="Theme" status="FAILED" reason="name: Too small" />);
    expect(screen.getByText('name: Too small')).toBeInTheDocument();
  });

  it.each([
    ['Already exists', 'Already exists'],
    ['Nothing to import', 'Nothing to import'],
    ['Unexpected item id', 'Unexpected item id'],
    ['Unknown message', 'Unknown message'],
    ['The standard id of the theme does not match its id', 'The standard id of the theme does not match its id'],
    ['The standard id of the theme is required to overwrite it', 'The standard id of the theme is required to overwrite it'],
    ['Requires Enterprise Edition', 'Requires Enterprise Edition'],
    ['Built-in theme', 'Built-in theme'],
    ['Theme already exists', 'Theme already exists'],
    ['Theme name already exists', 'Theme name already exists'],
    ['Added as "Dark (1)"', 'Added as "Dark (1)"'],
    ['Default theme Dark could not be imported', 'Default theme Dark could not be imported'],
    ['Entity types that cannot be hidden: Foo, Bar', 'Entity types that cannot be hidden: Foo, Bar'],
    ['Entity types shown again: Channel, Report', 'Entity types shown again: Channel, Report'],
    ['The standard id of the role does not match its name', 'The standard id of the role does not match its name'],
    ['Role already exists', 'Role already exists'],
    ['Role name already exists', 'Role name already exists'],
    ['The Administrator role keeps the bypass capability', 'The Administrator role keeps the bypass capability'],
    ['Grants sensitive rights', 'Grants sensitive rights'],
    ['Unknown capabilities: FOO, BAR', 'Unknown capabilities: FOO, BAR'],
    ['Capabilities not available in draft: SETTINGS_SETACCESSES', 'Capabilities not available in draft: SETTINGS_SETACCESSES'],
    ['The standard id of the group does not match its name', 'The standard id of the group does not match its name'],
    ['Group already exists', 'Group already exists'],
    ['Group name already exists', 'Group name already exists'],
    ['New users join this group automatically', 'New users join this group automatically'],
    ['New integration users join this group automatically', 'New integration users join this group automatically'],
    ['Roles could not be imported: Analyst', 'Roles could not be imported: Analyst'],
    ['Markings not found: TLP:AMBER, PAP:RED', 'Markings not found: TLP:AMBER, PAP:RED'],
    ['Default dashboard not found: SOC overview', 'Default dashboard not found: SOC overview'],
    ['Roles removed: Hunter', 'Roles removed: Hunter'],
    ['Markings removed: PAP:RED', 'Markings removed: PAP:RED'],
    ['Capabilities removed: EXPLORE', 'Capabilities removed: EXPLORE'],
    ['Capabilities in draft removed: KNOWLEDGE_KNUPDATE', 'Capabilities in draft removed: KNOWLEDGE_KNUPDATE'],
    ['The main organization requires the Enterprise Edition', 'The main organization requires the Enterprise Edition'],
    ['Main organization not found: Filigran', 'Main organization not found: Filigran'],
    ['Requires the right to manage the sensitive configuration', 'Requires the right to manage the sensitive configuration'],
    ['The Administrators group keeps the Administrator role', 'The Administrators group keeps the Administrator role'],
    ['Removes sensitive rights', 'Removes sensitive rights'],
    ['Shareable markings not allowed by the group: TLP:RED', 'Shareable markings not allowed by the group: TLP:RED'],
    ['Built-in marking', 'Built-in marking'],
    ['The order of the marking changes', 'The order of the marking changes'],
    ['Groups that get new markings automatically get this one', 'Groups that get new markings automatically get this one'],
    ['Sets the main organization: Filigran', 'Sets the main organization: Filigran'],
    ["The expiration date of the users' passwords changes", "The expiration date of the users' passwords changes"],
    ["The users' passwords no longer expire", "The users' passwords no longer expire"],
    ['Users can view the users of other organizations', 'Users can view the users of other organizations'],
    ['Fewer recent passwords are kept: users can reuse the oldest ones', 'Fewer recent passwords are kept: users can reuse the oldest ones'],
    ['Recent passwords are no longer kept: users can reuse them', 'Recent passwords are no longer kept: users can reuse them'],
    ['The reuse of recent passwords cannot be blocked on this platform', 'The reuse of recent passwords cannot be blocked on this platform'],
  ])('translates the reason %s', (reason, text) => {
    testRender(<ConfigPresetResultLine label="Theme" status="SKIPPED" reason={reason} />);
    expect(screen.getByText(text)).toBeInTheDocument();
  });

  it('translates each reason of an item that has several, and shows them on one line', () => {
    testRender(<ConfigPresetResultLine label="Group" status="CREATED" reason={'Added as "SOC (1)"\nMarkings not found: PAP:RED'} />);
    expect(screen.getByText('Added as "SOC (1)" · Markings not found: PAP:RED')).toBeInTheDocument();
  });

  it('says an item the platform has already as it is, without a status that would read as if it was ignored', () => {
    testRender(<ConfigPresetResultLine label="Banner" status="SKIPPED" reason="Already up to date" code="unchanged" />);
    expect(screen.getByText('Banner')).toBeInTheDocument();
    expect(screen.getByText('Already up to date')).toBeInTheDocument();
    expect(screen.queryByText('Skipped')).not.toBeInTheDocument();
  });

  it('keeps the status of a skipped item that is not unchanged, whatever its reason says', () => {
    testRender(<ConfigPresetResultLine label="Banner" status="SKIPPED" reason="Already up to date" code="not_overwrite" />);
    expect(screen.getByText('Skipped')).toBeInTheDocument();
  });

  it('shows an unknown status as is, and no reason when there is none', () => {
    testRender(<ConfigPresetResultLine label="Item" status="SOMETHING" reason={null} />);
    expect(screen.getByText('SOMETHING')).toBeInTheDocument();
  });
});
