import { fireEvent, screen } from '@testing-library/react';

// The groups of a bundle start collapsed: opens the ones of the test catalogs, as a user does before reaching their rows
export const expandConfigPresetGroups = () => {
  screen
    .queryAllByRole('button', { name: /^Expand (Platform settings|Data model|Entities) \(\d+\/\d+\)$/ })
    .forEach((button) => fireEvent.click(button));
};
