import React, { useState } from 'react';
import { Input, Text } from '@filigran/design-system';
import Button from '@common/button/Button';
import { Stack } from '@mui/material';
import { useTheme } from '@mui/material/styles';
import { useFormatter } from '../../../components/i18n';
import useSearchShortcut, { writeSearchShortcut } from '../../../utils/hooks/useSearchShortcut';
import { DEFAULT_SEARCH_SHORTCUT, formatSearchShortcut, SearchShortcut, searchShortcutFromEvent } from '../../../utils/searchShortcut';

const LABEL_ID = 'search-shortcut-label';

// "User experience" setting: the keyboard shortcut focusing the top bar search. Kept in this browser only.
// The label and the message sit outside the row, so the buttons center on the input box alone.
const ProfileSearchShortcut = () => {
  const { t_i18n } = useFormatter();
  const theme = useTheme();
  const shortcut = useSearchShortcut();
  const [refused, setRefused] = useState(false);
  const isDefault = shortcut !== null && formatSearchShortcut(shortcut) === formatSearchShortcut(DEFAULT_SEARCH_SHORTCUT);

  // The field records the next key combination instead of typing text.
  const handleKeyDown = (event: React.KeyboardEvent<HTMLInputElement>) => {
    if (event.key === 'Tab' || event.isComposing) return; // leaving the field stays possible from the keyboard
    event.preventDefault(); // also keeps the global shortcut from reacting to the key being recorded
    const next = searchShortcutFromEvent(event);
    setRefused(next === null);
    if (next) writeSearchShortcut(next);
  };

  const choose = (next: SearchShortcut | null) => {
    setRefused(false);
    writeSearchShortcut(next);
  };

  return (
    <div style={{ marginTop: 20 }}>
      <Text id={LABEL_ID} variant="content-compact-medium" as="div" style={{ marginBottom: 6 }}>
        {t_i18n('Search shortcut')}
      </Text>
      <Stack direction="row" spacing={1} sx={{ alignItems: 'center' }}>
        <div style={{ flex: 1 }}>
          <Input
            aria-labelledby={LABEL_ID}
            value={shortcut ? formatSearchShortcut(shortcut) : ''}
            placeholder={t_i18n('Disabled')}
            onChange={() => undefined}
            onKeyDown={handleKeyDown}
            onBlur={() => setRefused(false)}
            autoComplete="off"
            readOnly
          />
        </div>
        {!isDefault && (
          <Button variant="secondary" onClick={() => choose(DEFAULT_SEARCH_SHORTCUT)}>
            {t_i18n('Reset')}
          </Button>
        )}
        {shortcut && (
          <Button variant="secondary" onClick={() => choose(null)}>
            {t_i18n('Disable')}
          </Button>
        )}
      </Stack>
      <Text
        variant="content-caption"
        as="p"
        role={refused ? 'alert' : undefined}
        style={{ margin: '6px 0 0', color: refused ? theme.palette.error.main : undefined }}
      >
        {refused
          ? t_i18n('This key combination cannot be used. Try a symbol such as /, or add Ctrl / Command.')
          : t_i18n('Press the keys you want to use to focus the search bar')}
      </Text>
    </div>
  );
};

export default ProfileSearchShortcut;
