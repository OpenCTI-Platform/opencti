import React from 'react';
import { useTheme } from '@mui/styles';
import Box from '@mui/material/Box';
import Typography from '@mui/material/Typography';
import Button from '@mui/material/Button';
import Chip from '@mui/material/Chip';
import Tooltip from '@mui/material/Tooltip';
import Divider from '@mui/material/Divider';
import { DoNotDisturbOnOutlined, OpenInNew } from '@mui/icons-material';
import Link from '@mui/material/Link';
import type { Theme } from '../../Theme';
import { useFormatter } from '../../i18n';

export type EnhancedSearchMode = 'fuzzy' | 'wildcard' | 'fuzzy+wildcard' | null;

/**
 * Determines what the search string would become with a given mode applied.
 */
export const applySearchMode = (rawSearch: string, mode: EnhancedSearchMode): string => {
  if (!rawSearch || !mode) return rawSearch;

  // Strip previous mode markers before reapplying
  const stripped = rawSearch
    .split(' ')
    .map((w) => w.replace(/^(\*?)(.+?)(\*?)~?$/g, '$2'))
    .join(' ');

  switch (mode) {
    case 'fuzzy':
      return stripped.split(' ').map((w) => `${w}~`).join(' ');
    case 'wildcard':
      return stripped.split(' ').map((w) => `*${w}*`).join(' ');
    case 'fuzzy+wildcard':
      return stripped.split(' ').map((w) => `*${w}*~`).join(' ');
    default:
      return stripped;
  }
};

/**
 * Strips all fuzzy (~) and wildcard (*) markers from a search string
 * to recover the original user input.
 */
export const stripSearchMode = (search: string): string => {
  return search
    .split(' ')
    .map((w) => w.replace(/^(\*?)(.+?)(\*?)~?$/g, '$2'))
    .join(' ');
};

/**
 * Detects the current enhanced search mode from the search string.
 */
export const detectSearchMode = (search: string): EnhancedSearchMode => {
  if (!search) return null;
  const words = search.trim().split(' ').filter(Boolean);
  if (words.length === 0) return null;

  const hasFuzzy = words.every((w) => w.endsWith('~'));
  const hasWildcard = words.every((w) => {
    const base = w.replace(/~$/, '');
    return base.startsWith('*') && base.endsWith('*') && base.length > 2;
  });

  if (hasFuzzy && hasWildcard) return 'fuzzy+wildcard';
  if (hasFuzzy) return 'fuzzy';
  if (hasWildcard) return 'wildcard';
  return null;
};

interface EnhancedSearchSuggestionsProps {
  searchTerm: string;
  activeMode: EnhancedSearchMode;
  onApplyMode: (mode: EnhancedSearchMode) => void;
}

/**
 * Component displayed when a search returns no results and the IMPROVED_SEARCH
 * feature flag is enabled. It suggests fuzzy and wildcard search options.
 */
const EnhancedSearchSuggestions = ({
  searchTerm,
  activeMode,
  onApplyMode,
}: EnhancedSearchSuggestionsProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();

  const rawTerm = stripSearchMode(searchTerm);

  // Determine which suggestions to show depending on the currently active mode
  const renderSuggestions = () => {
    if (!activeMode) {
      // Screen 2: No mode active — suggest both options
      return (
        <>
          <Typography variant="body2" sx={{ mb: 2, color: theme.palette.text.secondary }}>
            {t_i18n('Try an enhanced search')}:
          </Typography>
          <Box sx={{ display: 'flex', gap: 2, justifyContent: 'center', flexWrap: 'wrap' }}>
            <Tooltip
              title={t_i18n('Finds results similar to your query, even with typos or slight variations.')}
            >
              <Button
                variant="outlined"
                size="small"
                onClick={() => onApplyMode('fuzzy')}
                sx={{ textTransform: 'none' }}
              >
                ~ {t_i18n('Fuzzy search')}
              </Button>
            </Tooltip>
            <Tooltip
              title={t_i18n('Automatically adds * before and after each word to match partial terms.')}
            >
              <Button
                variant="outlined"
                size="small"
                onClick={() => onApplyMode('wildcard')}
                sx={{ textTransform: 'none' }}
              >
                * {t_i18n('Wildcard search')}
              </Button>
            </Tooltip>
          </Box>
        </>
      );
    }

    if (activeMode === 'fuzzy') {
      // Screen 4: Fuzzy active but still no results — suggest combining
      return (
        <>
          <Typography variant="body2" sx={{ mb: 2, color: theme.palette.text.secondary }}>
            {t_i18n('Try combining options')}:
          </Typography>
          <Box sx={{ display: 'flex', gap: 2, justifyContent: 'center' }}>
            <Tooltip
              title={t_i18n('Combines fuzzy matching with wildcard to maximize results.')}
            >
              <Button
                variant="outlined"
                size="small"
                onClick={() => onApplyMode('fuzzy+wildcard')}
                sx={{ textTransform: 'none' }}
              >
                ~ {t_i18n('Fuzzy')} + * {t_i18n('Wildcard search')}
              </Button>
            </Tooltip>
          </Box>
        </>
      );
    }

    if (activeMode === 'wildcard') {
      // Wildcard active but still no results — suggest combining
      return (
        <>
          <Typography variant="body2" sx={{ mb: 2, color: theme.palette.text.secondary }}>
            {t_i18n('Try combining options')}:
          </Typography>
          <Box sx={{ display: 'flex', gap: 2, justifyContent: 'center' }}>
            <Tooltip
              title={t_i18n('Combines fuzzy matching with wildcard to maximize results.')}
            >
              <Button
                variant="outlined"
                size="small"
                onClick={() => onApplyMode('fuzzy+wildcard')}
                sx={{ textTransform: 'none' }}
              >
                ~ {t_i18n('Fuzzy')} + * {t_i18n('Wildcard search')}
              </Button>
            </Tooltip>
          </Box>
        </>
      );
    }

    // fuzzy+wildcard active and still no results — no more suggestions
    return null;
  };

  const suggestions = renderSuggestions();

  return (
    <Box
      sx={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        py: 6,
        px: 2,
        width: '100%',
      }}
    >
      {/* No results message */}
      <DoNotDisturbOnOutlined sx={{ fontSize: 40, color: theme.palette.text.disabled, mb: 1 }} />
      <Typography variant="h6" sx={{ color: theme.palette.text.secondary, mb: 0.5 }}>
        {t_i18n('No results for')} &quot;{rawTerm}&quot;
      </Typography>
      {activeMode && (
        <Typography variant="body2" sx={{ color: theme.palette.text.disabled, mb: 1 }}>
          {activeMode === 'fuzzy' && t_i18n('even with fuzzy matching enabled.')}
          {activeMode === 'wildcard' && t_i18n('even with wildcard matching enabled.')}
          {activeMode === 'fuzzy+wildcard' && t_i18n('even with fuzzy and wildcard matching enabled.')}
        </Typography>
      )}

      {/* Suggestions */}
      {suggestions && (
        <>
          <Divider sx={{ width: '60%', my: 3 }} />
          {suggestions}
        </>
      )}

      {/* Learn more link */}
      <Divider sx={{ width: '60%', my: 3 }} />
      <Link
        href="https://docs.opencti.io/latest/usage/search/"
        target="_blank"
        rel="noopener noreferrer"
        underline="hover"
        sx={{
          display: 'flex',
          alignItems: 'center',
          gap: 0.5,
          color: theme.palette.text.secondary,
        }}
      >
        📖 {t_i18n('Learn more about search options')}
        <OpenInNew sx={{ fontSize: 14 }} />
      </Link>
    </Box>
  );
};

export default EnhancedSearchSuggestions;

/**
 * Active mode badge displayed in the search area when an enhanced search mode is active.
 */
export const EnhancedSearchBadge = ({
  mode,
  onClear,
}: { mode: EnhancedSearchMode; onClear: () => void }) => {
  const { t_i18n } = useFormatter();
  if (!mode) return null;

  const labels: Record<string, string> = {
    fuzzy: `~ ${t_i18n('Fuzzy')}`,
    wildcard: `* ${t_i18n('Wildcard')}`,
    'fuzzy+wildcard': `~ ${t_i18n('Fuzzy')} + * ${t_i18n('Wildcard')}`,
  };

  const tooltips: Record<string, string> = {
    fuzzy: t_i18n('Results found using fuzzy matching. Your query was interpreted with approximate matching.'),
    wildcard: t_i18n('Results found using wildcard matching. Your query was interpreted with partial matching.'),
    'fuzzy+wildcard': t_i18n('Results found using fuzzy and wildcard matching.'),
  };

  return (
    <Tooltip title={tooltips[mode]}>
      <Chip
        label={labels[mode]}
        size="small"
        variant="outlined"
        color="primary"
        onDelete={onClear}
        sx={{ ml: 1, height: 24 }}
      />
    </Tooltip>
  );
};
