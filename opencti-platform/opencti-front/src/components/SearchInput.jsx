import React, { useEffect, useState, useCallback } from 'react';
import { SearchField, Spinner } from '@filigran/design-system';
import { ManageSearchOutlined, TuneOutlined, KeyboardArrowDownOutlined } from '@mui/icons-material';
import { LogoXtmOneIcon } from 'filigran-icon';
import { useNavigate } from 'react-router';
import Tooltip from '@mui/material/Tooltip';
import { useTheme } from '@mui/styles';
import ToggleButton from '@mui/material/ToggleButton';
import ToggleButtonGroup from '@mui/material/ToggleButtonGroup';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import ListItemText from '@mui/material/ListItemText';
import ListItemIcon from '@mui/material/ListItemIcon';
import useEnterpriseEdition from '../utils/hooks/useEnterpriseEdition';
import { useFormatter } from './i18n';
import useGranted, { SETTINGS_SETPARAMETERS } from '../utils/hooks/useGranted';
import useAuth from '../utils/hooks/useAuth';
import FiligranIcon from '../private/components/common/FiligranIcon';
import EnterpriseEditionAgreement from '../private/components/common/entreprise_edition/EnterpriseEditionAgreement';
import ValidateTermsOfUseDialog from '../private/components/settings/ValidateTermsOfUseDialog';
import FeedbackCreation from '../private/components/cases/feedbacks/FeedbackCreation';
import Loader from './Loader';
import useAI from '../utils/hooks/useAI';
import { fetchAgentsForIntent } from '../utils/ai/agentApi';
import { NLQ_INTENT } from '../private/components/common/ai/AINLQ';
import { useChatbot } from '../private/components/chatbox/ChatbotContext';
import { hexToRGB } from '../utils/Colors';

const MODE_SEARCH = 'search';
const MODE_BULK = 'bulk';
// NLQ modes are dynamic: `nlq:<agentSlug>`
const isNlqMode = (mode) => typeof mode === 'string' && mode.startsWith('nlq:');
const nlqSlugFromMode = (mode) => (isNlqMode(mode) ? mode.slice(4) : null);

const SIZE_BY_VARIANT = {
  thin: 'sm',
};

const SearchInput = (props) => {
  const navigate = useNavigate();
  const isEnterpriseEdition = useEnterpriseEdition();
  const { enabled, configured, fullyActive } = useAI();
  const { xtmOneConfigured } = useChatbot();
  const useXtmOne = xtmOneConfigured === true;
  const theme = useTheme();
  const { t_i18n } = useFormatter();
  const {
    onSubmit,
    variant,
    keyword,
    placeholder = `${t_i18n('Search these results')}...`,
    isNLQLoading,
    ...otherProps
  } = props;
  const [displayEEDialog, setDisplayEEDialog] = useState(false);
  const [displayCGUDialog, setDisplayCGUDialog] = useState(false);
  const [searchValue, setSearchValue] = useState(keyword);

  // Current mode: 'search', 'bulk', or 'nlq:<slug>'
  const [mode, setMode] = useState(MODE_SEARCH);

  // NLQ agent menu state (for the dropdown arrow on the NLQ toggle)
  const [nlqMenuAnchor, setNlqMenuAnchor] = useState(null);
  const [nlqAgents, setNlqAgents] = useState([]);
  const [nlqAgentsLoading, setNlqAgentsLoading] = useState(false);
  const [nlqAgentsFetched, setNlqAgentsFetched] = useState(false);
  // Track the default agent slug so clicking NLQ toggle auto-selects it
  const [defaultNlqSlug, setDefaultNlqSlug] = useState(null);
  // Shared hover state for the whole split-button: hovering EITHER the
  // icon-toggle zone or the caret zone must tint the entire wrapper as one
  // continuous button (matching the original single-<ToggleButton> look),
  // not just the sub-zone under the pointer.
  const [isNlqSplitHovered, setIsNlqSplitHovered] = useState(false);

  useEffect(() => {
    // Don't sync when in bulk mode: navigating to /search_bulk clears the URL
    // keyword, but we want to keep the user's typed value in the input.
    if (mode !== MODE_BULK && keyword !== searchValue) {
      setSearchValue(keyword);
    }
  }, [keyword]);

  const isAIEnabled = variant === 'topBar' && isEnterpriseEdition && enabled && configured;
  const isNLQActivated = isAIEnabled && isNlqMode(mode);
  const isAdmin = useGranted([SETTINGS_SETPARAMETERS]);
  const { settings: { id: settingsId } } = useAuth();

  // Derive selected agent from mode
  const selectedAgentSlug = nlqSlugFromMode(mode);
  const selectedAgent = nlqAgents.find((a) => a.slug === selectedAgentSlug) ?? null;

  // ── Fetch NLQ agents eagerly on mount when AI is available ──────────────
  const fetchNlqAgentsIfNeeded = useCallback(() => {
    if (!nlqAgentsFetched && !nlqAgentsLoading) {
      setNlqAgentsLoading(true);
      fetchAgentsForIntent(NLQ_INTENT).then((agents) => {
        setNlqAgents(agents);
        setNlqAgentsFetched(true);
        setNlqAgentsLoading(false);
        if (agents.length > 0) {
          setDefaultNlqSlug(agents[0].slug);
        }
      });
    }
  }, [nlqAgentsFetched, nlqAgentsLoading]);

  // Eagerly fetch NLQ agents so the default is ready when the user clicks the toggle
  // Only fetch when XTM One is configured — legacy mode doesn't use agents
  useEffect(() => {
    if (isAIEnabled && fullyActive && useXtmOne) {
      fetchNlqAgentsIfNeeded();
    }
  }, [isAIEnabled, fullyActive, useXtmOne]);

  const handleOpenNlqMenu = useCallback((event) => {
    setNlqMenuAnchor(event.currentTarget);
    fetchNlqAgentsIfNeeded();
  }, [fetchNlqAgentsIfNeeded]);

  const handleCloseNlqMenu = () => {
    setNlqMenuAnchor(null);
  };

  const handleSelectAgent = (agent) => {
    setMode(`nlq:${agent.slug}`);
    handleCloseNlqMenu();
    // Execute NLQ search immediately with the selected agent
    if (searchValue && typeof onSubmit === 'function') {
      onSubmit(searchValue, true, agent.slug);
    }
  };

  // Click on the NLQ toggle: activate NLQ and execute search if there's a value
  const handleNlqToggleClick = useCallback((event) => {
    if (!isAIEnabled) return;
    const isCGUStatusPending = useXtmOne && !fullyActive;
    if (isCGUStatusPending) {
      setDisplayCGUDialog(true);
      return;
    }
    if (isNlqMode(mode)) {
      // Already in NLQ mode — do nothing (user switches away via Search/Bulk toggles)
      return;
    }
    let agentSlug;
    if (useXtmOne && defaultNlqSlug) {
      // XTM One mode — activate with the default agent
      setMode(`nlq:${defaultNlqSlug}`);
      agentSlug = defaultNlqSlug;
    } else if (useXtmOne) {
      // XTM One but agents not loaded yet — open the menu as fallback
      handleOpenNlqMenu(event);
      return;
    } else {
      // Legacy mode — activate NLQ without an agent
      setMode('nlq:');
    }
    // Execute NLQ search immediately if there's a value
    if (searchValue && typeof onSubmit === 'function') {
      onSubmit(searchValue, true, agentSlug || undefined);
    }
  }, [isAIEnabled, mode, useXtmOne, defaultNlqSlug, handleOpenNlqMenu, searchValue, onSubmit]);

  // ── Mode change handler ────────────────────────────────────────────────
  const handleModeChange = (_event, newMode) => {
    if (newMode === null) return; // MUI sends null when clicking the already-selected button
    if (newMode === MODE_SEARCH) {
      setMode(newMode);
      // Execute search immediately with current value
      if (searchValue && typeof onSubmit === 'function') {
        onSubmit(searchValue, false, undefined);
      }
    } else if (newMode === MODE_BULK) {
      setMode(newMode);
      // Navigate to bulk with current value
      const encoded = encodeURIComponent(searchValue || '');
      navigate(`/dashboard/search_bulk${searchValue ? `?q=${encoded}` : ''}`);
    }
    // NLQ is handled via handleNlqToggleClick, not the toggle group
  };

  // ── Compute placeholder ────────────────────────────────────────────────
  const getPlaceholder = () => {
    if (isNLQActivated) {
      return selectedAgent
        ? `${t_i18n('Ask your question')} - ${selectedAgent.name}`
        : `${t_i18n('Ask your question')}...`;
    }
    if (mode === MODE_BULK) {
      return `${t_i18n('One keyword by line or separated by commas')}...`;
    }
    return placeholder;
  };

  // ── Submit handler ─────────────────────────────────────────────────────
  const handleKeyDown = (event) => {
    const { value } = event.target;
    if (typeof onSubmit === 'function' && event.key === 'Enter') {
      if (mode === MODE_BULK) {
        // Navigate to bulk search page with the keyword as a query param
        const encoded = encodeURIComponent(value);
        navigate(`/dashboard/search_bulk${value ? `?q=${encoded}` : ''}`);
      } else {
        // Pass agentSlug only if it's a non-empty string (XTM One mode),
        // otherwise pass undefined so AINLQ falls back to legacy
        onSubmit(value, isNLQActivated, selectedAgentSlug || undefined);
      }
    }
  };

  // ── Non-topBar variant: keep the simple input ──────────────────────────
  if (variant !== 'topBar') {
    return (
      <SearchField
        name="keyword"
        // WCAG 2.5.3: the announced name must contain the visible text, which here is the placeholder.
        aria-label={placeholder}
        size={SIZE_BY_VARIANT[variant] ?? 'md'}
        value={searchValue}
        placeholder={placeholder}
        onChange={(event) => {
          setSearchValue(event.target.value);
        }}
        onSubmit={(value) => {
          if (typeof onSubmit === 'function') {
            onSubmit(value);
          }
        }}
        // The library renders a clear cross only when it can act on one, and clearing has to
        // re-run the search: dropping the keyword locally while leaving the list filtered would
        // be a worse state than before, when there was no cross at all.
        onClear={() => {
          setSearchValue('');
          if (typeof onSubmit === 'function') {
            onSubmit('');
          }
        }}
        // Spread last, exactly as the MUI field did: the three call sites that pass their own onChange drive the
        // value themselves and must keep winning over the internal handler above.
        {...otherProps}
        autoComplete="off"
      />
    );
  }

  // ── TopBar variant: segmented control + search input ───────────────────

  // Styles for toggle buttons — matching the standard IconButton (size="default": 36×36)
  const toggleButtonSx = {
    height: 36,
    minWidth: 36,
    width: 36,
    textTransform: 'none',
    fontSize: '0.875rem',
    fontWeight: 600,
    px: 0,
    py: 0,
    lineHeight: 1,
    borderRadius: 1,
    border: `1px solid ${theme.palette.divider}`,
    '&.Mui-selected': {
      backgroundColor: theme.palette.action.selected,
      color: theme.palette.text.primary,
      borderColor: theme.palette.divider,
      '&:hover': {
        backgroundColor: theme.palette.action.selected,
      },
    },
  };

  const isCGUStatusPending = useXtmOne && !fullyActive;
  const nlqNoAgentAvailable = useXtmOne && nlqAgentsFetched && nlqAgents.length === 0;
  const nlqSplitDisabled = nlqNoAgentAvailable || (isCGUStatusPending && !isAdmin);
  const hasCaret = useXtmOne && nlqAgents.length > 0;

  // Same focus-visible ring color the MuiToggleButtonGroup theme override
  // gives every ToggleButton in this bar (mode-dependent, defined in
  // ThemeDark/ThemeLight) — reproduced here for the caret <button>, which
  // isn't a ToggleButton so doesn't get it for free (see .nlq-split-caret
  // in index.css).
  const nlqCaretFocusRingColor = theme.palette.mode === 'dark' ? '#BDFFED' : '#74E9CA';

  const aiColor = theme.palette.ai?.main;
  // Single source of truth for the split-button's background: both the
  // icon-toggle zone and the caret zone must render the SAME tint at the
  // SAME time (driven by shared hover state, not each zone's own hover).
  // Idle/hover-while-unselected match the tint the app-wide
  // MuiToggleButtonGroup theme override applies to every other button in
  // this control (theme.palette.primary.main alpha). Once in AI mode
  // (selected) AND hovered, the background switches to the AI color instead,
  // so hovering the active AI button reads as distinctly "AI" rather than
  // generic-selected. Both the ToggleButton and the caret <button> have
  // their own background neutralized to transparent so this wrapper
  // background is the only thing visible.
  const nlqSplitBackground = (() => {
    if (nlqSplitDisabled) return 'transparent';
    if (isNLQActivated) {
      return isNlqSplitHovered && aiColor
        ? hexToRGB(aiColor, 0.3)
        : hexToRGB(theme.palette.primary.main, 0.25);
    }
    return isNlqSplitHovered ? hexToRGB(theme.palette.primary.main, 0.15) : 'transparent';
  })();

  return (
    <>
      <div style={{ display: 'flex', flexDirection: 'row', alignItems: 'center', gap: 8, width: '100%' }}>
        {/* ── Search Input Field (left, fills remaining space) ──── */}
        <SearchField
          name="keyword"
          // WCAG 2.5.3: the announced name must contain the visible text, which here is the placeholder.
          aria-label={getPlaceholder()}
          value={searchValue}
          fullWidth
          placeholder={getPlaceholder()}
          onChange={(event) => {
            const { value } = event.target;
            setSearchValue(value);
          }}
          onKeyDown={handleKeyDown}
          onClear={() => setSearchValue('')}
          {...otherProps}
          autoComplete="off"
          label={t_i18n('Search')}
        />
        {/* FDS-WORKAROUND #20: NLQ loading indicator beside the field, SearchField exposes no busy slot — see fds-migration/LIBRARY-FEEDBACK.md #20 */}
        {isNLQActivated && isNLQLoading && <Loader variant="inline" />}

        {/* ── Mode Toggles (right) ────────────────────────────────── */}
        <ToggleButtonGroup
          value={mode}
          exclusive
          onChange={handleModeChange}
          size="small"
          sx={{
            flexShrink: 0,
            // Remove the default grouped border behavior so each button has its own border
            '& .MuiToggleButtonGroup-grouped': {
              border: 'none',
              borderRadius: `${theme.shape.borderRadius}px !important`,
              '&:not(:first-of-type)': {
                marginLeft: 0,
              },
            },
          }}
        >
          {/* Search mode */}
          <Tooltip title={t_i18n('Advanced search')}>
            <ToggleButton value={MODE_SEARCH} sx={{ ...toggleButtonSx, mr: 0.75 }}>
              <TuneOutlined sx={{ fontSize: 18 }} />
            </ToggleButton>
          </Tooltip>

          {/* Bulk mode */}
          <Tooltip title={t_i18n('Bulk search')}>
            <ToggleButton value={MODE_BULK} sx={{ ...toggleButtonSx, mr: 0.75 }}>
              <ManageSearchOutlined sx={{ fontSize: 18 }} />
            </ToggleButton>
          </Tooltip>

          {/* NLQ split button — icon toggles NLQ, caret opens agent selector.
              The icon toggle and the caret are two real, independently
              focusable elements (a <button> cannot validly nest another),
              but they share one background driven by React state so they
              still read, hover, and highlight as a single button, matching
              the rest of the segmented control (no visible outer border). */}
          {isAIEnabled && (
            <span
              onMouseEnter={() => setIsNlqSplitHovered(true)}
              onMouseLeave={() => setIsNlqSplitHovered(false)}
              style={{
                display: 'inline-flex',
                alignItems: 'stretch',
                height: 36,
                borderRadius: theme.shape.borderRadius,
                backgroundColor: nlqSplitBackground,
                // No overflow: hidden here — both zones have their own
                // background/border-radius fully neutralized (transparent,
                // 0), so nothing needs clipping to this wrapper's rounded
                // corners, and clipping would also cut off each zone's
                // focus-visible ring when tabbing through them.
                opacity: nlqSplitDisabled ? 0.5 : 1,
              }}
            >
              <Tooltip
                title={(isCGUStatusPending && !isAdmin)
                  ? t_i18n('Ask Ariane isn\'t activated yet. Please reach out to your administrator to enable this feature.')
                  : nlqNoAgentAvailable
                    ? t_i18n('No agent available for this action. Ask your administrator to configure XTM One.')
                    : isNLQActivated && selectedAgent
                      ? `${t_i18n('Ask AI')}: ${selectedAgent.name}${selectedAgent.description ? ` — ${selectedAgent.description}` : ''}`
                      : t_i18n('Ask AI')}
              >
                <span>
                  <ToggleButton
                    value={mode}
                    selected={isNLQActivated}
                    disableRipple
                    disableFocusRipple
                    sx={{
                      height: '100%',
                      minWidth: 36,
                      width: hasCaret ? 36 : 'auto',
                      px: 1,
                      border: '0 !important',
                      borderRadius: `${theme.shape.borderRadius}px !important`,
                      textTransform: 'none',
                      // Neutralized to transparent (with !important, since
                      // the app-wide MuiToggleButtonGroup theme override
                      // would otherwise tint this zone on its own hover):
                      // the wrapping <span> above is the single source of
                      // truth for the background, so both this zone and the
                      // caret tint/untint together, as one continuous button.
                      backgroundColor: 'transparent !important',
                      color: `${aiColor} !important`,
                      '&.Mui-disabled': { color: `${aiColor} !important` },
                    }}
                    onClick={handleNlqToggleClick}
                    disabled={nlqSplitDisabled}
                  >
                    <FiligranIcon
                      icon={LogoXtmOneIcon}
                      size="small"
                      color="ai"
                    />
                  </ToggleButton>
                </span>
              </Tooltip>
              {hasCaret && (
                <Tooltip title={t_i18n('Choose AI agent')}>
                  <button
                    type="button"
                    aria-label={t_i18n('Choose AI agent')}
                    className="nlq-split-caret"
                    onClick={handleOpenNlqMenu}
                    disabled={nlqSplitDisabled}
                    style={{
                      display: 'inline-flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      paddingLeft: 4,
                      paddingRight: 4,
                      border: 0,
                      borderLeft: `1px solid ${isNLQActivated ? `${aiColor}40` : theme.palette.divider}`,
                      background: 'transparent',
                      color: aiColor,
                      cursor: nlqSplitDisabled ? 'default' : 'pointer',
                      '--nlq-caret-focus-color': nlqCaretFocusRingColor,
                      '--nlq-caret-focus-radius': `${theme.shape.borderRadius}px`,
                    }}
                  >
                    <KeyboardArrowDownOutlined sx={{ fontSize: 18, color: 'inherit' }} />
                  </button>
                </Tooltip>
              )}
            </span>
          )}
        </ToggleButtonGroup>

        {/* ── NLQ Agent dropdown menu ─────────────────────────────── */}
        <Menu
          anchorEl={nlqMenuAnchor}
          open={Boolean(nlqMenuAnchor)}
          onClose={handleCloseNlqMenu}
          slotProps={{
            paper: {
              sx: {
                minWidth: 240,
                maxWidth: 360,
              },
            },
          }}
        >
          {nlqAgentsLoading && (
            <MenuItem disabled>
              <ListItemIcon>
                <Spinner size="md" label={t_i18n('Loading agents...')} />
              </ListItemIcon>
            </MenuItem>
          )}
          {!nlqAgentsLoading && nlqAgents.length === 0 && nlqAgentsFetched && (
            <MenuItem disabled>
              <ListItemText
                primary={t_i18n('No agent available')}
                secondary={t_i18n('No agent available for this action. Ask your administrator to configure XTM One.')}
                slotProps={{ secondary: { sx: { whiteSpace: 'normal' } } }}
              />
            </MenuItem>
          )}
          {!nlqAgentsLoading && nlqAgents.map((agent) => (
            <MenuItem
              key={agent.id}
              onClick={() => handleSelectAgent(agent)}
              selected={selectedAgentSlug === agent.slug}
            >
              <ListItemIcon>
                <FiligranIcon
                  icon={LogoXtmOneIcon}
                  size="small"
                  color="ai"
                />
              </ListItemIcon>
              <ListItemText
                primary={agent.name}
                secondary={agent.description}
                slotProps={{
                  secondary: {
                    sx: {
                      overflow: 'hidden',
                      textOverflow: 'ellipsis',
                      whiteSpace: 'nowrap',
                    },
                  },
                }}
              />
            </MenuItem>
          ))}
        </Menu>
      </div>

      {isAdmin ? (
        <EnterpriseEditionAgreement
          open={displayEEDialog}
          onClose={() => setDisplayEEDialog(false)}
          settingsId={settingsId}
        />
      ) : (
        <FeedbackCreation
          openDrawer={displayEEDialog}
          handleCloseDrawer={() => setDisplayEEDialog(false)}
          initialValue={{
            description: t_i18n('To use this AI feature in the enterprise edition, please add a token.'),
          }}
        />
      )}

      {displayCGUDialog && (
        <ValidateTermsOfUseDialog open={displayCGUDialog} onClose={() => setDisplayCGUDialog(false)} />
      )}
    </>
  );
};

export default SearchInput;
