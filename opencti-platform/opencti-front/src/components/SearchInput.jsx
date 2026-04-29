import React, { useEffect, useState, useCallback } from 'react';
import TextField from '@mui/material/TextField';
import InputAdornment from '@mui/material/InputAdornment';
import { ManageSearchOutlined, Search, TuneOutlined, KeyboardArrowDownOutlined } from '@mui/icons-material';
import { LogoXtmOneIcon } from 'filigran-icon';
import { useNavigate } from 'react-router-dom';
import makeStyles from '@mui/styles/makeStyles';
import Tooltip from '@mui/material/Tooltip';
import { useTheme } from '@mui/styles';
import ToggleButton from '@mui/material/ToggleButton';
import ToggleButtonGroup from '@mui/material/ToggleButtonGroup';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import ListItemText from '@mui/material/ListItemText';
import ListItemIcon from '@mui/material/ListItemIcon';
import CircularProgress from '@mui/material/CircularProgress';
import Stack from '@mui/material/Stack';
import Box from '@mui/material/Box';
import useEnterpriseEdition from '../utils/hooks/useEnterpriseEdition';
import { useFormatter } from './i18n';
import useGranted, { SETTINGS_SETPARAMETERS } from '../utils/hooks/useGranted';
import useAuth from '../utils/hooks/useAuth';
import FiligranIcon from '../private/components/common/FiligranIcon';
import EnterpriseEditionAgreement from '../private/components/common/entreprise_edition/EnterpriseEditionAgreement';
import FeedbackCreation from '../private/components/cases/feedbacks/FeedbackCreation';
import Loader from './Loader';
import useAI from '../utils/hooks/useAI';
import { fetchAgentsForIntent } from '../utils/ai/agentApi';
import { NLQ_INTENT } from '../private/components/common/ai/AINLQ';
import { useChatbot } from '../private/components/chatbox/ChatbotContext';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles((theme) => ({
  searchRoot: {
    borderRadius: 4,
    padding: '0 10px 0 10px',
  },
  searchRootTopBar: {
    borderRadius: 4,
    padding: '1px 10px 0 10px',
    marginRight: 5,
    width: '100%',
  },
  searchRootInDrawer: {
    borderRadius: 4,
    width: '100%',
    minWidth: 100,
    maxWidth: '255px',
  },
  searchRootThin: {
    borderRadius: 4,
    padding: '0 10px 0 10px',
    height: 30,
  },
  searchRootNoAnimation: {
    borderRadius: 4,
    padding: '0 10px 0 10px',
    backgroundColor: theme.palette.background.default,
  },
  searchInputTopBar: {
    width: '100%',
  },
  searchInputInDrawer: {
    width: '100%',
  },
  searchInput: {
    transition: theme.transitions.create('width'),
    width: 200,
    '&:focus': {
      width: 350,
    },
  },
  searchInputSmall: {
    transition: theme.transitions.create('width'),
    width: 150,
    '&:focus': {
      width: 250,
    },
  },
}));

export function GradientBorderTextField({
  isActive,
  ...props
}) {
  const theme = useTheme();

  return (
    <TextField
      {...props}
      variant="outlined"
      sx={{
        '& .MuiInputBase-input::placeholder': {
          opacity: 1,
          color: theme.palette.text.light,
        },
        '& .MuiOutlinedInput-root': {
          position: 'relative',
          borderRadius: 1,
          borderWidth: '1px',
          backgroundColor: theme.palette.background.secondary,
          '& input': {
            height: '19px', // textfield is computing something to make the search equal to 36px
            boxSizing: 'content-box',
          },

          '& fieldset': {
            // default mode without border color
            borderColor: 'transparent',
          },

          '&.Mui-focused:not(:hover) fieldset': {
            // when focus and not hover, prevent default mui change borderwidth
            borderWidth: '1px',
          },

          ...(isActive && {
            '&.Mui-focused:not(:hover) fieldset': {
              // prevent showing the default border when ai mode on and mouse out
              border: `1px solid ${theme.palette.ai.dark}`,
            },

            '&::before': {
              content: '""',
              position: 'absolute',
              inset: 0,
              borderRadius: 'inherit',
              padding: '1px',
              background: `linear-gradient(
                90deg,
                ${theme.palette.ai?.light},
                ${theme.palette.ai?.dark}
              )`,
              WebkitMask:
                'linear-gradient(#fff 0 0) content-box, linear-gradient(#fff 0 0)',
              maskComposite: 'exclude',
              pointerEvents: 'none',
              opacity: 0.8,
            },

            '&:hover fieldset': {
              border: `1px solid ${theme.palette.ai.dark}`,
            },
          }),
        },
      }}
    />
  );
}

// ── Mode constants ─────────────────────────────────────────────────────────
const MODE_SEARCH = 'search';
const MODE_BULK = 'bulk';
// NLQ modes are dynamic: `nlq:<agentSlug>`
const isNlqMode = (mode) => typeof mode === 'string' && mode.startsWith('nlq:');
const nlqSlugFromMode = (mode) => (isNlqMode(mode) ? mode.slice(4) : null);

const SearchInput = (props) => {
  const classes = useStyles();
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

  let classRoot = classes.searchRoot;
  if (variant === 'inDrawer') {
    classRoot = classes.searchRootInDrawer;
  } else if (variant === 'noAnimation') {
    classRoot = classes.searchRootNoAnimation;
  } else if (variant === 'topBar') {
    classRoot = classes.searchRootTopBar;
  } else if (variant === 'thin') {
    classRoot = classes.searchRootThin;
  }
  let classInput = classes.searchInput;
  if (variant === 'small' || variant === 'thin') {
    classInput = classes.searchInputSmall;
  } else if (variant === 'topBar') {
    classInput = classes.searchInputTopBar;
  } else if (variant === 'noAnimation') {
    classInput = classes.searchInputNoAnimation;
  } else if (variant === 'inDrawer') {
    classInput = classes.searchInputInDrawer;
  }

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
      // Navigate to advanced search screen (even if empty)
      if (typeof onSubmit === 'function') {
        onSubmit(searchValue || '', false, undefined);
      }
    } else if (newMode === MODE_BULK) {
      setMode(newMode);
      // Navigate to bulk search screen (even if empty)
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
      <>
        <GradientBorderTextField
          name="keyword"
          value={searchValue}
          variant="outlined"
          size="small"
          placeholder={placeholder}
          onChange={(event) => {
            const { value } = event.target;
            setSearchValue(value);
          }}
          onKeyDown={(event) => {
            const { value } = event.target;
            if (typeof onSubmit === 'function' && event.key === 'Enter') {
              onSubmit(value);
            }
          }}
          isActive={false}
          slotProps={{
            input: {
              startAdornment: (
                <Search fontSize="small" sx={{ mr: 0.5 }} />
              ),
              classes: {
                root: classRoot,
                input: classInput,
              },
            },
          }}
          {...otherProps}
          autoComplete="off"
        />
      </>
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

  const nlqNoAgentAvailable = useXtmOne && nlqAgentsFetched && nlqAgents.length === 0;

  const aiColor = theme.palette.ai?.main;
  const nlqToggleButtonSx = {
    ...toggleButtonSx,
    width: 'auto', // wider than standard because it contains icon + caret
    minWidth: 36,
    px: 1,
    // Always show AI/pink color on the NLQ button — use !important to beat MUI's default ToggleButton color
    color: `${aiColor} !important`,
    '&.Mui-selected': {
      backgroundColor: aiColor ? `${aiColor}24` : undefined,
      color: `${aiColor} !important`,
      borderColor: aiColor,
      '&:hover': {
        backgroundColor: aiColor ? `${aiColor}30` : undefined,
      },
    },
    '&:hover': {
      backgroundColor: aiColor ? `${aiColor}12` : undefined,
    },
    ...(isNLQActivated && {
      backgroundColor: aiColor ? `${aiColor}18` : undefined,
      borderColor: aiColor,
    }),
    // Keep AI/pink color even when disabled (no agents available)
    '&.Mui-disabled': {
      color: `${aiColor} !important`,
      opacity: 0.5,
    },
  };

  return (
    <>
      <Stack
        direction="row"
        alignItems="center"
        spacing={1}
        sx={{ minWidth: 550, width: '50%', maxWidth: 680 }}
      >
        {/* ── Search Input Field (left, fills remaining space) ──── */}
        <GradientBorderTextField
          name="keyword"
          value={searchValue}
          variant="outlined"
          size="small"
          fullWidth
          placeholder={getPlaceholder()}
          onChange={(event) => {
            const { value } = event.target;
            setSearchValue(value);
          }}
          onKeyDown={handleKeyDown}
          isActive={isNLQActivated}
          slotProps={{
            input: {
              startAdornment: (
                <Search
                  fontSize="small"
                  sx={{
                    color: isNLQActivated ? theme.palette.ai.main : 'inherit',
                    mr: 0.5,
                  }}
                />
              ),
              endAdornment: isNLQActivated && isNLQLoading ? (
                <InputAdornment position="end">
                  <Loader variant="inline" />
                </InputAdornment>
              ) : null,
              classes: {
                root: classRoot,
                input: classInput,
              },
            },
          }}
          {...otherProps}
          autoComplete="off"
        />

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

          {/* NLQ split button — icon toggles NLQ, caret opens agent selector */}
          {fullyActive && (
            <Tooltip
              title={nlqNoAgentAvailable
                ? t_i18n('No agent available for this action. Ask your administrator to configure XTM One.')
                : isNLQActivated && selectedAgent
                  ? `${t_i18n('Ask AI')}: ${selectedAgent.name}${selectedAgent.description ? ` — ${selectedAgent.description}` : ''}`
                  : t_i18n('Ask AI')}
            >
              <span>
                <ToggleButton
                  value={mode}
                  selected={isNLQActivated}
                  sx={nlqToggleButtonSx}
                  onClick={handleNlqToggleClick}
                  disabled={nlqNoAgentAvailable}
                >
                  <Stack direction="row" alignItems="center" spacing={0}>
                    <FiligranIcon
                      icon={LogoXtmOneIcon}
                      size="small"
                      color="ai"
                    />
                    {/* Caret click zone — larger hit area with visual separator */}
                    {useXtmOne && nlqAgents.length > 0 && (
                      <Box
                        component="span"
                        sx={{
                          display: 'inline-flex',
                          alignItems: 'center',
                          justifyContent: 'center',
                          ml: 0.5,
                          pl: 0.5,
                          borderLeft: `1px solid ${isNLQActivated ? theme.palette.ai?.main + '40' : theme.palette.divider}`,
                          cursor: 'pointer',
                        }}
                        onClick={(e) => {
                          e.stopPropagation();
                          handleOpenNlqMenu(e);
                        }}
                      >
                        <KeyboardArrowDownOutlined sx={{ fontSize: 18, color: 'inherit' }} />
                      </Box>
                    )}
                  </Stack>
                </ToggleButton>
              </span>
            </Tooltip>
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
                <CircularProgress size={18} />
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
      </Stack>

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
    </>
  );
};

export default SearchInput;
