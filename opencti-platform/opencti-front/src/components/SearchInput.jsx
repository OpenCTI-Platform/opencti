import React, { useEffect, useState } from 'react';
import TextField from '@mui/material/TextField';
import InputAdornment from '@mui/material/InputAdornment';
import { BiotechOutlined, ContentPasteSearchOutlined, Search } from '@mui/icons-material';
import { LogoXtmOneIcon } from 'filigran-icon';
import IconButton from '@mui/material/IconButton';
import { Link, useLocation } from 'react-router-dom';
import makeStyles from '@mui/styles/makeStyles';
import Tooltip from '@mui/material/Tooltip';
import { useTheme } from '@mui/styles';
import useEnterpriseEdition from '../utils/hooks/useEnterpriseEdition';
import EETooltip from '../private/components/common/entreprise_edition/EETooltip';
import { useFormatter } from './i18n';
import useGranted, { SETTINGS_SETPARAMETERS } from '../utils/hooks/useGranted';
import useAuth from '../utils/hooks/useAuth';
import FiligranIcon from '../private/components/common/FiligranIcon';
import EnterpriseEditionAgreement from '../private/components/common/entreprise_edition/EnterpriseEditionAgreement';
import FeedbackCreation from '../private/components/cases/feedbacks/FeedbackCreation';
import Loader from './Loader';
import useAI from '../utils/hooks/useAI';

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
    minWidth: 550,
    width: '50%',
  },
  searchRootInDrawer: {
    borderRadius: 4,
    padding: '0 10px 0 10px',
    height: 30,
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

const SearchInput = (props) => {
  const classes = useStyles();
  const location = useLocation();
  const isEnterpriseEdition = useEnterpriseEdition();
  const { enabled, configured, fullyActive } = useAI();
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
  const [askAI, setAskAI] = useState(false);

  useEffect(() => {
    if (keyword !== searchValue) {
      setSearchValue(keyword);
    }
  }, [keyword]);

  const isAIEnabled = variant === 'topBar' && isEnterpriseEdition && enabled && configured;
  const isNLQActivated = isAIEnabled && askAI;
  const isAdmin = useGranted([SETTINGS_SETPARAMETERS]);
  const { settings: { id: settingsId } } = useAuth();

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
  }

  const handleChangeAskAI = () => {
    if (!askAI && searchValue && searchValue.length > 0) {
      onSubmit(searchValue, true);
      setAskAI(true);
    }
    setAskAI(!askAI);
  };
  const handleRemoveAskAI = () => {
    if (askAI) {
      setAskAI(false);
    }
  };

  return (
    <>
      <TextField
        name="keyword"
        value={searchValue}
        variant="outlined"
        size="small"
        placeholder={isNLQActivated ? `${t_i18n('Ask your question')}...` : placeholder}
        onChange={(event) => {
          const { value } = event.target;
          setSearchValue(value);
        }}
        onKeyDown={(event) => {
          const { value } = event.target;
          if (typeof onSubmit === 'function' && event.key === 'Enter') {
            onSubmit(value, isNLQActivated);
          }
        }}
        sx={isNLQActivated ? {
          borderColor: 'red',
          '& .MuiOutlinedInput-root': {
            '& fieldset': {
              borderColor: theme.palette.ai.main,
              borderWidth: '2px',
            },
            '&:hover fieldset': {
              borderColor: theme.palette.ai.main,
              borderWidth: '2px',
            },
          },
        } : undefined}
        InputProps={{
          startAdornment: (
            <InputAdornment position="start" style={{ color: isNLQActivated ? theme.palette.ai.main : undefined }}>
              {isNLQActivated
                ? <FiligranIcon icon={LogoXtmOneIcon} size="medium" color="ai" />
                : <Search fontSize="small" />}
            </InputAdornment>
          ),
          endAdornment: variant === 'topBar' && (
            <InputAdornment position="end">
              {isNLQActivated && isNLQLoading
                && (
                  <div>
                    <Loader variant="inline" />
                  </div>
                )
              }
              <Tooltip title={t_i18n('Advanced search')}>
                <IconButton
                  onClick={handleRemoveAskAI}
                  component={Link}
                  to="/dashboard/search"
                  size="medium"
                  color={
                    location.pathname.includes('/dashboard/search')
                    && !location.pathname.includes('/dashboard/search_bulk')
                    && !isNLQActivated ? 'primary' : 'inherit'
                  }
                >
                  <BiotechOutlined fontSize="medium" />
                </IconButton>
              </Tooltip>
              <Tooltip title={t_i18n('Bulk search')}>
                <IconButton
                  onClick={handleRemoveAskAI}
                  component={Link}
                  to="/dashboard/search_bulk"
                  size="medium"
                  color={
                    location.pathname.includes('/dashboard/search_bulk') && !isNLQActivated
                      ? 'primary'
                      : 'inherit'
                  }
                >
                  <ContentPasteSearchOutlined fontSize="medium" />
                </IconButton>
              </Tooltip>
              {fullyActive && (
                <EETooltip forAi={true} title={t_i18n('Ask AI')}>
                  <IconButton
                    size="medium"
                    style={{ color: theme.palette.ai.main }}
                    onClick={isAIEnabled ? handleChangeAskAI : null}
                  >
                    <FiligranIcon icon={LogoXtmOneIcon} size="medium" color="ai" />
                  </IconButton>
                </EETooltip>
              )}
            </InputAdornment>
          ),
          classes: {
            root: classRoot,
            input: classInput,
          },
        }}
        {...otherProps}
        autoComplete="off"
      />
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
