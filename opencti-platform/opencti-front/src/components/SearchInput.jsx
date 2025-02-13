import React, { useEffect, useState } from 'react';
import TextField from '@mui/material/TextField';
import InputAdornment from '@mui/material/InputAdornment';
import { AutoAwesomeOutlined, BiotechOutlined, ContentPasteSearchOutlined, Search } from '@mui/icons-material';
import IconButton from '@mui/material/IconButton';
import { Link, useLocation } from 'react-router-dom';
import makeStyles from '@mui/styles/makeStyles';
import Tooltip from '@mui/material/Tooltip';
import { useTheme } from '@mui/styles';
import { useFormatter } from './i18n';
import useEnterpriseEdition from '../utils/hooks/useEnterpriseEdition';
import useGranted, { SETTINGS_SETPARAMETERS } from '../utils/hooks/useGranted';
import useAuth from '../utils/hooks/useAuth';
import EnterpriseEditionAgreement from '../private/components/common/entreprise_edition/EnterpriseEditionAgreement';
import FeedbackCreation from '../private/components/cases/feedbacks/FeedbackCreation';
import useHelper from '../utils/hooks/useHelper';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles((theme) => ({
  searchRoot: {
    borderRadius: 4,
    padding: '0 10px 0 10px',
    backgroundColor: theme.palette.background.paper,
  },
  searchRootTopBar: {
    borderRadius: 4,
    padding: '1px 10px 0 10px',
    marginRight: 5,
    backgroundColor: theme.palette.background.paper,
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
    backgroundColor: theme.palette.background.paper,
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
  const theme = useTheme();
  const { t_i18n } = useFormatter();
  const {
    onSubmit,
    variant,
    keyword,
    placeholder = `${t_i18n('Search these results')}...`,
    ...otherProps
  } = props;
  const { isFeatureEnable } = useHelper();
  const isNLQEnabled = isFeatureEnable('NLQ');
  const [displayEEDialog, setDisplayEEDialog] = useState(false);
  const [askAI, setAskAI] = useState(false);
  const handleChangeAskAI = () => {
    if (isEnterpriseEdition) {
      setAskAI(!askAI);
    } else {
      setDisplayEEDialog(true);
    }
  };
  const isAIEnabled = variant === 'topBar' && isEnterpriseEdition && askAI;
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
  const [searchValue, setSearchValue] = useState(keyword);
  useEffect(() => {
    if (keyword !== searchValue) {
      setSearchValue(keyword);
    }
  }, [keyword]);

  return (
    <>
      <TextField
        name="keyword"
        value={searchValue}
        variant="outlined"
        size="small"
        placeholder={isAIEnabled ? `${t_i18n('Ask your question')}...` : placeholder}
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
        sx={isAIEnabled ? {
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
            <InputAdornment position="start" style={{ color: isAIEnabled ? theme.palette.ai.main : undefined }} >
              {isAIEnabled
                ? <AutoAwesomeOutlined fontSize="small" />
                : <Search fontSize="small"/>}
            </InputAdornment>
          ),
          endAdornment: variant === 'topBar' && (
          <InputAdornment position="end">
            <Tooltip title={t_i18n('Advanced search')}>
              <IconButton
                component={Link}
                to="/dashboard/search"
                size="medium"
                color={
                   location.pathname.includes('/dashboard/search')
                    && !location.pathname.includes('/dashboard/search_bulk')
                     ? 'primary'
                     : 'inherit'
                    }
              >
                <BiotechOutlined fontSize='medium'/>
              </IconButton>
            </Tooltip>
            <Tooltip title={t_i18n('Bulk search')}>
              <IconButton
                component={Link}
                to="/dashboard/search_bulk"
                size="medium"
                color={
                location.pathname.includes('/dashboard/search_bulk')
                  ? 'primary'
                  : 'inherit'
              }
              >
                <ContentPasteSearchOutlined fontSize="medium"/>
              </IconButton>
            </Tooltip>
            {isNLQEnabled && <Tooltip title={t_i18n('Ask AI')}>
              <IconButton
                size="medium"
                style={{ color: theme.palette.ai.main }}
                onClick={handleChangeAskAI}
              >
                <AutoAwesomeOutlined fontSize='medium'/>
              </IconButton>
            </Tooltip>}
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
            description: t_i18n('I would like to use a EE feature AI Summary but I don\'t have EE activated.\nI would like to discuss with you about activating EE.'),
          }}
        />
      )}
    </>
  );
};

export default SearchInput;
