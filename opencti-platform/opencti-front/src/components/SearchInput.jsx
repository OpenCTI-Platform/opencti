import React, { useEffect, useState } from 'react';
import TextField from '@mui/material/TextField';
import InputAdornment from '@mui/material/InputAdornment';
import { BiotechOutlined, ContentPasteSearchOutlined, Search } from '@mui/icons-material';
import IconButton from '@mui/material/IconButton';
import { Link, useLocation } from 'react-router-dom';
import makeStyles from '@mui/styles/makeStyles';
import Tooltip from '@mui/material/Tooltip';
import { useFormatter } from './i18n';

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
  const { t_i18n } = useFormatter();
  const {
    onSubmit,
    variant,
    keyword,
    placeholder = `${t_i18n('Search these results')}...`,
    ...otherProps
  } = props;
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
    <TextField
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
      InputProps={{
        startAdornment: (
          <InputAdornment position="start">
            <Search fontSize="small" />
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
  );
};

export default SearchInput;
