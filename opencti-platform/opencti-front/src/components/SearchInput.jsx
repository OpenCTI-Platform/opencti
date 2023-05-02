import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import withStyles from '@mui/styles/withStyles';
import TextField from '@mui/material/TextField';
import InputAdornment from '@mui/material/InputAdornment';
import { Search } from '@mui/icons-material';
import { compose } from 'ramda';
import inject18n from './i18n';

const styles = (theme) => ({
  searchRoot: {
    borderRadius: 5,
    padding: '0 10px 0 10px',
    backgroundColor: theme.palette.background.paper,
  },
  searchRootTopBar: {
    borderRadius: 5,
    padding: '1px 10px 0 10px',
    marginRight: 5,
    backgroundColor: theme.palette.background.paper,
  },
  searchRootInDrawer: {
    borderRadius: 5,
    padding: '0 10px 0 10px',
    height: 30,
  },
  searchRootThin: {
    borderRadius: 5,
    padding: '0 10px 0 10px',
    height: 30,
    backgroundColor: theme.palette.background.paper,
  },
  searchRootNoAnimation: {
    borderRadius: 5,
    padding: '0 10px 0 10px',
    backgroundColor: theme.palette.background.default,
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
});

class SearchInput extends Component {
  render() {
    const { t, classes, onChange, onSubmit, variant, keyword, fullWidth } = this.props;
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
    return (
      <TextField
        fullWidth={fullWidth}
        name="keyword"
        defaultValue={keyword}
        variant="outlined"
        size="small"
        placeholder={`${t('Search')}...`}
        onChange={(event) => {
          const { value } = event.target;
          if (typeof onChange === 'function') {
            onChange(value);
          }
        }}
        onKeyPress={(event) => {
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
          classes: {
            root: classRoot,
            input:
              // eslint-disable-next-line no-nested-ternary
              variant === 'small' || variant === 'thin'
                ? classes.searchInputSmall
                : variant !== 'noAnimation'
                  ? classes.searchInput
                  : classes.searchInputNoAnimation,
          },
        }}
        autoComplete="off"
      />
    );
  }
}

SearchInput.propTypes = {
  keyword: PropTypes.string,
  t: PropTypes.func.isRequired,
  classes: PropTypes.object.isRequired,
  onChange: PropTypes.func,
  onSubmit: PropTypes.func,
  variant: PropTypes.string,
  fullWidth: PropTypes.bool,
};

export default compose(inject18n, withStyles(styles))(SearchInput);
