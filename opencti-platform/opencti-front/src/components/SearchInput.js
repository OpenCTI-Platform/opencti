import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { withStyles } from '@material-ui/core/styles';
import Input from '@material-ui/core/Input';
import InputAdornment from '@material-ui/core/InputAdornment';
import { Search } from '@material-ui/icons';
import { compose } from 'ramda';
import inject18n from './i18n';

const styles = (theme) => ({
  searchRoot: {
    borderRadius: 5,
    padding: '0 10px 0 10px',
    backgroundColor: theme.palette.background.paper,
  },
  searchRootInDrawer: {
    borderRadius: 5,
    padding: '0 10px 0 10px',
    backgroundColor: theme.palette.navAlt.background,
  },
  searchRootInDrawer2: {
    borderRadius: 5,
    padding: '0 10px 0 10px',
    backgroundColor:
      theme.palette.type === 'light'
        ? theme.palette.background.paperLight
        : theme.palette.navAlt.background,
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
    const {
      t, classes, onChange, onSubmit, variant, keyword, fullWidth,
    } = this.props;
    let classRoot = classes.searchRoot;
    if (variant === 'inDrawer') {
      classRoot = classes.searchRootInDrawer;
    } else if (variant === 'inDrawer2') {
      classRoot = classes.searchRootInDrawer2;
    } else if (variant === 'noAnimation') {
      classRoot = classes.searchRootNoAnimation;
    }
    return (
      <Input
        fullWidth={fullWidth}
        name="keyword"
        defaultValue={keyword}
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
        endAdornment={
          <InputAdornment position="start">
            <Search fontSize="inherit" />
          </InputAdornment>
        }
        classes={{
          root: classRoot,
          input:
            // eslint-disable-next-line no-nested-ternary
            variant === 'small'
              ? classes.searchInputSmall
              : variant !== 'noAnimation'
                ? classes.searchInput
                : classes.searchInputNoAnimation,
        }}
        disableUnderline={true}
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
