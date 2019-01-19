import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { withStyles } from '@material-ui/core/styles';
import Input from '@material-ui/core/Input';
import InputAdornment from '@material-ui/core/InputAdornment';
import { Search } from '@material-ui/icons';
import { compose } from 'ramda';
import inject18n from './i18n';

const styles = theme => ({
  searchRoot: {
    borderRadius: 5,
    padding: '0 10px 0 10px',
    backgroundColor: theme.palette.field.background,
  },
  searchRootInDrawer: {
    borderRadius: 5,
    padding: '0 10px 0 10px',
    backgroundColor: theme.palette.navAlt.background,
  },
  searchInput: {
    transition: theme.transitions.create('width'),
    width: 250,
    '&:focus': {
      width: 350,
    },
  },
});

class SearchInput extends Component {
  render() {
    const {
      t, classes, onChange, onSubmit, variant,
    } = this.props;
    return (
      <Input
        name='keyword'
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
        startAdornment={
          <InputAdornment position='start'>
            <Search/>
          </InputAdornment>
        }
        classes={{ root: variant === 'inDrawer' ? classes.searchRootInDrawer : classes.searchRoot, input: classes.searchInput }}
        disableUnderline={true}
      />
    );
  }
}

SearchInput.propTypes = {
  t: PropTypes.func.isRequired,
  classes: PropTypes.object.isRequired,
  onChange: PropTypes.func,
  onSubmit: PropTypes.func,
  variant: PropTypes.string,
};

export default compose(
  inject18n,
  withStyles(styles),
)(SearchInput);
