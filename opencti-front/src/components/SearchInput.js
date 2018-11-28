import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { withStyles } from '@material-ui/core/styles';
import Input from '@material-ui/core/Input';
import InputAdornment from '@material-ui/core/InputAdornment';
import { Search } from '@material-ui/icons';
import { compose } from 'ramda';
import inject18n from './i18n';

const styles = theme => ({
  searchInputRoot: {
    borderRadius: 5,
    padding: '0 10px 0 10px',
    backgroundColor: theme.palette.field.background,
  },
  searchInputInput: {
    transition: theme.transitions.create('width'),
    width: 150,
    '&:focus': {
      width: 200,
    },
  },
});

class SearchInput extends Component {
  render() {
    const { t, classes, handleSearch } = this.props;
    return (
      <Input
        name='keyword'
        placeholder={`${t('Search')}...`}
        onChange={handleSearch.bind(this)}
        startAdornment={
          <InputAdornment position='start'>
            <Search/>
          </InputAdornment>
        }
        classes={{ root: classes.searchInputRoot, input: classes.searchInputInput }}
        disableUnderline={true}
      />
    );
  }
}

SearchInput.propTypes = {
  t: PropTypes.func.isRequired,
  classes: PropTypes.object.isRequired,
  handleSearch: PropTypes.func,
  image: PropTypes.string,
};

export default compose(
  inject18n,
  withStyles(styles),
)(SearchInput);
