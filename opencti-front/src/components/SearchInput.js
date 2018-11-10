import React, {Component} from 'react'
import PropTypes from 'prop-types'
import {injectIntl} from 'react-intl'
import {withStyles} from '@material-ui/core/styles'
import Input from '@material-ui/core/Input'
import InputAdornment from '@material-ui/core/InputAdornment'
import {Search} from '@material-ui/icons'

const styles = theme => ({
  searchInputRoot: {
    borderRadius: 5,
    padding: '0 10px 0 10px',
    backgroundColor: theme.palette.field.background
  },
  searchInputInput: {
    transition: theme.transitions.create('width'),
    width: 150,
    '&:focus': {
      width: 200,
    }
  }
})

class SearchInput extends Component {
  render() {
    const {intl, classes, handleSearch} = this.props
    return (
      <Input
        name='keyword'
        placeholder={intl.formatMessage({id: 'Search'}) + '...'}
        onChange={handleSearch.bind(this)}
        startAdornment={
          <InputAdornment position='start'>
            <Search/>
          </InputAdornment>
        }
        classes={{root: classes.searchInputRoot, input: classes.searchInputInput}}
        disableUnderline={true}
      />
    )
  }
}

SearchInput.propTypes = {
  intl: PropTypes.object.isRequired,
  classes: PropTypes.object.isRequired,
  handleSearch: PropTypes.func,
  image: PropTypes.string,
}

export default injectIntl(withStyles(styles)(SearchInput))