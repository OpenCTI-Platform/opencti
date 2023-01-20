import React, { Component } from 'react';
import * as R from 'ramda';
import Chip from '@material-ui/core/Chip';
import Add from '@material-ui/icons/Add';
import TextField from '@material-ui/core/TextField';
import IconButton from '@material-ui/core/IconButton';
import inject18n from '../../../../components/i18n';

class ScopeField extends Component {
  constructor(props) {
    super(props);
    this.state = {
      scope: '',
      selectedScope: [...this.props.scopeValue],
    };
  }

  componentDidUpdate() {
    if (this.props.scopeValue.length < this.state.selectedScope.length) {
      this.props.setFieldValue(this.props.name, this.state.selectedScope);
    }
  }

  handleScopeChange(event) {
    this.setState({ scope: event.target.value });
  }

  handleAddScope() {
    const {
      selectedScope,
      scope,
    } = this.state;
    if (!R.includes(scope, selectedScope)) {
      this.setState({ selectedScope: selectedScope.concat(scope), scope: '' });
    }
  }

  handleDelete(field) {
    this.setState({ selectedScope: this.state.selectedScope.filter((value) => value !== field) });
  }

  render() {
    const {
      size,
      style,
      variant,
      containerstyle,
      disabled,
      helperText,
    } = this.props;
    return (
      <>
        <div style={{ display: 'flex', alignItems: 'self-end' }}>
          <TextField
            fullWidth={true}
            containerstyle={containerstyle}
            variant={variant}
            defaultValue={this.state.scope}
            value={this.state.scope}
            onChange={this.handleScopeChange.bind(this)}
            disabled={disabled || false}
            size={size}
            style={style}
            helperText={helperText}
          />
          <IconButton
            disabled={!this.state.scope}
            onClick={this.handleAddScope.bind(this)}
            size='small'
          >
            <Add />
          </IconButton>
        </div>
        <div style={{ marginTop: 15 }}>
          {this.state.selectedScope?.map((scope) => (
            <Chip
              key={scope}
              variant='outlined'
              color='primary'
              label={scope}
              style={{ marginRight: 10 }}
              onDelete={this.handleDelete.bind(this, scope)}
            />
          ))}
        </div>
      </>
    );
  }
}

export default inject18n(ScopeField);
