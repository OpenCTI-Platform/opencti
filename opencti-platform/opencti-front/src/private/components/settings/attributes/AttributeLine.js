/* eslint-disable no-underscore-dangle,no-nested-ternary */
// TODO Remove no-nested-ternary
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import ListItemSecondaryAction from '@material-ui/core/ListItemSecondaryAction';
import { withStyles } from '@material-ui/core/styles';
import { ShortText } from '@material-ui/icons';
import { compose } from 'ramda';
import inject18n from '../../../../components/i18n';
import AttributePopover from './AttributePopover';

const styles = theme => ({
  icon: {
    color: theme.palette.primary.main,
  },
});

class AttributeLineComponent extends Component {
  render() {
    const { attribute, classes, paginationOptions } = this.props;
    return (
      <ListItem key={attribute.value} divider={true} button={true}>
        <ListItemIcon classes={{ root: classes.icon }}>
          <ShortText />
        </ListItemIcon>
        <ListItemText primary={attribute.value} />
        <ListItemSecondaryAction>
          <AttributePopover
            attributeId={attribute.id}
            paginationOptions={paginationOptions}
          />
        </ListItemSecondaryAction>
      </ListItem>
    );
  }
}

AttributeLineComponent.propTypes = {
  classes: PropTypes.object,
  paginationOptions: PropTypes.object,
  t: PropTypes.func,
  attribute: PropTypes.object,
};

const AttributeLineFragment = createFragmentContainer(AttributeLineComponent, {
  attribute: graphql`
    fragment AttributeLine_attribute on Attribute {
      id
      type
      value
    }
  `,
});

export default compose(
  inject18n,
  withStyles(styles),
)(AttributeLineFragment);
