import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Typography from '@material-ui/core/Typography';
import IconButton from '@material-ui/core/IconButton';
import { Close } from '@material-ui/icons';
import graphql from 'babel-plugin-relay/macro';
import { createFragmentContainer } from 'react-relay';
import inject18n from '../../../../components/i18n';
import AttributeEditionOverview from './AttributeEditionOverview';

const styles = theme => ({
  header: {
    backgroundColor: theme.palette.navAlt.backgroundHeader,
    padding: '20px 20px 20px 60px',
  },
  closeButton: {
    position: 'absolute',
    top: 12,
    left: 5,
  },
  importButton: {
    position: 'absolute',
    top: 15,
    right: 20,
  },
  container: {
    padding: '10px 20px 20px 20px',
  },
  title: {
    float: 'left',
  },
});

class AttributeEdition extends Component {
  render() {
    const {
      t, classes, paginationOptions, handleClose,
    } = this.props;
    return (
      <div>
        <div className={classes.header}>
          <IconButton
            aria-label="Close"
            className={classes.closeButton}
            onClick={handleClose.bind(this)}
          >
            <Close fontSize="small" />
          </IconButton>
          <Typography variant="h6" classes={{ root: classes.title }}>
            {t('Update an attribute')}
          </Typography>
          <div className="clearfix" />
        </div>
        <div className={classes.container}>
          <AttributeEditionOverview
            attribute={this.props.attribute}
            paginationOptions={paginationOptions}
            handleClose={handleClose.bind(this)}
          />
        </div>
      </div>
    );
  }
}

AttributeEdition.propTypes = {
  paginationOptions: PropTypes.object,
  attribute: PropTypes.object,
  handleClose: PropTypes.func,
  classes: PropTypes.object,
  group: PropTypes.object,
  me: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
};

const AttributeEditionFragment = createFragmentContainer(AttributeEdition, {
  attribute: graphql`
    fragment AttributeEdition_attribute on Attribute {
      id
      ...AttributeEditionOverview_attribute
    }
  `,
});
export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(AttributeEditionFragment);
