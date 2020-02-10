import React, { Component } from 'react';
import PropTypes from 'prop-types';
import graphql from 'babel-plugin-relay/macro';
import { createFragmentContainer } from 'react-relay';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Typography from '@material-ui/core/Typography';
import IconButton from '@material-ui/core/IconButton';
import { Close } from '@material-ui/icons';
import inject18n from '../../../../components/i18n';
import { SubscriptionAvatars } from '../../../../components/Subscription';
import StixObservableEditionOverview from './StixObservableEditionOverview';

const styles = (theme) => ({
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
  appBar: {
    width: '100%',
    zIndex: theme.zIndex.drawer + 1,
    backgroundColor: theme.palette.navAlt.background,
    color: theme.palette.header.text,
    borderBottom: '1px solid #5c5c5c',
  },
  title: {
    float: 'left',
  },
});

class StixObservableEditionContainer extends Component {
  render() {
    const {
      t, classes, handleClose, stixObservable,
    } = this.props;
    const { editContext } = stixObservable;
    return (
      <div>
        <div className={classes.header}>
          <IconButton
            aria-label="Close"
            className={classes.closeButton}
            onClick={handleClose.bind(this)}>
            <Close fontSize="small" />
          </IconButton>
          <Typography variant="h6" classes={{ root: classes.title }}>
            {t('Update an observable')}
          </Typography>
          <SubscriptionAvatars context={editContext} />
          <div className="clearfix" />
        </div>
        <div className={classes.container}>
          <StixObservableEditionOverview stixObservable={this.props.stixObservable}
            context={editContext}/>
        </div>
      </div>
    );
  }
}

StixObservableEditionContainer.propTypes = {
  handleClose: PropTypes.func,
  classes: PropTypes.object,
  stixObservable: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
};

const StixObservableEditionFragment = createFragmentContainer(
  StixObservableEditionContainer,
  {
    stixObservable: graphql`
      fragment StixObservableEditionContainer_stixObservable on StixObservable {
        id
        ...StixObservableEditionOverview_stixObservable
        editContext {
          name
          focusOn
        }
      }
    `,
  },
);

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(StixObservableEditionFragment);
