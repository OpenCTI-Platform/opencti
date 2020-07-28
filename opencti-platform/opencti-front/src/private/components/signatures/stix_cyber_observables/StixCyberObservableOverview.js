import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, pathOr } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import Typography from '@material-ui/core/Typography';
import inject18n from '../../../../components/i18n';
import ItemAuthor from '../../../../components/ItemAuthor';

const styles = () => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '15px',
    borderRadius: 6,
  },
});

class StixCyberObservableOverviewComponent extends Component {
  render() {
    const {
      t, fldt, classes, stixCyberObservable,
    } = this.props;
    return (
      <div style={{ height: '100%' }} className="break">
        <Typography variant="h4" gutterBottom={true}>
          {t('Information')}
        </Typography>
        <Paper classes={{ root: classes.paper }} elevation={2}>
          <Typography variant="h3" gutterBottom={true}>
            {t('Observable type')}
          </Typography>
          {t(`observable_${stixCyberObservable.entity_type}`)}
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ marginTop: 20 }}
          >
            {t('Creation date')}
          </Typography>
          {fldt(stixCyberObservable.created_at)}
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ marginTop: 20 }}
          >
            {t('Modification date')}
          </Typography>
          {fldt(stixCyberObservable.updated_at)}
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ marginTop: 20 }}
          >
            {t('Author')}
          </Typography>
          <ItemAuthor
            createdBy={pathOr(null, ['createdBy', 'node'], stixCyberObservable)}
          />
        </Paper>
      </div>
    );
  }
}

StixCyberObservableOverviewComponent.propTypes = {
  stixCyberObservable: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fldt: PropTypes.func,
};

const StixCyberObservableOverview = createFragmentContainer(
  StixCyberObservableOverviewComponent,
  {
    stixCyberObservable: graphql`
      fragment StixCyberObservableOverview_stixCyberObservable on StixCyberObservable {
        id
        entity_type
        created_at
        updated_at
        createdBy {
          ... on Identity {
            id
            name
            entity_type
          }
        }
      }
    `,
  },
);

export default compose(
  inject18n,
  withStyles(styles),
)(StixCyberObservableOverview);
