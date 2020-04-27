import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import Typography from '@material-ui/core/Typography';
import inject18n from '../../../../components/i18n';
import StixObservableTags from '../../common/stix_observables/StixObservableTags';
import ItemCreator from '../../../../components/ItemCreator';

const styles = () => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '15px',
    borderRadius: 6,
  },
});

class StixObservableDetailsComponent extends Component {
  render() {
    const { t, classes, stixObservable } = this.props;
    return (
      <div style={{ height: '100%' }} className="break">
        <Typography variant="h4" gutterBottom={true}>
          {t('Details')}
        </Typography>
        <Paper classes={{ root: classes.paper }} elevation={2}>
          <Typography variant="h3" gutterBottom={true}>
            {t('Observable value')}
          </Typography>
          <pre>{stixObservable.observable_value}</pre>
          <div style={{ marginTop: 20 }}>
            <StixObservableTags
              tags={stixObservable.tags}
              id={stixObservable.id}
            />
          </div>
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ marginTop: 20 }}
          >
            {t('Creator')}
          </Typography>
          <ItemCreator creator={stixObservable.creator} />
        </Paper>
      </div>
    );
  }
}

StixObservableDetailsComponent.propTypes = {
  stixObservable: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const StixObservableDetails = createFragmentContainer(
  StixObservableDetailsComponent,
  {
    stixObservable: graphql`
      fragment StixObservableDetails_stixObservable on StixObservable {
        id
        observable_value
        creator {
          id
          name
        }
        tags {
          edges {
            node {
              id
              tag_type
              value
              color
            }
            relation {
              id
            }
          }
        }
      }
    `,
  },
);

export default compose(inject18n, withStyles(styles))(StixObservableDetails);
