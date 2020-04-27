import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import Typography from '@material-ui/core/Typography';
import inject18n from '../../../../components/i18n';
import StixDomainEntityTags from '../../common/stix_domain_entities/StixDomainEntityTags';
import ItemScore from '../../../../components/ItemScore';
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

class IndicatorDetailsComponent extends Component {
  render() {
    const {
      t, fld, classes, indicator,
    } = this.props;
    return (
      <div style={{ height: '100%' }} className="break">
        <Typography variant="h4" gutterBottom={true}>
          {t('Details')}
        </Typography>
        <Paper classes={{ root: classes.paper }} elevation={2}>
          <Typography variant="h3" gutterBottom={true}>
            {t('Indicator pattern')}
          </Typography>
          <pre>{indicator.indicator_pattern}</pre>
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ marginTop: 20 }}
          >
            {t('Creator')}
          </Typography>
          <ItemCreator creator={indicator.creator} />
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ marginTop: 20 }}
          >
            {t('Valid from')}
          </Typography>
          {fld(indicator.valid_from)}
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ marginTop: 20 }}
          >
            {t('Valid until')}
          </Typography>
          {fld(indicator.valid_until)}
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ marginTop: 20 }}
          >
            {t('Score')}
          </Typography>
          <ItemScore score={indicator.score} />
          <div style={{ marginTop: 20 }}>
            <StixDomainEntityTags tags={indicator.tags} id={indicator.id} />
          </div>
        </Paper>
      </div>
    );
  }
}

IndicatorDetailsComponent.propTypes = {
  indicator: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
};

const IndicatorDetails = createFragmentContainer(IndicatorDetailsComponent, {
  indicator: graphql`
    fragment IndicatorDetails_indicator on Indicator {
      id
      indicator_pattern
      valid_from
      valid_until
      score
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
});

export default compose(inject18n, withStyles(styles))(IndicatorDetails);
