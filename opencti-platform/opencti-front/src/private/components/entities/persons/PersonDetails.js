import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import Typography from '@material-ui/core/Typography';
import StixDomainEntityTags from '../../common/stix_domain_entities/StixDomainEntityTags';
import inject18n from '../../../../components/i18n';
import ItemCreator from '../../../../components/ItemCreator';

const styles = () => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '15px',
    borderRadius: 6,
  },
  item: {
    paddingLeft: 10,
    transition: 'background-color 0.1s ease',
    '&:hover': {
      background: 'rgba(0, 0, 0, 0.1)',
    },
  },
});

class PersonDetailsComponent extends Component {
  render() {
    const { t, classes, person } = this.props;
    return (
      <div style={{ height: '100%' }}>
        <Typography variant="h4" gutterBottom={true}>
          {t('Details')}
        </Typography>
        <Paper classes={{ root: classes.paper }} elevation={2}>
          <StixDomainEntityTags tags={person.tags} id={person.id} />
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ marginTop: 20 }}
          >
            {t('Creator')}
          </Typography>
          <ItemCreator creator={person.creator} />
        </Paper>
      </div>
    );
  }
}

PersonDetailsComponent.propTypes = {
  person: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
};

const PersonDetails = createFragmentContainer(PersonDetailsComponent, {
  person: graphql`
    fragment PersonDetails_person on User {
      id
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

export default compose(inject18n, withStyles(styles))(PersonDetails);
