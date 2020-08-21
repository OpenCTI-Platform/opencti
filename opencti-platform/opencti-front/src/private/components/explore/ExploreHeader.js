import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, propOr } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Chip from '@material-ui/core/Chip';
import Typography from '@material-ui/core/Typography';
import inject18n from '../../../components/i18n';

const styles = () => ({
  title: {
    float: 'left',
    textTransform: 'uppercase',
  },
  aliaseses: {
    float: 'right',
    overflowX: 'hidden',
    marginTop: '-5px',
  },
  aliases: {
    marginRight: 7,
  },
});

class ExploreHeaderComponent extends Component {
  render() {
    const { classes, stixDomainObject } = this.props;
    return (
      <div style={{ marginBottom: 10 }}>
        <Typography
          variant="h1"
          gutterBottom={true}
          classes={{ root: classes.title }}
        >
          {propOr('-', 'name', stixDomainObject)}
        </Typography>
        <div className={classes.aliaseses}>
          {propOr(null, 'x_opencti_aliases', stixDomainObject)
            || propOr([], 'aliases', stixDomainObject).map((label) => (label.length > 0 ? (
                <Chip
                  key={label}
                  classes={{ root: classes.aliases }}
                  label={label}
                />
            ) : (
              ''
            )))}
        </div>
        <div className="clearfix" />
      </div>
    );
  }
}

ExploreHeaderComponent.propTypes = {
  stixDomainObject: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
};

const ExploreHeader = createFragmentContainer(ExploreHeaderComponent, {
  stixDomainObject: graphql`
    fragment ExploreHeader_stixDomainObject on StixDomainObject {
      id
      ... on AttackPattern {
        name
        description
        aliases
      }
      ... on Campaign {
        name
        description
        aliases
      }
      ... on CourseOfAction {
        name
        description
        x_opencti_aliases
      }
      ... on Individual {
        name
        description
        x_opencti_aliases
      }
      ... on Organization {
        name
        description
        x_opencti_aliases
      }
      ... on Sector {
        name
        description
        x_opencti_aliases
      }
      ... on Indicator {
        name
        description
      }
      ... on Infrastructure {
        name
        description
      }
      ... on IntrusionSet {
        name
        aliases
        description
      }
      ... on Position {
        name
        description
        x_opencti_aliases
      }
      ... on City {
        name
        description
        x_opencti_aliases
      }
      ... on Country {
        name
        description
        x_opencti_aliases
      }
      ... on Region {
        name
        description
        x_opencti_aliases
      }
      ... on Malware {
        name
        aliases
        description
      }
      ... on ThreatActor {
        name
        aliases
        description
      }
      ... on Tool {
        name
        aliases
        description
      }
      ... on Vulnerability {
        name
        description
      }
      ... on XOpenCTIIncident {
        name
        aliases
        description
      }
    }
  `,
});

export default compose(inject18n, withStyles(styles))(ExploreHeader);
