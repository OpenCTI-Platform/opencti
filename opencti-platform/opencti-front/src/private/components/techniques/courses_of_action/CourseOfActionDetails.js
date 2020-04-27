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
import CoursesOfActionAttackPatterns from './CourseOfActionAttackPatterns';
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

class CourseOfActionDetailsComponent extends Component {
  render() {
    const { t, classes, courseOfAction } = this.props;
    return (
      <div style={{ height: '100%' }}>
        <Typography variant="h4" gutterBottom={true}>
          {t('Details')}
        </Typography>
        <Paper classes={{ root: classes.paper }} elevation={2}>
          <StixDomainEntityTags
            tags={courseOfAction.tags}
            id={courseOfAction.id}
          />
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ marginTop: 20 }}
          >
            {t('Creator')}
          </Typography>
          <ItemCreator creator={courseOfAction.creator} />
          <CoursesOfActionAttackPatterns courseOfAction={courseOfAction} />
        </Paper>
      </div>
    );
  }
}

CourseOfActionDetailsComponent.propTypes = {
  courseOfAction: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
};

const CourseOfActionDetails = createFragmentContainer(
  CourseOfActionDetailsComponent,
  {
    courseOfAction: graphql`
      fragment CourseOfActionDetails_courseOfAction on CourseOfAction {
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
        ...CourseOfActionAttackPatterns_courseOfAction
      }
    `,
  },
);

export default compose(inject18n, withStyles(styles))(CourseOfActionDetails);
