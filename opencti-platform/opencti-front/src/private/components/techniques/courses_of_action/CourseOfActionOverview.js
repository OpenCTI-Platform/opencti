import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, map, pathOr } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import Markdown from 'react-markdown';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import Typography from '@material-ui/core/Typography';
import inject18n from '../../../../components/i18n';
import ItemCreator from '../../../../components/ItemCreator';
import ItemMarking from '../../../../components/ItemMarking';

const styles = () => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '15px',
    borderRadius: 6,
  },
});

class CourseOfActionOverviewComponent extends Component {
  render() {
    const {
      t, fld, classes, courseOfAction,
    } = this.props;
    return (
      <div style={{ height: '100%' }} className="break">
        <Typography variant="h4" gutterBottom={true}>
          {t('Information')}
        </Typography>
        <Paper classes={{ root: classes.paper }} elevation={2}>
          <Typography variant="h3" gutterBottom={true}>
            {t('Marking')}
          </Typography>
          {courseOfAction.markingDefinitions.edges.length > 0 ? (
            map(
              (markingDefinition) => (
                <ItemMarking
                  key={markingDefinition.node.id}
                  label={markingDefinition.node.definition}
                />
              ),
              courseOfAction.markingDefinitions.edges,
            )
          ) : (
            <ItemMarking label="TLP:WHITE" />
          )}
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ marginTop: 20 }}
          >
            {t('Creation date')}
          </Typography>
          {fld(courseOfAction.created)}
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ marginTop: 20 }}
          >
            {t('Modification date')}
          </Typography>
          {fld(courseOfAction.modified)}
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ marginTop: 20 }}
          >
            {t('Creator')}
          </Typography>
          <ItemCreator
            createdByRef={pathOr(
              null,
              ['createdByRef', 'node'],
              courseOfAction,
            )}
          />
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ marginTop: 20 }}
          >
            {t('Description')}
          </Typography>
          <Markdown className="markdown" source={courseOfAction.description} />
        </Paper>
      </div>
    );
  }
}

CourseOfActionOverviewComponent.propTypes = {
  courseOfAction: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
};

const CourseOfActionOverview = createFragmentContainer(
  CourseOfActionOverviewComponent,
  {
    courseOfAction: graphql`
      fragment CourseOfActionOverview_courseOfAction on CourseOfAction {
        id
        name
        description
        created
        modified
        markingDefinitions {
          edges {
            node {
              id
              definition
            }
          }
        }
        createdByRef {
          node {
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
)(CourseOfActionOverview);
