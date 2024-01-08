import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { graphql, createFragmentContainer } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import Chip from '@mui/material/Chip';
import Grid from '@mui/material/Grid';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import { PostOutline } from 'mdi-material-ui';
import ListItemText from '@mui/material/ListItemText';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import CoursesOfActionAttackPatterns from './CourseOfActionAttackPatterns';
import inject18n from '../../../../components/i18n';

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
        <Paper classes={{ root: classes.paper }} variant="outlined">
          <Grid container={true} spacing={3}>
            <Grid item={true} xs={6}>
              <Typography variant="h3" gutterBottom={true}>
                {t('Description')}
              </Typography>
              <ExpandableMarkdown
                source={courseOfAction.description}
                limit={300}
              />
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('Log sources')}
              </Typography>
              {courseOfAction.x_opencti_log_sources && (
                <List>
                  {courseOfAction.x_opencti_log_sources.map((logSource, index) => (
                    <ListItem key={`${index}:${logSource}`} dense={true} divider={true}>
                      <ListItemIcon>
                        <PostOutline />
                      </ListItemIcon>
                      <ListItemText primary={logSource} />
                    </ListItem>
                  ))}
                </List>
              )}
            </Grid>
            <Grid item={true} xs={6}>
              <Typography variant="h3" gutterBottom={true}>
                {t('External ID')}
              </Typography>
              <Chip
                size="small"
                label={courseOfAction.x_mitre_id}
                color="primary"
              />
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('Threat hunting techniques')}
              </Typography>
              <ExpandableMarkdown
                source={courseOfAction.x_opencti_threat_hunting}
                limit={300}
              />
            </Grid>
          </Grid>
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
        description
        x_mitre_id
        x_opencti_threat_hunting
        x_opencti_log_sources
        objectLabel {
          edges {
            node {
              id
              value
              color
            }
          }
        }
        ...CourseOfActionAttackPatterns_courseOfAction
      }
    `,
  },
);

export default compose(inject18n, withStyles(styles))(CourseOfActionDetails);
