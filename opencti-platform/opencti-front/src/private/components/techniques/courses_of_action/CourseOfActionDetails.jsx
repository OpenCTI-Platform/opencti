import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { graphql, createFragmentContainer } from 'react-relay';
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
import FieldOrEmpty from '../../../../components/FieldOrEmpty';
import Card from '@common/card/Card';

class CourseOfActionDetailsComponent extends Component {
  render() {
    const { t, courseOfAction } = this.props;
    return (
      <div style={{ height: '100%' }}>
        <Card title={t('Details')}>
          <Grid container={true} spacing={3}>
            <Grid item xs={6}>
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
              <FieldOrEmpty source={courseOfAction.x_opencti_log_sources}>
                <List>
                  {(courseOfAction.x_opencti_log_sources ?? []).map((logSource, index) => (
                    <ListItem key={`${index}:${logSource}`} dense={true} divider={true}>
                      <ListItemIcon>
                        <PostOutline />
                      </ListItemIcon>
                      <ListItemText primary={logSource} />
                    </ListItem>
                  ))}
                </List>
              </FieldOrEmpty>
            </Grid>
            <Grid item xs={6}>
              <Typography variant="h3" gutterBottom={true}>
                {t('External ID')}
              </Typography>
              <FieldOrEmpty
                source={courseOfAction.x_mitre_id}
              >
                <Chip
                  size="small"
                  label={courseOfAction.x_mitre_id}
                  color="primary"
                  style={{ borderRadius: 4 }}
                />
              </FieldOrEmpty>
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
        </Card>
      </div>
    );
  }
}

CourseOfActionDetailsComponent.propTypes = {
  courseOfAction: PropTypes.object,
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
          id
          value
          color
        }
        ...CourseOfActionAttackPatterns_courseOfAction
      }
    `,
  },
);

export default compose(inject18n)(CourseOfActionDetails);
