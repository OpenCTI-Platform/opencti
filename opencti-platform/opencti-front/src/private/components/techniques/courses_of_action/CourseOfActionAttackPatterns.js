import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import List from '@material-ui/core/List';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import Avatar from '@material-ui/core/Avatar';
import Typography from '@material-ui/core/Typography';
import inject18n from '../../../../components/i18n';
import { QueryRenderer } from '../../../../relay/environment';
import CourseOfActionAttackPatternsLines, {
  courseOfActionAttackPatternsLinesQuery,
} from './CourseOfActionAttackPatternsLines';

const styles = (theme) => ({
  paper: {
    minHeight: '100%',
    margin: '3px 0 0 0',
    padding: 0,
    borderRadius: 6,
  },
  avatar: {
    width: 24,
    height: 24,
    backgroundColor: theme.palette.primary.main,
  },
  avatarDisabled: {
    width: 24,
    height: 24,
  },
  placeholder: {
    display: 'inline-block',
    height: '1em',
    backgroundColor: theme.palette.grey[700],
  },
});

class CoursesOfActionAttackPatterns extends Component {
  render() {
    const { t, classes, courseOfActionId } = this.props;
    const paginationOptions = {
      courseOfActionId,
      orderBy: 'created_at',
      orderMode: 'desc',
    };
    return (
      <QueryRenderer
        query={courseOfActionAttackPatternsLinesQuery}
        variables={{
          courseOfActionId,
          count: 200,
          orderBy: 'created_at',
          orderMode: 'desc',
        }}
        render={({ props }) => {
          if (props) {
            return (
              <CourseOfActionAttackPatternsLines
                courseOfActionId={courseOfActionId}
                data={props}
                paginationOptions={paginationOptions}
              />
            );
          }
          return (
            <div style={{ marginTop: 20 }}>
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ float: 'left' }}
              >
                {t('Mitigated TTPs')}
              </Typography>
              <List>
                {Array.from(Array(5), (e, i) => (
                  <ListItem key={i} dense={true} divider={true} button={false}>
                    <ListItemIcon>
                      <Avatar classes={{ root: classes.avatarDisabled }}>
                        {i}
                      </Avatar>
                    </ListItemIcon>
                    <ListItemText
                      primary={
                        <span className="fakeItem" style={{ width: '80%' }} />
                      }
                      secondary={
                        <span className="fakeItem" style={{ width: '90%' }} />
                      }
                    />
                  </ListItem>
                ))}
              </List>
            </div>
          );
        }}
      />
    );
  }
}

CoursesOfActionAttackPatterns.propTypes = {
  courseOfActionId: PropTypes.string,
  limit: PropTypes.number,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles),
)(CoursesOfActionAttackPatterns);
