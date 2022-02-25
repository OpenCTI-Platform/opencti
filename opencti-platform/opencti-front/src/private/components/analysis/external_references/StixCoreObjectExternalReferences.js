import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import Avatar from '@mui/material/Avatar';
import Skeleton from '@mui/material/Skeleton';
import inject18n from '../../../../components/i18n';
import { QueryRenderer } from '../../../../relay/environment';
import StixCoreObjectExternalReferencesLines, {
  stixCoreObjectExternalReferencesLinesQuery,
} from './StixCoreObjectExternalReferencesLines';

const styles = (theme) => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '-4px 0 0 0',
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

class StixCoreObjectExternalReferences extends Component {
  render() {
    const { t, classes, stixCoreObjectId } = this.props;
    return (
      <QueryRenderer
        query={stixCoreObjectExternalReferencesLinesQuery}
        variables={{ id: stixCoreObjectId, count: 200 }}
        render={({ props }) => {
          if (props) {
            return (
              <StixCoreObjectExternalReferencesLines
                stixCoreObjectId={stixCoreObjectId}
                data={props}
              />
            );
          }
          return (
            <div style={{ height: '100%' }}>
              <Typography
                variant="h4"
                gutterBottom={true}
                style={{ float: 'left', marginBottom: 15 }}
              >
                {t('External references')}
              </Typography>
              <div className="clearfix" />
              <Paper classes={{ root: classes.paper }} variant="outlined">
                <List>
                  {Array.from(Array(5), (e, i) => (
                    <ListItem
                      key={i}
                      dense={true}
                      divider={true}
                      button={false}
                    >
                      <ListItemIcon>
                        <Avatar classes={{ root: classes.avatarDisabled }}>
                          {i}
                        </Avatar>
                      </ListItemIcon>
                      <ListItemText
                        primary={
                          <Skeleton
                            animation="wave"
                            variant="rectangular"
                            width="90%"
                            height={15}
                            style={{ marginBottom: 10 }}
                          />
                        }
                        secondary={
                          <Skeleton
                            animation="wave"
                            variant="rectangular"
                            width="90%"
                            height={15}
                          />
                        }
                      />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </div>
          );
        }}
      />
    );
  }
}

StixCoreObjectExternalReferences.propTypes = {
  stixCoreObjectId: PropTypes.string,
  limit: PropTypes.number,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles),
)(StixCoreObjectExternalReferences);
