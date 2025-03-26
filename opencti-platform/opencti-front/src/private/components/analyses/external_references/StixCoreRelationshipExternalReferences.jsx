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
import StixCoreRelationshipExternalReferencesLines, { stixCoreRelationshipExternalReferencesLinesQuery } from './StixCoreRelationshipExternalReferencesLines';

const styles = (theme) => ({
  paper: {
    margin: '-4px 0 0 0',
    padding: 0,
    borderRadius: 4,
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

class StixCoreRelationshipExternalReferences extends Component {
  render() {
    const { t, classes, stixCoreRelationshipId } = this.props;
    return (
      <QueryRenderer
        query={stixCoreRelationshipExternalReferencesLinesQuery}
        variables={{ id: stixCoreRelationshipId, count: 200 }}
        render={({ props }) => {
          if (props) {
            return (
              <StixCoreRelationshipExternalReferencesLines
                stixCoreRelationshipId={stixCoreRelationshipId}
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
              <Paper classes={{ root: classes.paper }} className={'paper-for-grid'} variant="outlined">
                <List>
                  {Array.from(Array(5), (e, i) => (
                    <ListItem
                      key={i}
                      dense={true}
                      divider={true}

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

StixCoreRelationshipExternalReferences.propTypes = {
  stixCoreRelationshipId: PropTypes.string,
  limit: PropTypes.number,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles),
)(StixCoreRelationshipExternalReferences);
