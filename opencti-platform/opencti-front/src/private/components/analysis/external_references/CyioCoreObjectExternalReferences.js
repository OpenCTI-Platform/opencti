import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import Typography from '@material-ui/core/Typography';
import List from '@material-ui/core/List';
import ListItem from '@material-ui/core/ListItem';
import ListItemText from '@material-ui/core/ListItemText';
import Skeleton from '@material-ui/lab/Skeleton';
import { QueryRenderer as QR } from 'react-relay';
import DarkLightEnvironment from '../../../../relay/environmentDarkLight';
import inject18n from '../../../../components/i18n';
// import { QueryRenderer } from '../../../../relay/environment';
import CyioCoreObjectExternalReferencesLines, {
  cyioCoreObjectExternalReferencesLinesQuery,
} from './CyioCoreObjectExternalReferencesLines';

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

class CyioCoreObjectExternalReferences extends Component {
  render() {
    const { t, classes, cyioCoreObjectId } = this.props;
    return (
      <>
       <QR
          environment={DarkLightEnvironment}
          query={cyioCoreObjectExternalReferencesLinesQuery}
          variables={{ count: 200 }}
          render={({ props }) => {
            if (props) {
              return (
                <CyioCoreObjectExternalReferencesLines
                  cyioCoreObjectId={cyioCoreObjectId}
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
                <Paper classes={{ root: classes.paper }} elevation={2}>
                  <List>
                    {Array.from(Array(5), (e, i) => (
                      <ListItem
                        key={i}
                        dense={true}
                        divider={true}
                        button={false}
                      >
                        {/* <ListItemIcon>
                          <Avatar classes={{ root: classes.avatarDisabled }}>
                            {i}
                          </Avatar>
                        </ListItemIcon> */}
                        <ListItemText
                          primary={
                            <Skeleton
                              animation="wave"
                              variant="rect"
                              width="90%"
                              height={15}
                              style={{ marginBottom: 10 }}
                            />
                          }
                          secondary={
                            <Skeleton
                              animation="wave"
                              variant="rect"
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
      </>
    );
  }
}

CyioCoreObjectExternalReferences.propTypes = {
  cyioCoreObjectId: PropTypes.string,
  limit: PropTypes.number,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles),
)(CyioCoreObjectExternalReferences);
