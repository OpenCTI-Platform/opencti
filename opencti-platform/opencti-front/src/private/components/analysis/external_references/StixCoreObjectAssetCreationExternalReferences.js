import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import Typography from '@material-ui/core/Typography';
import List from '@material-ui/core/List';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import Avatar from '@material-ui/core/Avatar';
import Skeleton from '@material-ui/lab/Skeleton';
import { QueryRenderer as QR } from 'react-relay';
import DarkLightEnvironment from '../../../../relay/environmentDarkLight';
import inject18n from '../../../../components/i18n';
import { QueryRenderer } from '../../../../relay/environment';
import AddExternalReferences from './AddExternalReferences';
import ExternalReferencesField from '../../common/form/ExternalReferencesField';
import Security, {
  KNOWLEDGE_KNUPDATE,
} from '../../../../utils/Security';

const styles = (theme) => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '-4px 0 0 0',
    padding: '24px',
    borderRadius: 6,
    position: 'relative',
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

class StixCoreObjectAssetCreationExternalReferences extends Component {
  render() {
    const { t, classes } = this.props;
    return (
      <div style={{ height: '100%' }}>
        <Typography variant="h4" gutterBottom={true} style={{ float: 'left' }}>
          {t('External references')}
        </Typography>
        <Security
          needs={[KNOWLEDGE_KNUPDATE]}
          placeholder={<div style={{ height: 28 }} />}
        >
          <AddExternalReferences
            // stixCoreObjectOrStixCoreRelationshipId={stixCoreObjectId}
            // stixCoreObjectOrStixCoreRelationshipReferences={
            //   data.stixCoreObject.externalReferences.edges
            // }
          />
        </Security>
        <div className="clearfix" />
        <Paper classes={{ root: classes.paper }} elevation={2}>
          <ExternalReferencesField
            name="externalReferences"
            variant='outlined'
          />
        </Paper>
      </div>
    );
  }
}

StixCoreObjectAssetCreationExternalReferences.propTypes = {
  stixCoreObjectId: PropTypes.string,
  limit: PropTypes.number,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles),
)(StixCoreObjectAssetCreationExternalReferences);
