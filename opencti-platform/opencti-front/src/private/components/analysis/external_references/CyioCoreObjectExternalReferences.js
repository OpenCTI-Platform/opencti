import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import Typography from '@material-ui/core/Typography';
import inject18n from '../../../../components/i18n';
// import { QueryRenderer } from '../../../../relay/environment';
import CyioCoreObjectExternalReferencesLines, {
// cyioCoreObjectExternalReferencesLinesQuery,
} from './CyioCoreObjectExternalReferencesLines';
import CyioAddExternalReferences from './CyioAddExternalReferences';

const styles = (theme) => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    padding: 0,
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
  buttonExpand: {
    position: 'absolute',
    bottom: 2,
    width: '100%',
    height: 25,
    backgroundColor: 'rgba(255, 255, 255, .2)',
    borderTopLeftRadius: 0,
    borderTopRightRadius: 0,
    '&:hover': {
      backgroundColor: 'rgba(255, 255, 255, .5)',
    },
  },
});

class CyioCoreObjectExternalReferences extends Component {
  // constructor(props) {
  //   super(props);
  //   this.state = {
  //     expanded: false,
  //   };
  // }

  // handleToggleExpand() {
  //   this.setState({ expanded: !this.state.expanded });
  // }

  render() {
    const {
      t,
      classes,
      disableAdd,
      fieldName,
      cyioCoreObjectId,
      refreshQuery,
      typename,
      externalReferences,
      removeIcon,
    } = this.props;
    // const { expanded } = this.state;
    // const expandable = externalReferences.length > 7;
    return (
      <>
        <Typography variant="h4" gutterBottom={true} style={{ float: 'left' }}>
          {t('External references')}
        </Typography>
        <CyioAddExternalReferences
          cyioCoreObjectOrCyioCoreRelationshipId={cyioCoreObjectId}
          cyioCoreObjectOrCyioCoreRelationshipReferences={
            externalReferences
            // externalReference.externalReference
          }
          disableAdd={disableAdd}
          fieldName={fieldName}
          refreshQuery={refreshQuery}
          typename={typename}
          removeIcon={removeIcon}
        />
        <div className="clearfix" />
        <Paper classes={{ root: classes.paper }} elevation={2}>
          {(externalReferences && externalReferences.length > 0) ? (
            externalReferences.map((externalReference) => (
              <CyioCoreObjectExternalReferencesLines
                key={externalReference.id}
                fieldName={fieldName}
                typename={typename}
                cyioCoreObjectId={cyioCoreObjectId}
                refreshQuery={refreshQuery}
                externalReference={externalReference}
              />
            ))
          ) : (
            <div style={{ display: 'table', height: '100%', width: '100%' }}>
              <span
                style={{
                  display: 'table-cell',
                  verticalAlign: 'middle',
                  textAlign: 'center',
                }}
              >
                {t('No entities of this type has been found.')}
              </span>
            </div>
          )}
          {/* {expandable && (
           <Button
             variant="contained"
             size="small"
             onClick={this.handleToggleExpand.bind(this)}
             classes={{ root: classes.buttonExpand }}
           >
             {expanded ? (
               <ExpandLessOutlined fontSize="small" />
             ) : (
               <ExpandMoreOutlined fontSize="small" />
             )}
           </Button>
          )} */}
        </Paper>
      </>
    );
  }
}

CyioCoreObjectExternalReferences.propTypes = {
  externalReferences: PropTypes.array,
  fieldName: PropTypes.string,
  typename: PropTypes.string,
  cyioCoreObjectId: PropTypes.string,
  refreshQuery: PropTypes.func,
  disableAdd: PropTypes.bool,
  limit: PropTypes.number,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
  removeIcon: PropTypes.bool,
};

export default compose(
  inject18n,
  withStyles(styles),
)(CyioCoreObjectExternalReferences);
