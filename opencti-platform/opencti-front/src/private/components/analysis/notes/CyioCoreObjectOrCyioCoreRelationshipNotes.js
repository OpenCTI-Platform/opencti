import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import Typography from '@material-ui/core/Typography';
import { QueryRenderer as QR } from 'react-relay';
import Paper from '@material-ui/core/Paper';
import DarkLightEnvironment from '../../../../relay/environmentDarkLight';
import inject18n from '../../../../components/i18n';
import CyioCoreObjectNotesCards, {
  cyioCoreObjectNotesCardsQuery,
} from './CyioCoreObjectNotesCards';
import StixCoreRelationshipNotesCards, {
  stixCoreRelationshipNotesCardsQuery,
} from './StixCoreRelationshipNotesCards';
import { QueryRenderer } from '../../../../relay/environment';

class CyioCoreObjectOrCyioCoreRelationshipNotes extends Component {
  render() {
    const {
      t,
      cyioCoreObjectOrCyioCoreRelationshipId,
      isRelationship,
      marginTop,
    } = this.props;
    if (isRelationship) {
      return (
        <QueryRenderer
          query={stixCoreRelationshipNotesCardsQuery}
          variables={{ id: cyioCoreObjectOrCyioCoreRelationshipId, count: 200 }}
          render={({ props }) => {
            if (props) {
              return (
                <StixCoreRelationshipNotesCards
                  stixCoreRelationshipId={
                    cyioCoreObjectOrCyioCoreRelationshipId
                  }
                  data={props}
                  marginTop={marginTop}
                />
              );
            }
            return (
              <div style={{ height: '100%', marginTop: marginTop || 40 }}>
                <Typography
                  variant="h4"
                  gutterBottom={true}
                  style={{ float: 'left' }}
                >
                  {t('Notes')}
                </Typography>
              </div>
            );
          }}
        />
      );
    }
    return (
      <>
        <QR
          environment={DarkLightEnvironment}
          query={cyioCoreObjectNotesCardsQuery}
          variables={{ id: cyioCoreObjectOrCyioCoreRelationshipId, count: 200 }}
          render={({ props }) => {
            if (props) {
              return (
                <CyioCoreObjectNotesCards
                  cyioCoreObjectId={cyioCoreObjectOrCyioCoreRelationshipId}
                  data={props}
                  marginTop={marginTop}
                />
              );
            }
            return (
              <div style={{ height: '100%', marginTop: marginTop || 40 }}>
                <Typography
                  variant="h4"
                  gutterBottom={true}
                  style={{ float: 'left', marginTop: -20 }}
                >
                  {t('Notes')}
                </Typography>
                <Paper style={{ marginTop: 50, height: '100px' }} />
              </div>
            );
          }}
        />
      </>
    );
  }
}

CyioCoreObjectOrCyioCoreRelationshipNotes.propTypes = {
  t: PropTypes.func,
  cyioCoreObjectOrCyioCoreRelationshipId: PropTypes.string,
  isRelationship: PropTypes.bool,
  marginTop: PropTypes.number,
};

export default inject18n(CyioCoreObjectOrCyioCoreRelationshipNotes);
