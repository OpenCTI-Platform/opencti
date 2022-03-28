import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import Typography from '@material-ui/core/Typography';
import inject18n from '../../../../components/i18n';
import CyioCoreObjectNotesCards, {
// cyioCoreObjectNotesCardsQuery,
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
      disableAdd,
      height,
      typename,
      refreshQuery,
      notes,
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
        <CyioCoreObjectNotesCards
          cyioCoreObjectId={cyioCoreObjectOrCyioCoreRelationshipId}
          data={notes}
          disableAdd={disableAdd}
          refreshQuery={refreshQuery}
          height={height}
          typename={typename}
          marginTop={marginTop}
        />
      </>
    );
  }
}

CyioCoreObjectOrCyioCoreRelationshipNotes.propTypes = {
  notes: PropTypes.array,
  typename: PropTypes.string,
  refreshQuery: PropTypes.func,
  disabled: PropTypes.bool,
  t: PropTypes.func,
  disableAdd: PropTypes.bool,
  cyioCoreObjectOrCyioCoreRelationshipId: PropTypes.string,
  isRelationship: PropTypes.bool,
  marginTop: PropTypes.number,
  height: PropTypes.number,
};

export default inject18n(CyioCoreObjectOrCyioCoreRelationshipNotes);
