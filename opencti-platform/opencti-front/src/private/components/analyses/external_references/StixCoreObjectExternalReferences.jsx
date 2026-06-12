import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import inject18n from '../../../../components/i18n';
import { QueryRenderer } from '../../../../relay/environment';
import CardListSkeleton from '../../common/CardListSkeleton';
import StixCoreObjectExternalReferencesLines, { stixCoreObjectExternalReferencesLinesQuery } from './StixCoreObjectExternalReferencesLines';

class StixCoreObjectExternalReferences extends Component {
  render() {
    const { t, stixCoreObjectId } = this.props;

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
          return <CardListSkeleton title={t('External references')} />;
        }}
      />
    );
  }
}

StixCoreObjectExternalReferences.propTypes = {
  stixCoreObjectId: PropTypes.string,
  limit: PropTypes.number,
  t: PropTypes.func,
  fld: PropTypes.func,
};

export default inject18n(StixCoreObjectExternalReferences);
