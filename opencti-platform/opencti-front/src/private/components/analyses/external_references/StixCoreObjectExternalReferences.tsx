import React from 'react';
import { useFormatter } from '../../../../components/i18n';
import { QueryRenderer } from '../../../../relay/environment';
import CardListSkeleton from '../../common/CardListSkeleton';
import StixCoreObjectExternalReferencesLines, { stixCoreObjectExternalReferencesLinesQuery } from './StixCoreObjectExternalReferencesLines';

interface StixCoreObjectExternalReferencesProps {
  stixCoreObjectId: string;
}

const StixCoreObjectExternalReferences = ({ stixCoreObjectId }: StixCoreObjectExternalReferencesProps) => {
  const { t_i18n } = useFormatter();

  return (
    <QueryRenderer
      query={stixCoreObjectExternalReferencesLinesQuery}
      variables={{ id: stixCoreObjectId, count: 200 }}
      render={({ props }: { props: unknown }) => {
        if (props) {
          return (
            <StixCoreObjectExternalReferencesLines
              stixCoreObjectId={stixCoreObjectId}
              data={props as never}
            />
          );
        }
        return <CardListSkeleton title={t_i18n('External references')} />;
      }}
    />
  );
};

export default StixCoreObjectExternalReferences;
