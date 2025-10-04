import React, { FunctionComponent } from 'react';
import { useFormatter } from '../../../../components/i18n';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import StixCoreObjectOrStixCoreRelationshipNotesCards, { stixCoreObjectOrStixCoreRelationshipNotesCardsQuery } from './StixCoreObjectOrStixCoreRelationshipNotesCards';
import { NotesOrdering, OrderingMode, StixCoreObjectOrStixCoreRelationshipNotesCardsQuery } from './__generated__/StixCoreObjectOrStixCoreRelationshipNotesCardsQuery.graphql';
import { GqlFilterGroup } from '../../../../utils/filters/filtersUtils';
import { useIsHiddenEntities } from '../../../../utils/hooks/useEntitySettings';
import { Typography } from '@components';
interface StixCoreObjectOrStixCoreRelationshipNotesProps {
  stixCoreObjectOrStixCoreRelationshipId: string;
  marginTop?: number;
  isRelationship?: boolean;
  readonly defaultMarkings?: readonly {
    readonly definition: string | null | undefined;
    readonly definition_type: string | null | undefined;
    readonly id: string;
    readonly x_opencti_color: string | null | undefined;
    readonly x_opencti_order?: number;
  }[]
}

const StixCoreObjectOrStixCoreRelationshipNotes: FunctionComponent<StixCoreObjectOrStixCoreRelationshipNotesProps> = ({
  stixCoreObjectOrStixCoreRelationshipId,
  marginTop,
  isRelationship,
  defaultMarkings,
}) => {
  const { t_i18n } = useFormatter();
  const hiddenNote = useIsHiddenEntities('Note');
  const paginationOptions = {
    count: 200,
    orderBy: 'created' as NotesOrdering,
    orderMode: 'desc' as OrderingMode,
    filters: {
      mode: 'and',
      filters: [
        {
          key: ['objects'],
          values: [stixCoreObjectOrStixCoreRelationshipId],
          operator: 'eq',
        },
      ],
      filterGroups: [],
    } as GqlFilterGroup,
  };
  let queryRef;
  let title;
  if (isRelationship) {
    queryRef = useQueryLoading<StixCoreObjectOrStixCoreRelationshipNotesCardsQuery>(
      stixCoreObjectOrStixCoreRelationshipNotesCardsQuery,
      paginationOptions,
    );
    title = t_i18n('Notes about this relationship');
  } else {
    queryRef = useQueryLoading<StixCoreObjectOrStixCoreRelationshipNotesCardsQuery>(
      stixCoreObjectOrStixCoreRelationshipNotesCardsQuery,
      paginationOptions,
    );
    title = t_i18n('Notes about this entity');
  }
  return (
    <>
      {queryRef && !hiddenNote && (
        <React.Suspense
          fallback={
            <div style={{ height: '100%', marginTop }}>
              <Typography
                variant="h4"
                gutterBottom={true}
                style={{ float: 'left' }}
              >
                {title}
              </Typography>
            </div>
          }
        >
          <StixCoreObjectOrStixCoreRelationshipNotesCards
            id={stixCoreObjectOrStixCoreRelationshipId}
            queryRef={queryRef}
            marginTop={marginTop}
            paginationOptions={paginationOptions}
            defaultMarkings={defaultMarkings}
            title={title}
          />
        </React.Suspense>
      )}
    </>
  );
};

export default StixCoreObjectOrStixCoreRelationshipNotes;
