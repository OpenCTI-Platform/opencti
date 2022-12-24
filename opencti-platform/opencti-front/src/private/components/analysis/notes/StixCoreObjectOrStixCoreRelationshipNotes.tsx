import React, { FunctionComponent } from 'react';
import Typography from '@mui/material/Typography';
import { useFormatter } from '../../../../components/i18n';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { NotesFilter } from './__generated__/NotesLinesPaginationQuery.graphql';
import StixCoreObjectOrStixCoreRelationshipNotesCards, {
  stixCoreObjectOrStixCoreRelationshipNotesCardsQuery,
} from './StixCoreObjectOrStixCoreRelationshipNotesCards';
import { StixCoreObjectOrStixCoreRelationshipNotesCardsQuery } from './__generated__/StixCoreObjectOrStixCoreRelationshipNotesCardsQuery.graphql';

interface StixCoreObjectOrStixCoreRelationshipNotesProps {
  stixCoreObjectOrStixCoreRelationshipId: string;
  marginTop?: number;
  isRelationship?: boolean;
  defaultMarking: { id: string; definition: string | null }[];
}

const StixCoreObjectOrStixCoreRelationshipNotes: FunctionComponent<
StixCoreObjectOrStixCoreRelationshipNotesProps
> = ({
  stixCoreObjectOrStixCoreRelationshipId,
  marginTop,
  isRelationship,
  defaultMarking,
}) => {
  const { t } = useFormatter();
  const paginationOptions = {
    count: 200,
    filters: [
      {
        key: ['objectContains' as NotesFilter],
        values: [stixCoreObjectOrStixCoreRelationshipId],
      },
    ],
  };
  let queryRef;
  let title;
  if (isRelationship) {
    queryRef = useQueryLoading<StixCoreObjectOrStixCoreRelationshipNotesCardsQuery>(
      stixCoreObjectOrStixCoreRelationshipNotesCardsQuery,
      paginationOptions,
    );
    title = t('Notes about this relationship');
  } else {
    queryRef = useQueryLoading<StixCoreObjectOrStixCoreRelationshipNotesCardsQuery>(
      stixCoreObjectOrStixCoreRelationshipNotesCardsQuery,
      paginationOptions,
    );
    title = t('Notes about this entity');
  }
  return (
    <>
      {queryRef && (
        <React.Suspense
          fallback={
            <div style={{ height: '100%', marginTop: marginTop || 50 }}>
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
            defaultMarking={defaultMarking}
            title={title}
          />
        </React.Suspense>
      )}
    </>
  );
};

export default StixCoreObjectOrStixCoreRelationshipNotes;
