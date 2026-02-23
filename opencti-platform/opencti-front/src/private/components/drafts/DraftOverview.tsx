import React, { FunctionComponent } from 'react';
import { DraftRootFragment$data } from '@components/drafts/__generated__/DraftRootFragment.graphql';
import { Grid } from '@mui/material';
import useOverviewLayoutCustomization from '../../../utils/hooks/useOverviewLayoutCustomization';
import DraftBasicInformation from './DraftBasicInformation';
import DraftDetails from '@components/drafts/DraftDetails';
import DraftEdition from '@components/drafts/DraftEdition';

interface DraftOverviewProps {
  draft: DraftRootFragment$data;
}

const DraftOverview: FunctionComponent<DraftOverviewProps> = ({ draft }) => {
  const draftOverviewLayoutCustomization = useOverviewLayoutCustomization(draft.entity_type);
  return (
    <>
      <Grid
        container={true}
        spacing={3}
        style={{ marginBottom: 20 }}
      >
        {
          draftOverviewLayoutCustomization.map(({ key, width }) => {
            switch (key) {
              case 'details':
                return (
                  <Grid key={key} item xs={width}>
                    <DraftDetails draft={draft} />
                  </Grid>
                );
              case 'basicInformation':
                return (
                  <Grid key={key} item xs={width}>
                    <DraftBasicInformation draft={draft} />
                  </Grid>
                );
              default:
                return null;
            }
          })
        }
      </Grid>
      <DraftEdition draftId={draft.id} overviewData={draft} />
    </>
  );
};

export default DraftOverview;
