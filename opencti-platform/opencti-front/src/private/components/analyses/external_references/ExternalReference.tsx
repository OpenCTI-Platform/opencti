import React, { FunctionComponent } from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import Grid from '@mui/material/Grid';
import makeStyles from '@mui/styles/makeStyles';
import useHelper from 'src/utils/hooks/useHelper';
import ExternalReferenceOverview from './ExternalReferenceOverview';
import ExternalReferenceDetails from './ExternalReferenceDetails';
import ExternalReferenceEdition from './ExternalReferenceEdition';
import Security from '../../../../utils/Security';
import ExternalReferencePopover from './ExternalReferencePopover';
import ExternalReferenceHeader from './ExternalReferenceHeader';
import ExternalReferenceFileImportViewer from './ExternalReferenceFileImportViewer';
import ExternalReferenceStixCoreObjects from './ExternalReferenceStixCoreObjects';
import { ExternalReference_externalReference$data } from './__generated__/ExternalReference_externalReference.graphql';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import useOverviewLayoutCustomization from '../../../../utils/hooks/useOverviewLayoutCustomization';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles(() => ({
  container: {
    margin: 0,
  },
  gridContainer: {
    marginBottom: 20,
  },
}));

interface ExternalReferenceComponentProps {
  externalReference: ExternalReference_externalReference$data;
  connectorsImport: {
    id: string;
    name: string;
    active: boolean;
    connector_scope: string[];
    updated_at: string;
  }[];
}

const ExternalReferenceComponent: FunctionComponent<
ExternalReferenceComponentProps
> = ({ externalReference, connectorsImport }) => {
  const classes = useStyles();
  const { isFeatureEnable } = useHelper();
  const isFABReplaced = isFeatureEnable('FAB_REPLACEMENT');
  const overviewLayoutCustomization = useOverviewLayoutCustomization('External-Reference');
  return (
    <div className={classes.container}>
      <ExternalReferenceHeader
        externalReference={externalReference}
        PopoverComponent={
          <ExternalReferencePopover id={''} handleRemove={undefined} />
        }
        EditComponent={(
          <Security needs={[KNOWLEDGE_KNUPDATE]}>
            <ExternalReferenceEdition externalReferenceId={externalReference.id} />
          </Security>
        )}
      />
      <Grid
        container={true}
        spacing={3}
        classes={{ container: classes.gridContainer }}
      >
        {
          overviewLayoutCustomization.map(({ key, width }) => {
            switch (key) {
              case 'basicInformation':
                return (
                  <Grid key={key} item xs={width}>
                    <ExternalReferenceOverview externalReference={externalReference} />
                  </Grid>
                );
              case 'details':
                return (
                  <Grid key={key} item xs={width}>
                    <ExternalReferenceDetails externalReference={externalReference} />
                  </Grid>
                );
              case 'linkedObjects':
                return (
                  <Grid key={key} item xs={width}>
                    <ExternalReferenceStixCoreObjects
                      externalReference={externalReference}
                    />
                  </Grid>
                );
              case 'uploadedFiles':
                return (
                  <Grid key={key} item xs={width}>
                    <ExternalReferenceFileImportViewer
                      externalReference={externalReference}
                      connectorsImport={connectorsImport}
                    />
                  </Grid>
                );
              default:
                return null;
            }
          })
        }
      </Grid>
      {!isFABReplaced && (
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <ExternalReferenceEdition externalReferenceId={externalReference.id} />
        </Security>
      )}
    </div>
  );
};

const ExternalReference = createFragmentContainer(ExternalReferenceComponent, {
  externalReference: graphql`
    fragment ExternalReference_externalReference on ExternalReference {
      id
      ...ExternalReferenceHeader_externalReference
      ...ExternalReferenceOverview_externalReference
      ...ExternalReferenceDetails_externalReference
      ...ExternalReferenceFileImportViewer_entity
      ...ExternalReferenceStixCoreObjects_externalReference
    }
  `,
  connectorsImport: graphql`
    fragment ExternalReference_connectorsImport on Connector
    @relay(plural: true) {
      ...ExternalReferenceFileImportViewer_connectorsImport
    }
  `,
});

export default ExternalReference;
