import React, { FunctionComponent } from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import Grid from '@mui/material/Grid';
import makeStyles from '@mui/styles/makeStyles';
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

const useStyles = makeStyles(() => ({
  container: {
    margin: 0,
  },
  gridContainer: {
    marginBottom: 20,
  },
}));

interface ExternalReferenceComponentProps {
  externalReference: ExternalReference_externalReference$data,
  connectorsImport: {
    id: string,
    name: string,
    active: boolean,
    connector_scope: string[],
    updated_at: string,
  }[],
}

const ExternalReferenceComponent: FunctionComponent<ExternalReferenceComponentProps> = ({ externalReference, connectorsImport }) => {
  const classes = useStyles();

  return (
    <div className={classes.container}>
      <ExternalReferenceHeader
        externalReference={externalReference}
        PopoverComponent={<ExternalReferencePopover
          id={''} handleRemove={undefined} entityId={''}
          />}
      />
      <Grid
        container={true}
        spacing={3}
        classes={{ container: classes.gridContainer }}
      >
        <Grid item={true} xs={6} style={{ paddingTop: 10 }}>
          <ExternalReferenceOverview externalReference={externalReference} />
        </Grid>
        <Grid item={true} xs={6} style={{ paddingTop: 10 }}>
          <ExternalReferenceDetails externalReference={externalReference} />
        </Grid>
      </Grid>
      <Grid
        container={true}
        spacing={3}
        classes={{ container: classes.gridContainer }}
        style={{ marginTop: 25 }}
      >
        <Grid item={true} xs={6}>
          <ExternalReferenceStixCoreObjects
            externalReference={externalReference}
          />
        </Grid>
        <Grid item={true} xs={6}>
          <ExternalReferenceFileImportViewer
            externalReference={externalReference}
            connectorsImport={connectorsImport}
          />
        </Grid>
      </Grid>
      <Security needs={[KNOWLEDGE_KNUPDATE]}>
        <ExternalReferenceEdition
          externalReferenceId={externalReference.id}
        />
      </Security>
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
