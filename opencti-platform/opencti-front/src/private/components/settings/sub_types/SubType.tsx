import Grid from '@mui/material/Grid';
import Typography from '@mui/material/Typography';
import React from 'react';
import Paper from '@mui/material/Paper';
import makeStyles from '@mui/styles/makeStyles';
import { graphql, useFragment } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import ItemStatusTemplate from '../../../../components/ItemStatusTemplate';
import SubTypeStatusPopover from './SubTypeWorkflowPopover';
import EntitySetting, { entitySettingQuery } from './EntitySetting';
import { SubType_subType$key } from './__generated__/SubType_subType.graphql';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { EntitySettingQuery } from './__generated__/EntitySettingQuery.graphql';

const useStyles = makeStyles(() => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '15px',
    borderRadius: 6,
  },
}));

// -- GRAPHQL - ENTITY --

export const subTypeFragment = graphql`
  fragment SubType_subType on SubType {
    id
    label
    workflowEnabled
    settings {
      id
      enforce_reference
      platform_entity_files_ref
      platform_hidden_type
      target_type
    }
    statuses {
      edges {
        node {
          id
          order
          template {
            name
            color
          }
        }
      }
    }
  }
`;

const SubType = ({ data }: { data: SubType_subType$key }) => {
  const { t } = useFormatter();
  const classes = useStyles();

  const subType = useFragment(subTypeFragment, data);
  const statuses = (subType.statuses?.edges ?? []).map((edge) => edge.node);

  const queryRef = useQueryLoading<EntitySettingQuery>(entitySettingQuery, {
    targetType: subType.id,
  });

  return (
    <>
      <Typography variant="h1" gutterBottom={true}>
        {t(`entity_${subType.label}`)}
      </Typography>
      <Grid container={true} spacing={3} style={{ paddingTop: 10 }}>
        <Grid item={true} xs={6}>
          <div>
            <Typography variant="h4" gutterBottom={true}>
              {t('Configuration')}
            </Typography>
            <Paper classes={{ root: classes.paper }} variant="outlined">
              {queryRef && (
                <React.Suspense
                  fallback={<Loader variant={LoaderVariant.inElement} />}
                >
                  <EntitySetting queryRef={queryRef} />
                </React.Suspense>
              )}
              <div style={{ marginTop: 10 }}>
                <Typography variant="h3" gutterBottom={true}>
                  {`${t('Workflow of')} ${t(`entity_${subType.label}`)}`}
                  <SubTypeStatusPopover subTypeId={subType.id} />
                </Typography>
              </div>
              <ItemStatusTemplate
                statuses={statuses}
                disabled={!subType.workflowEnabled}
              />
            </Paper>
          </div>
        </Grid>
        {/* <Grid item={true} xs={6}> */}
        {/*  <div style={{ height: '100%' }}> */}
        {/*    <Typography variant="h4" gutterBottom={true}> */}
        {/*      /!* TODO: I18n *!/ */}
        {/*      {t('Mandatory attributes')} */}
        {/*    </Typography> */}
        {/*    <Paper classes={{ root: classes.paper }} variant="outlined"> */}
        {/*      <span>Mandatory attributes</span> */}
        {/*    </Paper> */}
        {/*  </div> */}
        {/* </Grid> */}
      </Grid>
    </>
  );
};

export default SubType;
