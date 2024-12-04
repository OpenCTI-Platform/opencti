import React from 'react';
import Grid from '@mui/material/Grid';
import Typography from '@mui/material/Typography';

import { RelatedContainerNode } from '@components/common/containers/RelatedContainers';
import { useFormatter } from '../../../../components/i18n';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import ItemMarkings from '../../../../components/ItemMarkings';

const RelatedContainersDetails = ({ containerId, relatedContainer }: { containerId: string, relatedContainer: RelatedContainerNode }) => {
  const { t_i18n, fldt } = useFormatter();
  console.log({ containerId, relatedContainer });

  return (
    <div>
      <Grid container={true} spacing={3} style={{ marginBottom: 20 }}>
        <Grid item xs={6}>
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ marginTop: 20 }}
          >
            {t_i18n('Description')}
          </Typography>
          <ExpandableMarkdown source={relatedContainer.description} limit={300} />
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ marginTop: 20 }}
          >
            {t_i18n('Assignees')}
          </Typography>
          {/* <ItemAssignees assignees={relatedContainer.objectAssignee ?? []} stixDomainObjectId={relatedContainer.id}/> */}
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ marginTop: 20 }}
          >
            {t_i18n('Original creation date')}
          </Typography>
          {fldt(relatedContainer.created ?? relatedContainer.published)}
        </Grid>
        <Grid item xs={6}>
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ marginTop: 20 }}
          >
            {t_i18n('Due Date')}
          </Typography>
          {/* <ItemDueDate due_date={relatedContainer.due_date} variant="inElement" /> */}
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ marginTop: 20 }}
          >
            {t_i18n('Processing status')}
          </Typography>
          {/* <ItemStatus status={relatedContainer.status} disabled={!relatedContainer.workflowEnabled} /> */}
          {relatedContainer.objectMarking && relatedContainer.objectMarking.length > 0 && (
            <>
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t_i18n('Marking')}
              </Typography>
              <ItemMarkings markingDefinitions={relatedContainer.objectMarking}/>
            </>
          )}
        </Grid>
      </Grid>
    </div>
  );
};

export default RelatedContainersDetails;
