import React, { FunctionComponent } from 'react';
import { graphql, useFragment } from 'react-relay';
import Grid from '@mui/material/Grid';
import { useTheme } from '@mui/material/styles';
import { Switch, Text } from '@filigran/design-system';
import CustomFieldValuesDisplay from '@components/common/custom_fields/CustomFieldValuesDisplay';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import { useFormatter } from '../../../../components/i18n';
import { TaskDetails_task$data, TaskDetails_task$key } from './__generated__/TaskDetails_task.graphql';
import { TasksEditionOverviewFieldPatchMutation } from './__generated__/TasksEditionOverviewFieldPatchMutation.graphql';
import ItemDueDate from '../../../../components/ItemDueDate';
import Card from '../../../../components/common/card/Card';
import Label from '../../../../components/common/label/Label';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { tasksMutationFieldPatch } from './TasksEditionOverview';

const TaskDetailsFragment = graphql`
  fragment TaskDetails_task on Task {
    id
    entity_type
    customFieldValues {
      ...CustomFieldValuesDisplay_values @relay(mask: false)
    }
    name
    due_date
    description
    workflowEnabled
    completes_containment
    workflow_completed
    creators {
      id
      name
    }
    createdBy {
      ... on Identity {
        id
        name
        entity_type
      }
    }
    objectMarking {
      definition
      definition_type
      id
    }
    objectLabel {
      id
      value
      color
    }
    objectAssignee {
      entity_type
      id
      name
    }
    status {
      template {
        name
        color
      }
    }
  }
`;

interface TasksDetailsProps {
  tasksData: TaskDetails_task$key;
}

const TaskDetails: FunctionComponent<TasksDetailsProps> = ({ tasksData }) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme();
  const data: TaskDetails_task$data = useFragment(
    TaskDetailsFragment,
    tasksData,
  );
  const [commitFieldPatch, fieldPatching] = useApiMutation<TasksEditionOverviewFieldPatchMutation>(tasksMutationFieldPatch);
  // Offered once the task reaches the last status of its workflow, whatever moved it there, and kept visible while it is set
  const offersContainment = !!data.workflow_completed || !!data.completes_containment;
  const completesContainment = !!data.completes_containment;
  return (
    <div style={{ height: '100%' }} data-testid="task-details-page">
      <Card title={t_i18n('Details')}>
        <Grid container={true} spacing={2}>
          <Grid item xs={12}>
            <Label>
              {t_i18n('Description')}
            </Label>
            <ExpandableMarkdown source={data.description} limit={300} />
          </Grid>
          <Grid item xs={12}>
            <Label>
              {t_i18n('Due Date')}
            </Label>
            <ItemDueDate due_date={data.due_date} variant="inElement" />
          </Grid>
          {offersContainment && (
            <Grid item xs={12} data-testid="task-containment">
              <Label>
                {t_i18n('Containment')}
              </Label>
              <Security
                needs={[KNOWLEDGE_KNUPDATE]}
                placeholder={(
                  <Text variant="content-base" as="div">
                    {completesContainment ? t_i18n('This task completes the containment') : t_i18n('This task does not complete the containment')}
                  </Text>
                )}
              >
                <Switch
                  name="completes_containment"
                  checked={completesContainment}
                  disabled={fieldPatching}
                  label={t_i18n('This task completes the containment')}
                  onCheckedChange={(checked: boolean) => commitFieldPatch({
                    variables: { id: data.id, input: [{ key: 'completes_containment', value: [checked] }] },
                  })}
                />
              </Security>
              <Text variant="content-caption" as="div" style={{ marginTop: theme.spacing(0.5) }}>
                {t_i18n('Its completion sets the containment date in the timeline of the case')}
              </Text>
            </Grid>
          )}
          <CustomFieldValuesDisplay entityType={data.entity_type} values={data.customFieldValues ?? []} />
        </Grid>
      </Card>
    </div>
  );
};
export default TaskDetails;
