import React, { FunctionComponent } from 'react';
import { graphql, useFragment } from 'react-relay';
import { Link } from 'react-router';
import Grid from '@mui/material/Grid';
import List from '@mui/material/List';
import ListItemButton from '@mui/material/ListItemButton';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import CustomFieldValuesDisplay from '@components/common/custom_fields/CustomFieldValuesDisplay';
import Card from '@common/card/Card';
import TextList from '@common/text/TextList';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import FieldOrEmpty from '../../../../components/FieldOrEmpty';
import ItemIcon from '../../../../components/ItemIcon';
import ItemOpenVocab from '../../../../components/ItemOpenVocab';
import Label from '../../../../components/common/label/Label';
import { useFormatter } from '../../../../components/i18n';
import { resolveLink } from '../../../../utils/Entity';
import StixCoreObjectKillChainPhasesView from '../../common/stix_core_objects/StixCoreObjectKillChainPhasesView';
import { ProcedureDetails_procedure$key } from './__generated__/ProcedureDetails_procedure.graphql';

const ProcedureDetailsFragment = graphql`
  fragment ProcedureDetails_procedure on Procedure {
    id
    entity_type
    customFieldValues {
      ...CustomFieldValuesDisplay_values @relay(mask: false)
    }
    description
    x_procedure_type
    x_mitre_platforms
    first_observed
    last_observed
    x_execution_start
    x_execution_end
    x_fingerprint
    killChainPhases {
      id
      entity_type
      kill_chain_name
      phase_name
      x_opencti_order
    }
    procedureCommand {
      id
      entity_type
      observable_value
    }
    procedureObservables(first: 100) {
      edges {
        node {
          id
          entity_type
          observable_value
        }
      }
    }
    procedureSources {
      id
      entity_type
      name
    }
  }
`;

interface LinkedEntity {
  id: string;
  entity_type: string;
  label: string;
}

const LinkedEntities = ({ entities }: { entities: LinkedEntity[] }) => (
  <FieldOrEmpty source={entities}>
    <List sx={{ py: 0 }}>
      {entities.map((entity) => (
        <ListItemButton
          key={entity.id}
          component={Link}
          to={`${resolveLink(entity.entity_type)}/${entity.id}`}
          dense={true}
          divider={true}
        >
          <ListItemIcon>
            <ItemIcon type={entity.entity_type} />
          </ListItemIcon>
          <ListItemText primary={entity.label} />
        </ListItemButton>
      ))}
    </List>
  </FieldOrEmpty>
);

interface ProcedureDetailsProps {
  procedure: ProcedureDetails_procedure$key;
}

const ProcedureDetails: FunctionComponent<ProcedureDetailsProps> = ({ procedure }) => {
  const { t_i18n, fldt } = useFormatter();
  const data = useFragment(ProcedureDetailsFragment, procedure);

  const command: LinkedEntity[] = data.procedureCommand
    ? [{ id: data.procedureCommand.id, entity_type: data.procedureCommand.entity_type, label: data.procedureCommand.observable_value }]
    : [];
  const observables: LinkedEntity[] = (data.procedureObservables?.edges ?? [])
    .map(({ node }) => ({ id: node.id, entity_type: node.entity_type, label: node.observable_value }));
  const sources: LinkedEntity[] = (data.procedureSources ?? [])
    .flatMap((source) => (source ? [{ id: source.id, entity_type: source.entity_type, label: source.name }] : []));

  const dates = [
    { label: t_i18n('First observed'), value: data.first_observed },
    { label: t_i18n('Last observed'), value: data.last_observed },
    { label: t_i18n('Execution start'), value: data.x_execution_start },
    { label: t_i18n('Execution end'), value: data.x_execution_end },
  ];

  return (
    <div style={{ height: '100%' }}>
      <Card title={t_i18n('Details')}>
        <Grid container={true} spacing={2}>
          <Grid size={12}>
            <Label>{t_i18n('Description')}</Label>
            <FieldOrEmpty source={data.description}>
              <ExpandableMarkdown source={data.description} limit={300} />
            </FieldOrEmpty>
          </Grid>
          <Grid size={6}>
            <Label>{t_i18n('Procedure type')}</Label>
            <ItemOpenVocab type="procedure_type_ov" value={data.x_procedure_type} />
            <Label sx={{ marginTop: 2 }}>{t_i18n('Platforms')}</Label>
            <TextList list={data.x_mitre_platforms} />
            <StixCoreObjectKillChainPhasesView killChainPhases={data.killChainPhases} />
            <Label sx={{ marginTop: 2 }}>{t_i18n('Fingerprint')}</Label>
            <FieldOrEmpty source={data.x_fingerprint}>
              <span style={{ fontFamily: 'monospace', wordBreak: 'break-all' }}>{data.x_fingerprint}</span>
            </FieldOrEmpty>
          </Grid>
          <Grid size={6}>
            {dates.map(({ label, value }, index) => (
              <React.Fragment key={label}>
                <Label sx={index > 0 ? { marginTop: 2 } : undefined}>{label}</Label>
                <FieldOrEmpty source={value}>{fldt(value)}</FieldOrEmpty>
              </React.Fragment>
            ))}
          </Grid>
          <Grid size={12}>
            <Label>{t_i18n('Command')}</Label>
            <LinkedEntities entities={command} />
            <Label sx={{ marginTop: 2 }}>{t_i18n('Observables')}</Label>
            <LinkedEntities entities={observables} />
            <Label sx={{ marginTop: 2 }}>{t_i18n('Sources')}</Label>
            <LinkedEntities entities={sources} />
          </Grid>
          <CustomFieldValuesDisplay entityType={data.entity_type} values={data.customFieldValues ?? []} />
        </Grid>
      </Card>
    </div>
  );
};

export default ProcedureDetails;
