import React, { FunctionComponent } from 'react';
import { graphql, useFragment } from 'react-relay';
import Grid from '@mui/material/Grid';
import Tag from '../../../../components/common/tag/Tag';
import { Stack } from '@mui/material';
import StixCoreObjectsDonut from '../../common/stix_core_objects/StixCoreObjectsDonut';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import { useFormatter } from '../../../../components/i18n';
import StixCoreObjectKillChainPhasesView from '../../common/stix_core_objects/StixCoreObjectKillChainPhasesView';
import { InfrastructureDetails_infrastructure$data, InfrastructureDetails_infrastructure$key } from './__generated__/InfrastructureDetails_infrastructure.graphql';
import Card from '../../../../components/common/card/Card';
import Label from '../../../../components/common/label/Label';
import FieldOrEmpty from '../../../../components/FieldOrEmpty';
import { EMPTY_VALUE } from '../../../../utils/String';

const InfrastructureDetailsFragment = graphql`
  fragment InfrastructureDetails_infrastructure on Infrastructure {
    id
    name
    description
    infrastructure_types
    first_seen
    last_seen
    killChainPhases {
      id
      entity_type
      kill_chain_name
      phase_name
      x_opencti_order
    }
    objectLabel {
      id
      value
      color
    }
  }
`;

interface InfrastructureDetailsProps {
  infrastructure: InfrastructureDetails_infrastructure$key;
}

const InfrastructureDetails: FunctionComponent<InfrastructureDetailsProps> = ({
  infrastructure,
}) => {
  const { t_i18n, fldt } = useFormatter();

  const data: InfrastructureDetails_infrastructure$data = useFragment(
    InfrastructureDetailsFragment,
    infrastructure,
  );
  const killChainPhases = data.killChainPhases ?? [];
  const infrastructureTypes = data.infrastructure_types ?? [];
  const observablesDataSelection = [
    {
      attribute: 'entity_type',
      filters: {
        mode: 'and',
        filters: [
          {
            key: 'entity_type',
            values: 'Stix-Cyber-Observable',
          },
          {
            key: 'regardingOf',
            values: [
              { key: 'id', values: [data.id] },
              { key: 'relationship_type', values: ['consists-of'] },
            ],
          },
        ],
        filterGroups: [],
      },
    },
  ];
  return (
    <div style={{ height: '100%' }}>
      <Card title={t_i18n('Details')}>
        <Grid container={true} spacing={3}>
          <Grid item xs={6}>
            <Label>
              {t_i18n('Infrastructure types')}
            </Label>
            <FieldOrEmpty source={infrastructureTypes}>
              <Stack direction="row" flexWrap="wrap" gap={1}>
                {infrastructureTypes.length > 0
                  && infrastructureTypes.map((infrastructureType) => (
                    <Tag
                      key={infrastructureType}
                      label={infrastructureType}
                    />
                  ),
                  )}
              </Stack>
            </FieldOrEmpty>
          </Grid>
          <Grid item xs={6}>
            <Label>
              {t_i18n('Description')}
            </Label>
            <ExpandableMarkdown source={data.description} limit={400} />
          </Grid>
          <Grid item xs={6}>
            <Label>
              {t_i18n('First seen')}
            </Label>
            {data.first_seen ? fldt(data.first_seen) : EMPTY_VALUE}
          </Grid>
          <Grid item xs={6}>
            <Label>
              {t_i18n('Last seen')}
            </Label>
            {data.last_seen ? fldt(data.last_seen) : EMPTY_VALUE}
          </Grid>
          <Grid item xs={6}>
            <StixCoreObjectKillChainPhasesView killChainPhases={killChainPhases} />
          </Grid>
        </Grid>
        <br />
        <StixCoreObjectsDonut
          dataSelection={observablesDataSelection}
          parameters={{ title: t_i18n('Observables distribution') }}
          variant="inEntity"
          height={300}
          startDate={undefined}
          endDate={undefined}
          popover={undefined}
        />
      </Card>
    </div>
  );
};

export default InfrastructureDetails;
