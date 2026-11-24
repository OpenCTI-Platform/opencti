import React, { FunctionComponent } from 'react';
import { graphql, useFragment } from 'react-relay';
import { Link } from 'react-router';
import Box from '@mui/material/Box';
import Table from '@mui/material/Table';
import TableBody from '@mui/material/TableBody';
import TableCell from '@mui/material/TableCell';
import TableHead from '@mui/material/TableHead';
import TableRow from '@mui/material/TableRow';
import { Alert, Chip } from '@filigran/design-system';
import Card from '@common/card/Card';
import { useFormatter } from '../../../../components/i18n';
import { resolveLink } from '../../../../utils/Entity';
import { ProcedureComponents_procedure$key } from './__generated__/ProcedureComponents_procedure.graphql';

const ProcedureComponentsFragment = graphql`
  fragment ProcedureComponents_procedure on Procedure {
    id
    procedureComponents {
      relationship_id
      component_index
      component_type
      observable {
        id
        entity_type
        observable_value
      }
    }
  }
`;

// A sequence is complete when its indexes run 0..n-1 with no gap or duplicate.
export const isSequenceComplete = (indexes: readonly number[]) => {
  const sorted = [...indexes].sort((a, b) => a - b);
  return sorted.every((index, position) => index === position);
};

interface ProcedureComponentsProps {
  procedure: ProcedureComponents_procedure$key;
}

const ProcedureComponents: FunctionComponent<ProcedureComponentsProps> = ({ procedure }) => {
  const { t_i18n } = useFormatter();
  const data = useFragment(ProcedureComponentsFragment, procedure);
  const components = [...(data.procedureComponents ?? [])].sort((a, b) => a.component_index - b.component_index);
  const complete = isSequenceComplete(components.map((c) => c.component_index));
  return (
    <Card title={t_i18n('Components')}>
      {!complete && (
        <Box sx={{ marginBottom: 2 }}>
          <Alert
            severity="warning"
            title={t_i18n('Sequence incomplete')}
            description={t_i18n('Some positions in the sequence have no component.')}
          />
        </Box>
      )}
      {components.length === 0 ? (
        <span>{t_i18n('No components')}</span>
      ) : (
        <Table size="small" aria-label={t_i18n('Components')}>
          <TableHead>
            <TableRow>
              <TableCell>#</TableCell>
              <TableCell>{t_i18n('Type')}</TableCell>
              <TableCell>{t_i18n('Entity type')}</TableCell>
              <TableCell>{t_i18n('Value')}</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {components.map((component) => (
              <TableRow key={component.relationship_id}>
                <TableCell>{component.component_index}</TableCell>
                <TableCell>
                  <Chip
                    label={component.component_type === 'primary' ? t_i18n('Primary') : t_i18n('Secondary')}
                    severity={component.component_type === 'primary' ? 'info' : 'neutral'}
                  />
                </TableCell>
                <TableCell>{t_i18n(`entity_${component.observable.entity_type}`)}</TableCell>
                <TableCell sx={{ wordBreak: 'break-all' }}>
                  <Link to={`${resolveLink(component.observable.entity_type)}/${component.observable.id}`}>
                    {component.observable.observable_value}
                  </Link>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
    </Card>
  );
};

export default ProcedureComponents;
