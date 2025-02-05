import { graphql } from 'react-relay';
import React, { FunctionComponent, useEffect, useState } from 'react';
import MenuItem from '@mui/material/MenuItem';
import { Field } from 'formik';
import { DisseminationListFieldQuery$data } from './__generated__/DisseminationListFieldQuery.graphql';
import { fetchQuery } from '../../relay/environment';
import SelectField from './SelectField';
import { useFormatter } from '../i18n';

export const disseminationListFieldQuery = graphql`
    query DisseminationListFieldQuery(
        $cursor: ID
        $orderBy: DisseminationListOrdering
        $orderMode: OrderingMode
        $filters: FilterGroup
    ) {
        disseminationLists(
            after: $cursor
            orderBy: $orderBy
            orderMode: $orderMode
            filters: $filters
        ) {
            edges {
                node {
                    id
                    name
                }
            }
        }
    }
`;

const DisseminationListField: FunctionComponent = () => {
  const { t_i18n } = useFormatter();
  const [lists, setLists] = useState<DisseminationListFieldQuery$data['disseminationLists'] | null>(null);

  const fetchDisseminationLists = async () => {
    return await fetchQuery(disseminationListFieldQuery, {
    })
      .toPromise() as Promise<DisseminationListFieldQuery$data>;
  };

  useEffect(() => {
    fetchDisseminationLists().then((response) => {
      setLists(response?.disseminationLists ?? { edges: [] });
    });
  }, []);

  return (
    <Field
      component={SelectField}
      label={t_i18n('Dissemination list')}
      name="disseminationListId"
      required
    >
      {lists?.edges?.map((edge) => (
        <MenuItem key={edge.node.id} value={edge.node.id}>
          {edge.node.name}
        </MenuItem>
      ))}
    </Field>
  );
};

export default DisseminationListField;
