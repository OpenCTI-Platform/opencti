import React, { FunctionComponent } from 'react';
import { Link } from 'react-router';
import ListItem from '@mui/material/ListItem';
import ListItemButton from '@mui/material/ListItemButton';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { MoreVert } from '@mui/icons-material';
import Skeleton from '@mui/material/Skeleton';
import { graphql, useFragment } from 'react-relay';
import { styled } from '@mui/material/styles';
import { DataColumns } from '../../../../components/list_lines';
import { FormLine_node$key } from './__generated__/FormLine_node.graphql';
import { FormLinesPaginationQuery$variables } from './__generated__/FormLinesPaginationQuery.graphql';
import { useFormatter } from '../../../../components/i18n';
import FormPopover from './FormPopover';
import ItemBoolean from '../../../../components/ItemBoolean';
import ItemIcon from '../../../../components/ItemIcon';
import { EMPTY_VALUE } from '../../../../utils/String';
import { bodyItemStyle } from '../../../../components/list_lines/listLineStyles';

const BodyItem = styled('div')(bodyItemStyle);

const formLineFragment = graphql`
  fragment FormLine_node on Form {
    id
    name
    description
    active
    created_at
    updated_at
    form_schema
  }
`;

interface FormLineComponentProps {
  dataColumns: DataColumns;
  node: FormLine_node$key;
  paginationOptions: FormLinesPaginationQuery$variables;
}

export const FormLineComponent: FunctionComponent<FormLineComponentProps> = ({
  dataColumns,
  node,
  paginationOptions,
}) => {
  const { t_i18n, ftd } = useFormatter();
  const data = useFragment(formLineFragment, node);

  let mainEntityType = 'Unknown';
  try {
    const schema = JSON.parse(data.form_schema);
    mainEntityType = schema.mainEntityType || 'Unknown';
  } catch {
    // Invalid JSON, keep default
  }

  return (
    <ListItem
      divider={true}
      disablePadding
      secondaryAction={(
        <FormPopover
          formId={data.id}
          formName={data.name}
          paginationOptions={paginationOptions}
        />
      )}
    >
      <ListItemButton
        sx={{ paddingLeft: '10px', height: 50 }}
        component={Link}
        to={`/dashboard/integrations/feeds/form/${data.id}`}
      >
        <ListItemIcon sx={{ color: 'primary.main' }}>
          <ItemIcon type={mainEntityType} />
        </ListItemIcon>
        <ListItemText
          primary={(
            <div>
              <BodyItem style={{ width: dataColumns.name.width }}>
                {data.name}
              </BodyItem>
              <BodyItem style={{ width: dataColumns.description.width }}>
                {data.description || EMPTY_VALUE}
              </BodyItem>
              <BodyItem style={{ width: dataColumns.mainEntityType.width }}>
                {mainEntityType}
              </BodyItem>
              <BodyItem style={{ width: dataColumns.active.width }}>
                <ItemBoolean
                  label={data.active ? t_i18n('Active') : t_i18n('Inactive')}
                  status={!!data.active}
                />
              </BodyItem>
              <BodyItem style={{ width: dataColumns.updated_at.width }}>
                {ftd(data.updated_at)}
              </BodyItem>
            </div>
          )}
        />
      </ListItemButton>
    </ListItem>
  );
};

export const FormLineDummy: FunctionComponent<{ dataColumns: DataColumns }> = ({
  dataColumns,
}) => {
  return (
    <ListItem
      sx={{ paddingLeft: '10px', height: 50 }}
      divider={true}
      secondaryAction={<MoreVert sx={{ color: 'grey.700' }} />}
    >
      <ListItemIcon sx={{ color: 'primary.main' }}>
        <Skeleton
          animation="wave"
          variant="circular"
          width={30}
          height={30}
        />
      </ListItemIcon>
      <ListItemText
        primary={(
          <div>
            {Object.entries(dataColumns).map(([key, column]) => (
              <BodyItem
                key={key}
                style={{ width: column.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rectangular"
                  width="90%"
                  height="100%"
                />
              </BodyItem>
            ))}
          </div>
        )}
      />
    </ListItem>
  );
};
