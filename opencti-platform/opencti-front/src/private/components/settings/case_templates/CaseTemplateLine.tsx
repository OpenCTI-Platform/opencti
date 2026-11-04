import React, { FunctionComponent } from 'react';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { KeyboardArrowRightOutlined } from '@mui/icons-material';
import { styled } from '@mui/material/styles';
import { graphql, useFragment } from 'react-relay';
import { Link } from 'react-router';
import { ListItemButton } from '@mui/material';
import { CaseTemplateLine_node$key } from './__generated__/CaseTemplateLine_node.graphql';
import { DataColumns } from '../../../../components/list_lines';
import ItemIcon from '../../../../components/ItemIcon';
import { bodyItemStyle } from '../../../../components/list_lines/listLineStyles';

const BodyItem = styled('div')(bodyItemStyle);

export const CaseTemplateLineFragment = graphql`
  fragment CaseTemplateLine_node on CaseTemplate {
    entity_type
    id
    name
    description
    tasks {
      edges {
        node {
          id
          name
        }
      }
      pageInfo {
        globalCount
      }
    }
  }
`;

interface CaseTemplateLineProps {
  node: CaseTemplateLine_node$key;
  dataColumns: DataColumns;
}

const CaseTemplateLine: FunctionComponent<CaseTemplateLineProps> = ({
  node,
  dataColumns,
}) => {
  const data = useFragment(CaseTemplateLineFragment, node);

  return (
    <ListItemButton
      sx={{ paddingLeft: '10px', height: 50 }}
      component={Link}
      divider
      to={`/dashboard/settings/vocabularies/case_templates/${data.id}`}
    >
      <ListItemIcon>
        <ItemIcon type="Case-Template" />
      </ListItemIcon>
      <ListItemText
        primary={(
          <>
            {Object.values(dataColumns).map((value) => (
              <BodyItem
                key={value.label}
                style={{ width: value.width }}
              >
                {value.render?.(data)}
              </BodyItem>
            ))}
          </>
        )}
      />
      <ListItemIcon sx={{ position: 'absolute', right: -10 }}>
        <KeyboardArrowRightOutlined />
      </ListItemIcon>
    </ListItemButton>
  );
};

export default CaseTemplateLine;
