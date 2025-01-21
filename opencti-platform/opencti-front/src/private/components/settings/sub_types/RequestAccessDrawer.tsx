import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery, useFragment, usePreloadedQuery } from 'react-relay';
import Drawer from '@components/common/drawer/Drawer';
import Chip from '@mui/material/Chip';
import { requestAccessFragment } from '@components/settings/sub_types/RequestAccessStatus';
import { hexToRGB } from '../../../../utils/Colors';
import { SubTypeWorkflowEditionQuery } from './__generated__/SubTypeWorkflowEditionQuery.graphql';
import { useFormatter } from '../../../../components/i18n';

export const requestAccessDrawerQuery = graphql`
  query RequestAccessDrawerEditionQuery($id: String!) {
    subType(id: $id) {
      ...RequestAccessDrawer_subType
    }
  }
`;

export const requestAccessEditionFragment = graphql`
    fragment RequestAccessDrawer_subType on SubType {
        id
    }
`;

interface RequestAccessDrawerProps {
  handleClose: () => void
  queryRef: PreloadedQuery<SubTypeWorkflowEditionQuery>
  open?: boolean
}

const RequestAccessDrawer: FunctionComponent<RequestAccessDrawerProps> = ({
  handleClose,
  open,
  queryRef,
}) => {
  const { t_i18n } = useFormatter();
  const queryData = usePreloadedQuery(requestAccessDrawerQuery, queryRef);
  const subType = useFragment(
    requestAccessFragment,
    queryData.subType,
  );

  console.log('ANGIE subType', { subType });

  return (
    <Drawer
      open={open}
      title={`${t_i18n('Request access settings')}`}
      onClose={handleClose}
    >
      <>
        <div>
          <div>
            {t_i18n('Approve to status:')}
            <Chip
              variant="outlined"
              label={'APPROVED_STATUS'}
              style={{
                fontSize: 12,
                lineHeight: '12px',
                height: 25,
                margin: 7,
                textTransform: 'uppercase',
                borderRadius: 4,
                width: 100,
                backgroundColor: hexToRGB(
                  '#000000',
                ),
              }}
            />
          </div>

          <div>
            {t_i18n('Declined to status:')}
            <Chip
              variant="outlined"
              label={'DECLINED_STATUS'}
              style={{
                fontSize: 12,
                lineHeight: '12px',
                height: 25,
                margin: 7,
                textTransform: 'uppercase',
                borderRadius: 4,
                width: 100,
                backgroundColor: hexToRGB(
                  '#000000',
                ),
              }}
            />
          </div>
        </div>
        <div>
          {t_i18n('Request access admin:')}
          <Chip
            variant="outlined"
            label={'TODO UNE ORGA'}
            style={{
              fontSize: 12,
              lineHeight: '12px',
              height: 25,
              margin: 7,
              textTransform: 'uppercase',
              borderRadius: 4,
              width: 100,
              backgroundColor: hexToRGB(
                '#000000',
              ),
            }}
          />
        </div>
      </>
    </Drawer>
  );
};

export default RequestAccessDrawer;
