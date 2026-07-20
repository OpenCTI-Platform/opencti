import React, { FunctionComponent, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import Table from '@mui/material/Table';
import TableBody from '@mui/material/TableBody';
import TableCell from '@mui/material/TableCell';
import TableContainer from '@mui/material/TableContainer';
import TableHead from '@mui/material/TableHead';
import TableRow from '@mui/material/TableRow';
import Paper from '@mui/material/Paper';
import IconButton from '@mui/material/IconButton';
import { DeleteOutlined } from '@mui/icons-material';
import Tooltip from '@mui/material/Tooltip';
import Breadcrumbs from '../../../components/Breadcrumbs';
import { useFormatter } from '../../../components/i18n';
import ItemBoolean from '../../../components/ItemBoolean';
import PreprocessingCreation from './preprocessing/PreprocessingCreation';
import { deleteRule, getRules, PreprocessingRule, toggleRule } from './preprocessing/preprocessingStore';
import useConnectedDocumentModifier from '../../../utils/hooks/useConnectedDocumentModifier';

const Preprocessing: FunctionComponent = () => {
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('Pre-processing | Data'));
  const [rules, setRules] = useState<PreprocessingRule[]>(getRules());
  const refresh = () => setRules(getRules());
  const handleDelete = (event: React.MouseEvent, id: string) => { event.stopPropagation(); deleteRule(id); refresh(); };
  const handleToggle = (event: React.MouseEvent, id: string) => { event.stopPropagation(); toggleRule(id); refresh(); };
  return (
    <div style={{ paddingRight: '200px', height: '100%', minWidth: 1280 }}>
      <Breadcrumbs elements={[{ label: t_i18n('Data') }, { label: t_i18n('Pre-processing'), current: true }]} />
      <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: 16 }}>
        <PreprocessingCreation onCreated={refresh} />
      </div>
      <TableContainer component={Paper} variant="outlined">
        <Table>
          <TableHead>
            <TableRow>
              <TableCell>{t_i18n('Rule name')}</TableCell>
              <TableCell>{t_i18n('Creator')}</TableCell>
              <TableCell>{t_i18n('Status')}</TableCell>
              <TableCell align="right">{t_i18n('Actions')}</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {rules.length === 0 && (
              <TableRow><TableCell colSpan={4} align="center">{t_i18n('No pre-processing rules defined yet')}</TableCell></TableRow>
            )}
            {rules.map((rule) => (
              <TableRow key={rule.id} hover style={{ cursor: 'pointer' }} onClick={() => navigate(/dashboard/data/preprocessing/${rule.id})}>
                <TableCell>{rule.name}</TableCell>
                <TableCell>{rule.creator}</TableCell>
                <TableCell>
                  <span onClick={(e) => handleToggle(e, rule.id)} style={{ cursor: 'pointer' }}>
                    <ItemBoolean label={rule.active ? t_i18n('Active') : t_i18n('Inactive')} status={rule.active} />
                  </span>
                </TableCell>
                <TableCell align="right">
                  <Tooltip title={t_i18n('Delete')}>
                    <IconButton size="small" onClick={(e) => handleDelete(e, rule.id)}><DeleteOutlined fontSize="small" /></IconButton>
                  </Tooltip>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>
    </div>
  );
};
export default Preprocessing;
