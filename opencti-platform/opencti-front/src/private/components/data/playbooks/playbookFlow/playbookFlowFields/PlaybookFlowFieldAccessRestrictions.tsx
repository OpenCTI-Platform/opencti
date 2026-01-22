/*
Copyright (c) 2021-2025 Filigran SAS

This file is part of the OpenCTI Enterprise Edition ("EE") and is
licensed under the OpenCTI Enterprise Edition License (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://github.com/OpenCTI-Platform/opencti/blob/master/LICENSE

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*/

import { Field } from 'formik';
import { useFormatter } from '../../../../../../components/i18n';
import AuthorizedMembersField from '../../../../common/form/AuthorizedMembersField';

const PlaybookFlowFieldAccessRestrictions = () => {
  const { t_i18n } = useFormatter();

  return (
    <Field
      hideInfo
      adminDefault
      enableAccesses
      showAllMembersLine
      dynamicKeysForPlaybooks
      name="access_restrictions"
      label={t_i18n('Access restrictions')}
      component={AuthorizedMembersField}
    />
  );
};

export default PlaybookFlowFieldAccessRestrictions;
