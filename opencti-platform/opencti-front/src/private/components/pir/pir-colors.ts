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

import { itemColor } from '../../../utils/Colors';

// OpenCTI's `itemColor` groups every threat entity into the same "allThreats"
// orange (and Malware into the "arsenal" gold), which makes the PIR threat
// landscape look monochrome. We give each threat type a distinct, deliberate
// hue so analysts can tell them apart at a glance, and fall back to the
// platform color for any other entity type.
const PIR_ENTITY_COLORS: Record<string, string> = {
  Malware: '#F44336', // red
  Campaign: '#A66BFF', // purple
  'Intrusion-Set': '#FF9800', // amber
  'Threat-Actor': '#26C6DA', // cyan
  'Threat-Actor-Group': '#26C6DA',
  'Threat-Actor-Individual': '#26C6DA',
};

export const pirEntityColor = (type?: string | null): string => {
  if (type && PIR_ENTITY_COLORS[type]) return PIR_ENTITY_COLORS[type];
  return itemColor(type);
};
