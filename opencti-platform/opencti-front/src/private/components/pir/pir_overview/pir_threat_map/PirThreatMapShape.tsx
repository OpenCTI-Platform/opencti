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

import React from 'react';
import { PirThreatMapShape as Shape } from './pirThreatMapUtils';

interface PirThreatMapShapeProps {
  shape: Shape;
  color: string;
  size?: number;
}

// The marker of an entity type as the map draws it, for the legend and the tooltip.
const PirThreatMapShape = ({ shape, color, size = 12 }: PirThreatMapShapeProps) => {
  let path: React.ReactNode;
  switch (shape) {
    case 'square':
      path = <rect x="1" y="1" width="10" height="10" fill={color} />;
      break;
    case 'diamond':
      path = <polygon points="6,0 12,6 6,12 0,6" fill={color} />;
      break;
    case 'triangle':
      path = <polygon points="6,0 12,12 0,12" fill={color} />;
      break;
    case 'star':
      path = <polygon points="6,0 7.8,4.2 12,4.6 8.8,7.4 9.7,12 6,9.6 2.3,12 3.2,7.4 0,4.6 4.2,4.2" fill={color} />;
      break;
    default:
      path = <circle cx="6" cy="6" r="5.5" fill={color} />;
  }
  return (
    <svg width={size} height={size} viewBox="0 0 12 12" aria-hidden="true" style={{ flexShrink: 0 }}>
      {path}
    </svg>
  );
};

export default PirThreatMapShape;
