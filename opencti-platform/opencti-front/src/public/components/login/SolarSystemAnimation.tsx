import { Box, SxProps, Theme } from '@mui/material';
import { useEffect, useRef } from 'react';
import type { ReactNode } from 'react';

import DatabaseIcon from './icons/DatabaseIcon';
import DashboardIcon from './icons/DashboardIcon';
import PipelineIcon from './icons/PipelineIcon';
import HSMIcon from './icons/HSMIcon';
import ServiceMeshIcon from './icons/ServiceMeshIcon';
import TreatActorIcon from './icons/TreatActorIcon';
import AutomationIcon from './icons/AutomationIcon';
import NotificationIcon from './icons/NotificationChannelsIcon';
import ReportIcon from './icons/ReportIcon';
import { fileUri } from '../../../relay/environment';
import Circles from '../../../static/images/Circles.png';
interface PlanetPosition {
  top?: string | number;
  bottom?: string | number;
  left?: string | number;
  right?: string | number;
  transform?: string;
}

interface Planet {
  icon: ReactNode;
  position: PlanetPosition;
}

interface OrbitRing {
  size: number;
  duration: number;
  planets: Planet[];
}

const PLANET_SIZE = 62;
const PLANET_HALF = PLANET_SIZE / 2;

function circularPositions(count: number, containerSize: number) {
  const positions: PlanetPosition[] = [];
  const radius = containerSize / 2;
  for (let i = 0; i < count; i++) {
    const angle = (2 * Math.PI * i) / count - Math.PI / 2;
    const cx = containerSize / 2 + radius * Math.cos(angle);
    const cy = containerSize / 2 + radius * Math.sin(angle);
    positions.push({
      top: cy - PLANET_HALF,
      left: cx - PLANET_HALF,
    });
  }
  return positions;
}

const iconSize = { width: 32, height: 32 };

const orbits: OrbitRing[] = [
  {
    size: 272,
    duration: 20,
    planets: circularPositions(2, 272).map((position) => ({
      icon: <DashboardIcon {...iconSize} />,
      position,
    })),
  },
  {
    size: 633,
    duration: 35,
    planets: [
      ServiceMeshIcon,
      HSMIcon,
      TreatActorIcon,
      ServiceMeshIcon,
      HSMIcon,
      TreatActorIcon,
    ].map((Icon, i) => ({
      icon: <Icon {...iconSize} />,
      position: circularPositions(6, 633)[i],
    })),
  },
  {
    size: 916,
    duration: 50,
    planets: [
      DatabaseIcon,
      NotificationIcon,
      AutomationIcon,
      PipelineIcon,
      ReportIcon,
      DatabaseIcon,
      NotificationIcon,
      AutomationIcon,
      PipelineIcon,
      ReportIcon,
    ].map((Icon, i) => ({
      icon: <Icon {...iconSize} />,
      position: circularPositions(10, 916)[i],
    })),
  },
];

const planetSx: SxProps<Theme> = {
  position: 'absolute',
  width: 62,
  height: 62,
  borderRadius: '50%',
  // backgroundColor: 'rgba(255, 255, 255, 0.08)',
  // border: '1px solid rgba(255, 255, 255, 0.15)',
  backdropFilter: 'blur(10px)',
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'center',
  // boxShadow:
  //   '0 0 20px rgba(0, 0, 0, 0.25), inset 0 0 12px rgba(255, 255, 255, 0.08)',
  '& .planet-icon': {
    width: 32,
    height: 32,
  },
};

const KEYFRAMES_STYLE_ID = 'solar-system-keyframes';

const SolarSystemAnimation = ({ sx }: { sx?: SxProps<Theme> }) => {
  const styleInjected = useRef(false);

  useEffect(() => {
    if (styleInjected.current) return;
    styleInjected.current = true;

    const style = document.createElement('style');
    style.id = KEYFRAMES_STYLE_ID;
    style.textContent = `
      @keyframes rotate {
        from { transform: translate(-50%, -50%) rotate(0deg); }
        to   { transform: translate(-50%, -50%) rotate(360deg); }
      }
      @keyframes counterRotate {
        from { transform: rotate(0deg); }
        to   { transform: rotate(-360deg); }
      }
    `;
    document.head.appendChild(style);

    return () => {
      document.getElementById(KEYFRAMES_STYLE_ID)?.remove();
      styleInjected.current = false;
    };
  }, []);

  return (
    <Box
      sx={{
        position: 'absolute',
        inset: 0,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        overflow: 'hidden',
        left: '-100%',
        backgroundImage: `url(${fileUri(Circles)})`,
        backgroundPosition: 'center',
        backgroundRepeat: 'no-repeat',
        ...sx,
      }}
    >
      <Box
        sx={{
          position: 'absolute',
          width: 500,
          height: 500,
          borderRadius: '50%',
          left: '50%',
          top: '50%',
          transform: 'translate(-50%, -50%)',
          background:
            'radial-gradient(circle, rgba(255,255,255,0.15), rgba(255,255,255,0.02), transparent 70%)',
        }}
      />

      {orbits.map((orbit, orbitIndex) => (
        <Box
          key={orbitIndex}
          sx={{
            position: 'absolute',
            left: '50%',
            top: '50%',
            transform: 'translate(-50%, -50%)',
            width: orbit.size,
            height: orbit.size,
            border: '1px solid rgba(255, 255, 255, 0.08)',
            borderRadius: '50%',
            animation: `rotate ${orbit.duration}s linear infinite`,
          }}
        >
          {orbit.planets.map((planet, planetIndex) => (
            <Box
              key={planetIndex}
              sx={{
                background: 'radial-gradient(50% 50% at 50% 50%, #5C44FC 61.06%, #372996 100%)',
                border: '2px solid #6553DE',
                ...planetSx,
                ...planet.position,
              }}
            >
              <Box
                className="planet-icon"
                sx={{
                  animation: `counterRotate ${orbit.duration}s linear infinite`,
                }}
              >
                {planet.icon}
              </Box>
            </Box>
          ))}
        </Box>
      ))}
    </Box>
  );
};

export default SolarSystemAnimation;
