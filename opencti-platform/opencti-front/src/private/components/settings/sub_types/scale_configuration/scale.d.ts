export interface Scale {
  local_config: ScaleConfig;
}

export interface ScaleConfig {
  better_side: string;
  min: Tick;
  max: Tick;
  ticks: Array<Tick | UndefinedTick>;
}

export interface Tick {
  value: number;
  color: string;
  label: string;
}

export interface UndefinedTick {
  value: string;
  label: string;
  color: string;
}
