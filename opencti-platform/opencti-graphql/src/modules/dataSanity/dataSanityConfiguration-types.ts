export type DayOfWeek = 'monday' | 'tuesday' | 'wednesday' | 'thursday' | 'friday' | 'saturday' | 'sunday';

export interface MaintenanceWindow {
  day: DayOfWeek;
  start_time: string; // "HH:mm" format (e.g., "22:30")
  end_time: string; // "HH:mm" format (e.g., "04:15")
}

export type MaintenancePlanning = MaintenanceWindow[];

export interface DataSanityConfigurationObject {
  maintenance_planning: string; // JSON-serialized MaintenancePlanning
  timezone_offset: number; // UTC offset in minutes (e.g., 120 for UTC+2, -300 for UTC-5)
}
