// CG-095 Convert a Microsoft Intune (Graph) managedDevices export into CyberGuard coverage evidence.
//   Export (read-only, by an Intune administrator): GET https://graph.microsoft.com/v1.0/deviceManagement/managedDevices
//   with DeviceManagementManagedDevices.Read.All, saved as JSON. Then:
//   CG_MDM_SALT=<private random value> node scripts/mdm-to-telemetry.js <managedDevices.json> <output.json>
// Personal (BYOD) devices are pseudonymised: user names, serial numbers, phone numbers, IMEI and location are dropped.
import fs from 'node:fs';
import { managedDevices, toTelemetry } from '../lib/mdm.js';

const [input, output] = process.argv.slice(2);
if (!input || !output) { console.error('usage: CG_MDM_SALT=<secret> node scripts/mdm-to-telemetry.js <managedDevices.json> <output.json>'); process.exit(2); }
if (fs.existsSync(output)) { console.error('Output already exists. Choose a new private file path.'); process.exit(2); }
try {
  const devices = managedDevices(JSON.parse(fs.readFileSync(input, 'utf8').replace(/^﻿/, '')), { salt: process.env.CG_MDM_SALT });
  fs.writeFileSync(output, JSON.stringify(toTelemetry(devices), null, 2), { mode: 0o600, flag: 'wx' });
  const by = k => devices.reduce((o, d) => ({ ...o, [d[k]]: (o[d[k]] || 0) + 1 }), {});
  console.log(JSON.stringify({ devices: devices.length, platforms: by('platform'), ownership: by('ownership'), output }));
} catch (e) { console.error(`Refused: ${e.message}`); process.exit(1); }
