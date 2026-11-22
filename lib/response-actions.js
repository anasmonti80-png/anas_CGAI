import { isIP } from 'node:net';
import { fail, text, object, choice, integer } from './common.js';

const entry = (id, owner, target, inverse, risk='high', options={}) => Object.freeze({id,owner,target,inverse,risk,requirement:'CG-029',typed_only:true,raw_command_allowed:false,...options});

export const responseActionCatalog = Object.freeze({
  'network.block-ip':entry('network.block-ip','cyberguard-connector','ip','network.allow-ip','high',{requires_management_preflight:true}),
  'network.allow-ip':entry('network.allow-ip','cyberguard-connector','ip','network.block-ip'),
  'network.block-port':entry('network.block-port','cyberguard-connector','network-port','network.allow-port','high',{requires_management_preflight:true}),
  'network.allow-port':entry('network.allow-port','cyberguard-connector','network-port','network.block-port'),
  'endpoint.block-app':entry('endpoint.block-app','cyberguard-connector','application','endpoint.allow-app','high',{requires_management_preflight:true}),
  'endpoint.allow-app':entry('endpoint.allow-app','cyberguard-connector','application','endpoint.block-app'),
  'dns.block-domain':entry('dns.block-domain','cyberguard-connector','domain','dns.allow-domain','high',{requires_management_preflight:true}),
  'dns.allow-domain':entry('dns.allow-domain','cyberguard-connector','domain','dns.block-domain'),
  'endpoint.stop-service':entry('endpoint.stop-service','cyberguard-connector','service','endpoint.start-service','high',{requires_management_preflight:true}),
  'endpoint.disable-service':entry('endpoint.disable-service','cyberguard-connector','service','endpoint.enable-service','high',{requires_management_preflight:true}),
  'endpoint.quarantine-file':entry('endpoint.quarantine-file','cyberguard-connector','file','endpoint.restore-file','critical',{requires_management_preflight:true}),
  'endpoint.isolate-device':entry('endpoint.isolate-device','cyberguard-connector','device','endpoint.reconnect-device','critical',{requires_management_preflight:true}),
  'endpoint.reconnect-device':entry('endpoint.reconnect-device','cyberguard-connector','device','endpoint.isolate-device','critical'),
  'endpoint.shutdown-host':entry('endpoint.shutdown-host','cyberguard-connector','device',null,'critical',{requires_management_preflight:true}),
  'network.switch-port-admin-down':entry('network.switch-port-admin-down','ncc-scoped-api','physical-switch-port','network.switch-port-admin-up','critical',{requires_management_preflight:true}),
  'network.nac-quarantine-endpoint':entry('network.nac-quarantine-endpoint','cisco-ise','nac-endpoint','network.nac-release-endpoint','critical',{requirement:'CG-041',requires_management_preflight:true}),
  // CG-120 cloud provider actions (AWS, Azure, Google Cloud) through a scoped cloud connector, typed like every other action.
  'cloud.isolate-instance':entry('cloud.isolate-instance','cloud-connector','cloud-resource','cloud.release-instance','critical',{requirement:'CG-120'}),
  'cloud.release-instance':entry('cloud.release-instance','cloud-connector','cloud-resource','cloud.isolate-instance','high',{requirement:'CG-120'}),
  'cloud.disable-access-key':entry('cloud.disable-access-key','cloud-connector','cloud-credential','cloud.enable-access-key','high',{requirement:'CG-120'}),
  'cloud.enable-access-key':entry('cloud.enable-access-key','cloud-connector','cloud-credential','cloud.disable-access-key','high',{requirement:'CG-120'}),
  'network.nac-release-endpoint':entry('network.nac-release-endpoint','cisco-ise','nac-endpoint','network.nac-quarantine-endpoint','high',{requirement:'CG-041'}),
  'endpoint.remove-service':entry('endpoint.remove-service','cyberguard-connector','permanent-service-removal','endpoint.restore-service','critical',{requirement:'CG-030',requires_service_preflight:true,requires_safety_approval:true,requires_management_preflight:true}),
  'endpoint.change-service-permanent':entry('endpoint.change-service-permanent','cyberguard-connector','permanent-service-change','endpoint.restore-service-configuration','critical',{requirement:'CG-030',requires_service_preflight:true,requires_safety_approval:true,requires_management_preflight:true}),
});

const domainPattern=/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
const sha256Pattern=/^[a-f0-9]{64}$/;

export function validateResponseTarget(type, value) {
  const spec=responseActionCatalog[type];fail(spec,400,'unsupported_response_action');
  const target=object(value,['mac','policy_name','ip','protocol','port','direction','application_ref','domain','service_ref','file_ref','sha256','device_ref','interface_ref','port_role','provenance_ref','desired_configuration_ref','expected_postcondition','recovery_plan','provider','resource_id','principal_ref','key_ref'],'response_target');
  if(spec.target==='ip'){fail(isIP(target.ip)!==0,400,'invalid_response_ip');return {ip:target.ip};}
  if(spec.target==='network-port')return {protocol:choice(target.protocol,['tcp','udp'],'response_protocol'),port:integer(target.port,1,65535,'response_port'),direction:choice(target.direction,['inbound','outbound','both'],'response_direction')};
  if(spec.target==='application')return {application_ref:text(target.application_ref,'application_ref',500)};
  if(spec.target==='domain'){const domain=text(target.domain,'response_domain',253).toLowerCase();fail(domainPattern.test(domain),400,'invalid_response_domain');return {domain};}
  if(spec.target==='service')return {service_ref:text(target.service_ref,'service_ref',500)};
  if(spec.target==='file'){const sha256=text(target.sha256,'response_file_sha256',64).toLowerCase();fail(sha256Pattern.test(sha256),400,'invalid_response_file_sha256');return {file_ref:text(target.file_ref,'file_ref',1000),sha256};}
  if(spec.target==='device')return {device_ref:text(target.device_ref,'device_ref',500)};
  if(spec.target==='cloud-resource')return {provider:choice(target.provider,['aws','azure','gcp'],'response_cloud_provider'),resource_id:text(target.resource_id,'response_cloud_resource_id',500)};
  if(spec.target==='cloud-credential')return {provider:choice(target.provider,['aws','azure','gcp'],'response_cloud_provider'),principal_ref:text(target.principal_ref,'response_cloud_principal',300),key_ref:text(target.key_ref,'response_cloud_key_ref',300)};
  if(spec.target==='nac-endpoint'){const mac=text(target.mac,'response_mac',17).toUpperCase();fail(/^([0-9A-F]{2}:){5}[0-9A-F]{2}$/.test(mac),400,'invalid_response_mac');const policy_name=text(target.policy_name,'response_anc_policy',64);fail(/^[A-Za-z0-9_.-]{1,64}$/.test(policy_name),400,'invalid_response_anc_policy');return {mac,policy_name};}
  if(spec.target==='permanent-service-removal'||spec.target==='permanent-service-change'){
    const recovery=object(target.recovery_plan,['method','artifact_ref','owner_ref','steps','verification_steps'],'service_recovery_plan');
    fail(Array.isArray(recovery.steps)&&recovery.steps.length>=1&&recovery.steps.length<=20,400,'invalid_service_recovery_steps');
    fail(Array.isArray(recovery.verification_steps)&&recovery.verification_steps.length>=1&&recovery.verification_steps.length<=10,400,'invalid_service_recovery_verification_steps');
    const result={service_ref:text(target.service_ref,'service_ref',500),expected_postcondition:choice(target.expected_postcondition,spec.target==='permanent-service-removal'?['absent']:['configured'],'service_expected_postcondition'),recovery_plan:{method:choice(recovery.method,['reinstall','restore-configuration','rollback-package','restore-snapshot'],'service_recovery_method'),artifact_ref:text(recovery.artifact_ref,'service_recovery_artifact_ref',500),owner_ref:text(recovery.owner_ref,'service_recovery_owner_ref',300),steps:recovery.steps.map((step,index)=>text(step,`service_recovery_step_${index}`,500)),verification_steps:recovery.verification_steps.map((step,index)=>text(step,`service_recovery_verification_${index}`,500))}};
    if(spec.target==='permanent-service-change')result.desired_configuration_ref=text(target.desired_configuration_ref,'desired_configuration_ref',500);
    return result;
  }
  const port_role=choice(target.port_role,['edge'],'switch_port_role');
  return {device_ref:text(target.device_ref,'device_ref',500),interface_ref:text(target.interface_ref,'interface_ref',300),port_role,provenance_ref:text(target.provenance_ref,'switch_port_provenance_ref',500)};
}

export function responseActionTypes() { return Object.values(responseActionCatalog); }
