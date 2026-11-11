import {createApp} from '../server.js';
const major=Number(process.versions.node.split('.')[0]),minor=Number(process.versions.node.split('.')[1]);
if(major!==24||minor<21)throw new Error('Node.js 24.21.0 or newer within major 24 is required.');
const app=createApp();const address=await app.listen(Number(process.env.CG_PORT||4310));
console.log(`CyberGuard AI: http://127.0.0.1:${address.port}`);
console.log('Engineering preview. Localhost only. No production protection claim.');
if(!app.store.get('SELECT id FROM users LIMIT 1'))console.log(`Read the setup token privately from: ${app.setupFile}`);
for(const signal of ['SIGINT','SIGTERM'])process.once(signal,()=>app.close().then(()=>process.exit(0)));
