import {mkdirSync,readdirSync,readFileSync,writeFileSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import {resolve} from 'node:path';
// Local-only config adds migration tracking without modifying build output.
mkdirSync('.wrangler',{recursive:true});
const config=JSON.parse(readFileSync('dist/server/wrangler.json','utf8'));
config.main=resolve('dist/server/index.js');
if(config.assets)config.assets.directory=resolve('dist/client');
for(const binding of config.d1_databases||[])binding.migrations_dir=resolve('drizzle');
writeFileSync('.wrangler/local-migrations.json',JSON.stringify(config,null,2));
const r=spawnSync(process.execPath,['--import','./scripts/sites-env.mjs','./node_modules/wrangler/bin/wrangler.js','d1','migrations','apply','DB','--local','--config','.wrangler/local-migrations.json','--persist-to','.wrangler/state'],{stdio:'inherit'});
process.exit(r.status||0);
