import { DatabaseSync } from 'node:sqlite';
import {readFileSync,readdirSync} from 'node:fs';
export const sqlite=new DatabaseSync(':memory:');
for(const file of readdirSync('drizzle').filter(f=>f.endsWith('.sql')).sort())sqlite.exec(readFileSync('drizzle/'+file,'utf8'));
function statement(sql,args=[]){const query=()=>sqlite.prepare(sql);return{bind(...values){return statement(sql,values)},async all(){return{results:query().all(...args)}},async first(){return query().get(...args)||null},exec(){return query().run(...args)},async run(){return query().run(...args)}}}
export const env={DB:{prepare:statement,async batch(list){sqlite.exec('BEGIN');try{const results=[];for(const item of list)results.push(item.exec());sqlite.exec('COMMIT');return results}catch(e){sqlite.exec('ROLLBACK');throw e}}}};
