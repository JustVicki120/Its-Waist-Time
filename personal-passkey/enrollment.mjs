// Separate, unpublished browser enrollment. No app storage or native bridge.
const origin='https://xqczjqonivguoeltskon.supabase.co';
const account='553089d1-232f-423f-b808-34cafa08f237';
const rp='itswaisttime.com';
const marker='waist-personal-enrollment-pending-v1';
const emailMarker='waist-personal-email-attempt-v1';
export function enrollment({enabled=false,fetcher=fetch,storage=localStorage,credentials=navigator.credentials,pageOrigin=location.origin,topLevel=typeof window==='undefined'||window.self===window.top,locks=navigator.locks,key,now=Date.now,requestTimeoutMs=20000}) {
  let token, pendingToken, pendingId, busy=false;
  const gate=()=>{if(!enabled||!topLevel||pageOrigin!=='https://'+rp)throw Error('Personal enrollment is not activated.');};
  async function request(path,method,body,authenticated=true,authToken=token) {
    gate();if(authenticated&&!authToken)throw Error('Sign in to your existing account first.');
    const controller=new AbortController();let timer;
    const work=(async()=>{
      const response=await fetcher(origin+'/auth/v1/'+path,{method,headers:{apikey:key,'Content-Type':'application/json',...(authenticated?{Authorization:'Bearer '+authToken}:{})},body:body===undefined?undefined:JSON.stringify(body),credentials:'omit',cache:'no-store',redirect:'error',signal:controller.signal});
      if(response.status===429){const e=Error('Please wait before requesting another code.');const delay=Number(response.headers.get('Retry-After'));e.retryAfterMs=Number.isFinite(delay)&&delay>0?Math.min(delay*1000,86400000):60000;throw e;}
      if(!response.ok)throw Error('The provider could not confirm this request.');
      if(response.status===204)return null;
      const text=await response.text();if(text.length>131072)throw Error('Provider response unavailable.');return JSON.parse(text);
    })();
    // Race the entire transport/body read. A late transport completion has no
    // state-writing callback and cannot become a later attempt's session.
    try{return await Promise.race([work,new Promise((_,reject)=>{timer=setTimeout(()=>{controller.abort();reject(Error('Request timed out.'));},requestTimeoutMs);})]);}finally{clearTimeout(timer);}
  }
  async function identity(authToken=token){const u=await request('user','GET',undefined,true,authToken);if(u.id!==account||u.is_anonymous===true)throw Error('This is not the approved existing account.');}
  async function list(authToken=token){await identity(authToken);const rows=await request('passkeys','GET',undefined,true,authToken);if(!Array.isArray(rows)||rows.some(x=>typeof x.id!=='string'))throw Error('Credential inventory unavailable.');return rows;}
  function readEmail(){
    const raw=storage.getItem(emailMarker);if(!raw)return null;
    const value=JSON.parse(raw);if(value?.account!==account)throw Error('Email attempt unavailable.');return value;
  }
  function migrateEmail(){
    const raw=storage.getItem(marker);if(!raw)return;
    let old;try{old=JSON.parse(raw);}catch{return;}
    if(old?.account===account&&['email-verifying','email-received'].includes(old.phase)){
      // Write first; never reinterpret or remove a registration journal.
      if(!storage.getItem(emailMarker))storage.setItem(emailMarker,JSON.stringify({...old,id:crypto.randomUUID()}));
      storage.removeItem(marker);
    }
  }
  function currentEmail(id){if(readEmail()?.id!==id)throw Error('This sign-in attempt was superseded.');}
  async function exclusive(fn){gate();if(busy||!locks)throw Error('Enrollment is busy or unavailable.');busy=true;try{return await locks.request(marker,{ifAvailable:true},async lock=>{if(!lock)throw Error('Enrollment is open in another tab.');return fn();});}finally{busy=false;}}
  const decode=value=>{if(typeof value!=='string'||!value||value.length>16384||!/^[\w-]+$/.test(value))throw Error('Invalid enrollment options.');return Uint8Array.from(atob(value.replace(/-/g,'+').replace(/_/g,'/')),x=>x.charCodeAt(0));};
  const encode=value=>btoa(String.fromCharCode(...new Uint8Array(value))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
  function recoveryState(){
    gate();
    const email=readEmail();
    if(email)return {state:email.phase==='email-received'&&pendingToken&&pendingId===email.id?'confirmation-retryable':'retry-email'};
    const raw=storage.getItem(marker);
    if(!raw)return {state:token?'ready':'sign-in-required'};
    let receipt;
    try{if(raw.length>4096)throw Error();receipt=JSON.parse(raw);}catch{return {state:'unresolved'};}
    if(receipt?.account!==account)return {state:'unresolved'};
    if(!token)return {state:'session-unavailable'};
    if(receipt.phase==='email-received')return {state:'confirmation-retryable'};
    if(['registered','complete'].includes(receipt.phase)&&typeof receipt.passkeyId==='string'&&receipt.passkeyId&&typeof receipt.credentialHash==='string'&&/^[a-f0-9]{64}$/.test(receipt.credentialHash))return {state:'confirmation-retryable'};
    return {state:'unresolved'};
  }
  return {
    recoveryState,
    canEnroll:()=>{gate();return Boolean(token)&&!storage.getItem(marker)&&!storage.getItem(emailMarker);},
    sendCode:email=>exclusive(async()=>{
      migrateEmail();const prior=readEmail();
      if(prior?.retryAt>now())throw Error('Please wait before requesting another code.');
      const attempt={id:crypto.randomUUID(),account,phase:'email-sending',retryAt:now()+60000};
      storage.setItem(emailMarker,JSON.stringify(attempt));pendingToken=undefined;
      try{await request('otp','POST',{email,create_user:false},false);}catch(e){currentEmail(attempt.id);if(e.retryAfterMs)storage.setItem(emailMarker,JSON.stringify({...attempt,retryAt:now()+Math.max(60000,e.retryAfterMs)}));throw e;}currentEmail(attempt.id);
      storage.setItem(emailMarker,JSON.stringify({...attempt,phase:'email-sent'}));
    }),
    verifyCode:(email,code)=>exclusive(async()=>{
      migrateEmail();let attempt=readEmail();
      if(attempt&&!['email-sent'].includes(attempt.phase))throw Error('Request a new code before trying again.');
      attempt={...attempt,id:attempt?.id??crypto.randomUUID(),account,phase:'email-verifying'};
      storage.setItem(emailMarker,JSON.stringify(attempt));pendingToken=undefined;
      const s=await request('verify','POST',{email,token:code,type:'email'},false);currentEmail(attempt.id);
      if(typeof s.access_token!=='string'||!s.access_token||s.user?.id!==account||s.user?.is_anonymous===true)throw Error('The approved account could not be confirmed.');
      pendingToken=s.access_token;pendingId=attempt.id;
      storage.setItem(emailMarker,JSON.stringify({...attempt,phase:'email-received'}));
      const rows=await list(pendingToken);currentEmail(attempt.id);
      token=pendingToken;pendingToken=undefined;storage.removeItem(emailMarker);return rows.length;
    }),
    inspect:()=>exclusive(async()=>({count:(await list()).length,pending:storage.getItem(marker)!==null})),
    enroll:()=>exclusive(async()=>{
      if(storage.getItem(emailMarker))throw Error('Finish confirming your account first.');
      if(storage.getItem(marker))throw Error('A previous enrollment needs review. Do not create another passkey.');
      if((await list()).length!==0)throw Error('A passkey already exists. No additional passkey will be created.');
      const tx=await request('passkeys/registration/options','POST',{}),o=tx.options;
      if(typeof tx.challenge_id!=='string'||!tx.challenge_id||o?.rp?.id!==rp||!o.user?.name||!Array.isArray(o.pubKeyCredParams)||!o.pubKeyCredParams.length)throw Error('Enrollment options could not be verified.');
      const publicKey={...o,challenge:decode(o.challenge),user:{...o.user,id:decode(o.user.id)},excludeCredentials:(o.excludeCredentials??[]).map(x=>({...x,id:decode(x.id)})),timeout:Math.min(o.timeout??60000,120000)};
      // Persist before the OS sheet: cancellation/timeout can still leave a local
      // authenticator credential. Never auto-clear or repeat this transaction.
      storage.setItem(marker,JSON.stringify({phase:'creating',account,challengeId:tx.challenge_id}));
      const c=await credentials.create({publicKey});
      if(!c||c.type!=='public-key')throw Error('Passkey creation was not confirmed. Check your password manager before retrying.');
      const credentialHash=Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',c.rawId)),b=>b.toString(16).padStart(2,'0')).join('');
      const receipt={account,challengeId:tx.challenge_id,credentialHash};
      storage.setItem(marker,JSON.stringify({...receipt,phase:'created'}));
      const response=c.response;
      const client=JSON.parse(new TextDecoder().decode(response.clientDataJSON));
      if(client.type!=='webauthn.create'||client.challenge!==o.challenge||client.origin!=='https://'+rp||client.crossOrigin===true)throw Error('Credential response did not match this enrollment.');
      const credential={id:c.id,rawId:encode(c.rawId),type:c.type,clientExtensionResults:c.getClientExtensionResults(),response:{clientDataJSON:encode(response.clientDataJSON),attestationObject:encode(response.attestationObject),transports:response.getTransports?.()??[]}};
      await identity();
      storage.setItem(marker,JSON.stringify({...receipt,phase:'verifying'}));
      const result=await request('passkeys/registration/verify','POST',{challenge_id:tx.challenge_id,credential});
      if(typeof result?.id!=='string'||!result.id)throw Error('Enrollment needs reconciliation. Do not create another passkey.');
      // Persist the provider receipt before the fallible inventory request.
      storage.setItem(marker,JSON.stringify({...receipt,phase:'registered',passkeyId:result.id}));
      const rows=await list();
      if(rows.length!==1||rows[0].id!==result.id)throw Error('Enrollment needs reconciliation. Do not create another passkey.');
      storage.setItem(marker,JSON.stringify({...receipt,phase:'complete',passkeyId:result.id}));
      return {complete:true};
    }),
    recover:()=>exclusive(async()=>{
      const email=readEmail();
      if(email){
        if(email.phase!=='email-received'||!pendingToken||pendingId!==email.id)throw Error('Request a new email code to sign in again.');
        const rows=await list(pendingToken);currentEmail(email.id);
        token=pendingToken;pendingToken=undefined;storage.removeItem(emailMarker);
        return {accountConfirmed:true,count:rows.length};
      }
      const raw=storage.getItem(marker);
      if(!raw||raw.length>4096)throw Error('No confirmed registration receipt is available.');
      const receipt=JSON.parse(raw);
      if(receipt.account===account&&receipt.phase==='email-received'){
        // A received token stays memory-only; retry only read-only confirmation.
        const rows=await list();storage.removeItem(marker);return {accountConfirmed:true,count:rows.length};
      }
      if(receipt.account!==account||!['registered','complete'].includes(receipt.phase)||typeof receipt.passkeyId!=='string'||!receipt.passkeyId||typeof receipt.credentialHash!=='string'||!/^[a-f0-9]{64}$/.test(receipt.credentialHash))throw Error('This enrollment still needs reconciliation. Do not create another passkey.');
      // Requires the existing in-memory session; never issues a replacement or
      // guesses that an unrelated inventory row belongs to this enrollment.
      const rows=await list();
      if(rows.length!==1||rows[0].id!==receipt.passkeyId)throw Error('The saved registration receipt could not be confirmed.');
      storage.setItem(marker,JSON.stringify({...receipt,phase:'complete'}));
      return {complete:true};
    }),
    close:()=>exclusive(async()=>{
      const pending=storage.getItem(marker)!==null||storage.getItem(emailMarker)!==null;
      if(pendingToken&&pendingToken!==token){await request('logout?scope=local','POST',{},true,pendingToken);pendingToken=undefined;}
      if(!token)return {closed:!pending,pending};
      await request('logout?scope=local','POST',{});token=undefined;
      // Closing the known session does not resolve an interrupted ceremony.
      return {closed:true,pending};
    })
  };
}
