import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const cors={"Access-Control-Allow-Origin":"*","Access-Control-Allow-Headers":"authorization, x-client-info, apikey, content-type"};
const json=(body:unknown,status=200)=>new Response(JSON.stringify(body),{status,headers:{...cors,"Content-Type":"application/json"}});

Deno.serve(async(req)=>{
  if(req.method==="OPTIONS")return new Response("ok",{headers:cors});
  try{
    const url=Deno.env.get("SUPABASE_URL")!;
    const anon=Deno.env.get("SUPABASE_ANON_KEY")!;
    const service=Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
    const authHeader=req.headers.get("Authorization")||"";
    const callerClient=createClient(url,anon,{global:{headers:{Authorization:authHeader}}});
    const {data:{user},error:userError}=await callerClient.auth.getUser();
    if(userError||!user)return json({error:"Nao autenticado"},401);
    const admin=createClient(url,service,{auth:{persistSession:false,autoRefreshToken:false}});
    const payload=await req.json();
    const organizationId=String(payload.organizationId||"");
    const {data:caller}=await admin.from("organization_members").select("role,active").eq("organization_id",organizationId).eq("user_id",user.id).maybeSingle();
    if(!caller?.active||!["master","admin"].includes(caller.role))return json({error:"Sem permissao"},403);

    const targetRole=String(payload.role||"viewer");
    const targetUserId=String(payload.userId||"");
    if(caller.role!=="master"&&["master","admin"].includes(targetRole))return json({error:"Administrador nao pode atribuir esta funcao"},403);
    if(targetUserId){
      const {data:target}=await admin.from("organization_members").select("role").eq("organization_id",organizationId).eq("user_id",targetUserId).maybeSingle();
      if(target?.role==="master"&&caller.role!=="master")return json({error:"Administrador nao pode alterar Master"},403);
    }

    if(payload.action==="invite"){
      const email=String(payload.email||"").trim().toLowerCase();
      const {data,error}=await admin.auth.admin.inviteUserByEmail(email,{data:{full_name:payload.fullName||""},redirectTo:payload.redirectTo});
      if(error)throw error;
      await admin.from("profiles").upsert({id:data.user.id,email,full_name:payload.fullName||"",status:"pending"});
      await admin.from("organization_members").upsert({organization_id:organizationId,user_id:data.user.id,role:targetRole,active:false,invited_by:user.id},{onConflict:"organization_id,user_id"});
      await admin.from("audit_logs").insert({organization_id:organizationId,user_id:user.id,action:"user.invite",entity_type:"user",entity_id:data.user.id,new_data:{email,role:targetRole}});
      return json({ok:true,userId:data.user.id});
    }

    if(payload.action==="approve"){
      await admin.from("profiles").update({status:"active",approved_at:new Date().toISOString(),approved_by:user.id,blocked_at:null,blocked_by:null}).eq("id",targetUserId);
      await admin.from("organization_members").upsert({organization_id:organizationId,user_id:targetUserId,role:targetRole,active:true,approved_by:user.id},{onConflict:"organization_id,user_id"});
    }else if(payload.action==="reject"){
      await admin.from("profiles").update({status:"rejected"}).eq("id",targetUserId);
      await admin.from("organization_members").update({active:false}).eq("organization_id",organizationId).eq("user_id",targetUserId);
    }else if(payload.action==="block"||payload.action==="unblock"){
      const blocked=payload.action==="block";
      await admin.from("profiles").update({status:blocked?"blocked":"active",blocked_at:blocked?new Date().toISOString():null,blocked_by:blocked?user.id:null}).eq("id",targetUserId);
      await admin.from("organization_members").update({active:!blocked}).eq("organization_id",organizationId).eq("user_id",targetUserId);
    }else if(payload.action==="role"){
      await admin.from("organization_members").update({role:targetRole}).eq("organization_id",organizationId).eq("user_id",targetUserId);
    }else if(payload.action==="revoke_sessions"){
      await admin.auth.admin.signOut(targetUserId,"global");
    }else if(payload.action==="permissions"){
      if(caller.role!=="master"&&targetRole==="admin")return json({error:"Somente Master pode alterar permissoes de Administrador"},403);
      const permissions=Array.isArray(payload.permissions)?payload.permissions:[];
      await admin.from("user_permissions").delete().eq("organization_id",organizationId).eq("user_id",targetUserId);
      if(permissions.length)await admin.from("user_permissions").insert(permissions.map((permission:string)=>({organization_id:organizationId,user_id:targetUserId,permission,allowed:true,created_by:user.id})));
    }else if(payload.action==="reset_password"){
      const email=String(payload.email||"").trim().toLowerCase();
      await admin.auth.resetPasswordForEmail(email,{redirectTo:payload.redirectTo});
    }else return json({error:"Acao invalida"},400);

    await admin.from("audit_logs").insert({organization_id:organizationId,user_id:user.id,action:`user.${payload.action}`,entity_type:"user",entity_id:targetUserId,new_data:{role:targetRole}});
    return json({ok:true});
  }catch(error){console.error(error);return json({error:"Nao foi possivel concluir a operacao"},400);}
});
