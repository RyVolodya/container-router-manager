const CURRENT_VERSION = "0.16.9";
const cacheTtlMs = Number(process.env.GITHUB_UPDATE_CACHE_MS ?? 15 * 60 * 1000);

type GithubRelease = {
  tag_name?: string;
  name?: string | null;
  html_url?: string;
  published_at?: string | null;
  body?: string | null;
  draft?: boolean;
  prerelease?: boolean;
};

type UpdateStatus = {
  configured: boolean;
  currentVersion: string;
  latestVersion: string | null;
  updateAvailable: boolean;
  releaseName: string | null;
  releaseUrl: string | null;
  publishedAt: string | null;
  repository: string | null;
  error?: string;
};

let cached: {at:number; value:UpdateStatus} | null = null;

function normalizeVersion(value:string){
  return value.trim().replace(/^v/i,"").split("+")[0].split("-")[0];
}

function versionParts(value:string){
  return normalizeVersion(value).split(".").map(part=>{
    const n=Number.parseInt(part,10);
    return Number.isFinite(n)?n:0;
  });
}

function isNewerVersion(candidate:string,current:string){
  const a=versionParts(candidate), b=versionParts(current);
  const length=Math.max(a.length,b.length);
  for(let i=0;i<length;i++){
    const left=a[i]??0,right=b[i]??0;
    if(left>right)return true;
    if(left<right)return false;
  }
  return false;
}

function repositoryName(){
  const raw=(process.env.GITHUB_REPOSITORY ?? "").trim()
    .replace(/^https?:\/\/github\.com\//i,"")
    .replace(/\.git$/i,"")
    .replace(/^\/+|\/+$/g,"");
  return /^[^/\s]+\/[^/\s]+$/.test(raw) ? raw : "";
}

export async function getUpdateStatus(force=false):Promise<UpdateStatus>{
  const repository=repositoryName();

  if(!repository){
    return {
      configured:false,currentVersion:CURRENT_VERSION,latestVersion:null,
      updateAvailable:false,releaseName:null,releaseUrl:null,publishedAt:null,
      repository:null
    };
  }

  if(!force && cached && Date.now()-cached.at<cacheTtlMs) return cached.value;

  const headers:Record<string,string>={
    "Accept":"application/vnd.github+json",
    "X-GitHub-Api-Version":"2026-03-10",
    "User-Agent":`Docker-Router-Manager/${CURRENT_VERSION}`
  };
  const token=(process.env.GITHUB_TOKEN ?? "").trim();
  if(token) headers.Authorization=`Bearer ${token}`;

  try{
    const response=await fetch(`https://api.github.com/repos/${repository}/releases/latest`,{
      headers,
      signal:AbortSignal.timeout(8000)
    });

    if(!response.ok){
      const result:UpdateStatus={
        configured:true,currentVersion:CURRENT_VERSION,latestVersion:null,
        updateAvailable:false,releaseName:null,releaseUrl:null,publishedAt:null,
        repository,error:`GitHub API returned ${response.status}`
      };
      cached={at:Date.now(),value:result};
      return result;
    }

    const release=await response.json() as GithubRelease;
    const tag=String(release.tag_name ?? "").trim();
    const latest=tag ? normalizeVersion(tag) : null;

    const result:UpdateStatus={
      configured:true,
      currentVersion:CURRENT_VERSION,
      latestVersion:latest,
      updateAvailable:Boolean(latest && isNewerVersion(latest,CURRENT_VERSION)),
      releaseName:release.name || tag || null,
      releaseUrl:release.html_url || null,
      publishedAt:release.published_at || null,
      repository
    };
    cached={at:Date.now(),value:result};
    return result;
  }catch(error){
    const result:UpdateStatus={
      configured:true,currentVersion:CURRENT_VERSION,latestVersion:null,
      updateAvailable:false,releaseName:null,releaseUrl:null,publishedAt:null,
      repository,error:error instanceof Error?error.message:String(error)
    };
    cached={at:Date.now(),value:result};
    return result;
  }
}
