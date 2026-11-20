/** Forms submit the JSON media type required by Better Auth's router. Setup
 * HTML is rendered on the server; this controller neither encodes nor keeps a QR.
 * The written page keeps this document's policy, so its scripts are given this
 * document's nonce as an attribute: browsers never serialize the `nonce` property. */
export function factorFormScript(): string {
	return `<script>(()=>{
const pageNonce=document.currentScript?.nonce;
document.addEventListener('submit',async(event)=>{
const form=event.target;if(!(form instanceof HTMLFormElement)||!form.matches('form[data-factor-form]'))return;
event.preventDefault();const button=event.submitter;const spinner=button?.querySelector('[data-pending-indicator]');
if(button){button.disabled=true;button.setAttribute('aria-busy','true');}spinner?.removeAttribute('hidden');
try{const response=await fetch(form.action,{method:'POST',headers:{'content-type':'application/json',accept:'text/html'},body:JSON.stringify(Object.fromEntries(new FormData(form)))});
if(response.redirected){location.assign(response.url);return;}
if(!response.headers.get('content-type')?.includes('text/html'))throw new Error('Factor response unavailable.');
const html=await response.text();let nextDocument=html;
if(pageNonce){const parsed=new DOMParser().parseFromString(html,'text/html');for(const script of parsed.querySelectorAll('script'))script.setAttribute('nonce',pageNonce);nextDocument='<!doctype html>'+parsed.documentElement.outerHTML;}
document.open();document.write(nextDocument);document.close();
}catch{const status=document.getElementById('status');if(status)status.textContent='Factor confirmation is unavailable. Please try again.';if(button){button.disabled=false;button.removeAttribute('aria-busy');}spinner?.setAttribute('hidden','');}
});})();</script>`;
}
