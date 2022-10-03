import fetch from "node-fetch";
import crypto from "crypto-js";
import fs from "fs";

// Honor
const ip = "192.168.3.1";
const password = "manage password";

// Cloudflare
const cf_email = "Email";
const cf_global_key = "Global API Key (https://dash.cloudflare.com/profile/api-tokens)";
const cf_zone = "zone_id"
const domain = "test.exp.com"

const firstnonce = crypto.lib.WordArray.random(8 * 4).toString();
const hasher = crypto.algo.SHA256;
const hmac = crypto.HmacSHA256;
const LOCALHOST = "http://" + ip
let csrf_param = null;
let csrf_token = null;
const saltedPassWord = (password, salt, iterations) => {
    return crypto.PBKDF2(password, salt, {
        keySize: 8,
        iterations: iterations,
        hasher: hasher
    });
}
const clientKey = (saltPwd) => {
    return hmac(saltPwd, "Client Key");
}
const storedKey = (clientKey) => {
    const hasherobj = hasher.create();
    hasherobj.update(clientKey);
    return hasherobj.finalize();
}
const signature = (storedKey, authMessage) => {
    return hmac(storedKey, authMessage);
}
const clientProof = (password, salt, iterations, authMessage) => {
    const spwd = saltedPassWord(password, salt, iterations);
    const ckey = clientKey(spwd);
    const skey = storedKey(ckey);
    const csig = signature(skey, authMessage);

    for (var i = 0; i < ckey.sigBytes / 4; i += 1) {
        ckey.words[i] = ckey.words[i] ^ csig.words[i]
    }
    return ckey.toString();
}

const getip = async (localhostpsw) => {
    const loginFirstReq = await fetch(`${LOCALHOST}/html/index.html`);
    const loginloginSecondReqCookie = loginFirstReq.headers.get("set-cookie").match(/(.+?);/)[1];
    const loginIndexHtml = await loginFirstReq.text();
    const csrfData = loginIndexHtml.match(
        /<meta name="(csrf_token|csrf_param)" content="(.+?)"\/>/g
    );
    csrf_param = csrfData[0].match(/content="(.+)"/)[1];
    csrf_token = csrfData[1].match(/content="(.+)"/)[1];
    const loginSecondReq = await fetch(`${LOCALHOST}/api/system/user_login_nonce`, {
        method: 'post',
        body: JSON.stringify({
            csrf: {
                csrf_param,
                csrf_token
            },
            data: {
                username: "admin",
                firstnonce
            }
        }),
        headers: {
            "Host": ip,
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36",
            'Content-Type': 'application/json; charset=UTF-8',
            "Cookie": loginloginSecondReqCookie,
            "_ResponseFormat": "JSON",
            "Referer": "http://" + ip + "/html/index.html",
            "Accept": "application/json, text/javascript, */*; q=0.01"
        },
    });
    const loginSecondReqJson = await loginSecondReq.json();
    const salt = crypto.enc.Hex.parse(loginSecondReqJson['salt']);
    const { iterations: iter, servernonce: finalNonce } = loginSecondReqJson;
    const authMsg = [firstnonce, finalNonce, finalNonce].join(",")
    const loginThirdReq = await fetch("http://" + ip + "/api/system/user_login_proof", {
        method: "POST",
        body: JSON.stringify({
            csrf: {
                csrf_param: loginSecondReqJson['csrf_param'],
                csrf_token: loginSecondReqJson['csrf_token']
            },
            data: {
                clientproof: clientProof(localhostpsw, salt, iter, authMsg),
                finalnonce: finalNonce
            }
        }),
        headers: {
            "Host": ip,
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36",
            'Content-Type': 'application/json; charset=UTF-8',
            "Cookie": loginloginSecondReqCookie,
            "_ResponseFormat": "JSON",
            "Referer": "http://" + ip + "/html/index.html",
            "Accept": "application/json, text/javascript, */*; q=0.01"
        },
    })
    const thirdCookie = (loginThirdReq.headers.get("set-cookie").match(/(.+?);/)[1])
    const reqLast = await fetch("http://" + ip + "/api/ntwk/wan?type=active", {
        method: "GET",
        headers: {
            "_ResponseFormat": "JSON,",
            "Accept": "application/json, text/javascript, */*; q=0.01",
            "Host": ip,
            "Pragma": "no-cache",
            "Cookie": thirdCookie,
            "Referer": "http://" + ip + "/html/index.html",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36",
        }
    })
    const hostDeviceJson = (await reqLast.json())
    return hostDeviceJson.IPv4Addr
}

getip(password).then(async (i) => {
    let last = "";
    try { last = fs.readFileSync("./ip") } catch (e) { }

    if (last != i) {
        let getrid = await fetch(`https://api.cloudflare.com/client/v4/zones/${cf_zone}/dns_records?type=A&name=${domain}`, {
            headers: {
                "X-Auth-Email": cf_email,
                "X-Auth-Key": cf_global_key,
                "Content-Type": "application/json"
            }
        })
        let rid = (await getrid.json()).result[0].id;

        let b = await fetch(`https://api.cloudflare.com/client/v4/zones/${cf_zone}/dns_records/${rid}`, {
            headers: {
                "X-Auth-Email": cf_email,
                "X-Auth-Key": cf_global_key,
                "Content-Type": "application/json"
            },
            method: "PUT",
            body: JSON.stringify({ "type": "A", "name": domain, "content": i, "ttl": 1, "proxied": false })
        })

        console.log(await b.json())
        fs.writeFileSync("./ip", i);
    } else {
        console.log('no change')
    }
})