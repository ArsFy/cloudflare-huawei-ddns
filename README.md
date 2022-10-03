# DDNS

基於 華為/榮耀路由器 API 獲取公網 IP 的 Cloudflare DDNS 工具

## Config

填入對應配置，請先在 CF DNS 中創建對應 A 記錄

```js
// Honor
const ip = "192.168.3.1";
const password = "manage password";

// Cloudflare
const cf_email = "Email";
const cf_global_key = "Global API Key (https://dash.cloudflare.com/profile/api-tokens)";
const cf_zone = "zone_id"
const domain = "test.exp.com"
```

## Run

```bash
git close https://github.com/ArsFy/cloudflare-huawei-ddns.git
cd cloudflare-huawei-ddns
npm i

# Edit Config

node main.js
```