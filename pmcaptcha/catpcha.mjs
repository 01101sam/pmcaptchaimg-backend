import fetch from 'node-fetch';
import jsdom from 'jsdom';
import {createCanvas, Image, loadImage} from "canvas";
import protobuf from "protobufjs";
import ascii85 from "ascii85";


const
    randInt = (min, max) => Math.floor(Math.random() * (max - min + 1)) + min,
    UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/100.0.4896.75",
    {JSDOM} = jsdom,
    {window} = new JSDOM(null, {runScripts: 'outside-only'});  // FunCaptcha

let ReloadRequestProto;
protobuf.load("./proto/recaptcha/reload.proto", (err, root) => {
    if (err) throw err;
    ReloadRequestProto = root.lookupType("ReloadRequest");
});

export class FunCaptcha {
    constructor() {
        this.captchaVersion = null;
        this.captchaEndpoint = "https://api.funcaptcha.com";
        this.publicKey = "69A21A01-CC7B-B9C6-0F9A-E7FA06677FFC";
        this.token = null;
        this.tokenFull = null;
        this.challengeID = null;

        // Cache
        this._cachedBuildRequestFunc = null;
        this.exampleImgs = null;
    }

    async getCaptchaImageDisplay(imgUrl) {
        const canvas = createCanvas(400, 400), ctx = canvas.getContext('2d');
        ctx.font = "20px Arial";
        ctx.drawImage(await loadImage(this.exampleImgs['correct']), 150, 5);
        ctx.drawImage(await loadImage(imgUrl), 50, 150);

        // Adding difficulty

        // Lines
        let up = false;
        for (let i = 0; i < randInt(3, 5); i++) {
            ctx.strokeStyle = `#${randInt(79308561, 4294967295).toString(16)}`;
            ctx.lineWidth = randInt(1, 3);
            up = Math.random() > 0.5;
            ctx.moveTo(up ? 52 : 348, randInt(152, 202));
            ctx.lineTo(up ? 348 : 52, randInt(202, 245));
            ctx.stroke();
            ctx.strokeStyle = `#${randInt(79308561, 4294967295).toString(16)}`;
            ctx.lineWidth = randInt(1, 3);
            up = Math.random() > 0.5 && up;
            ctx.moveTo(up ? 52 : 348, randInt(255, 305));
            ctx.lineTo(up ? 348 : 52, randInt(305, 348));
            ctx.stroke();
        }

        // Noises

        const iData = ctx.getImageData(0, 0, 400, 400),
            buffer32 = new Uint32Array(iData.data.buffer);

        for (let i = 0; i < buffer32.length; i++)
            if (Math.random() < 0.15) buffer32[i] = randInt(2684354560, 4278190080);
            else if (Math.random() >= 0.5 && buffer32[i] !== 0) buffer32[i] -= Number(`0x${randInt(3, 6)}0000000`);


        ctx.putImageData(iData, 0, 0);

        // Marks
        ctx.font = "20px Arial";
        for (let i = 0; i < 3; i++) {
            ctx.fillStyle = `#${randInt(0, 16776960).toString(16)}`;
            ctx.fillText(String(i + 1), 100 * i + 95, 140);
            ctx.fillStyle = `#${randInt(0, 16776960).toString(16)}`;
            ctx.fillText(String(i + 4), 100 * i + 95, 375);
        }

        return canvas.toBuffer();
    }

    getImgArea(number) {
        const x = ((number % 3) * 100) + 50, y = Math.floor(number / 3) * 100 + 50;
        return this.captchaVersion === 1 ? {x, y} : {a: x, b: y};
    }

    async _getBuildRequestFunc() {
        if (this._cachedBuildRequestFunc) return this._cachedBuildRequestFunc;
        const
            urlPath = '/cdn/fc/js/3cd822399e15c38e0f212031c7c6190487e33dca/standard/meta_bootstrap.js',
            resp = await fetch(this.captchaEndpoint + urlPath);
        if (!(resp.status === 200)) return console.error("Failed to fetch bootstrap script");
        window.eval(await resp.text());
        // noinspection JSUnresolvedVariable
        return this._cachedBuildRequestFunc = window.build_request;
    }

    async getToken(github = true) {
        console.debug("[FunCaptcha] Getting a new token...");
        await this._getBuildRequestFunc();
        let resp = await fetch(this.captchaEndpoint + `/fc/gt2/public_key/${this.publicKey}`, {
            method: 'POST',
            headers: {'Content-Type': 'application/x-www-form-urlencoded', 'User-Agent': UserAgent},
            body: new URLSearchParams({
                bda: "",
                public_key: this.publicKey,
                site: "https://octocaptcha.com",
                userbrowser: UserAgent,
                rnd: Math.random().toString(),
                "data[origin_page]": github ? "github_org_create" : ""
            })
        });
        if (resp.status === 200) {
            resp = await resp.json();
            this.tokenFull = resp["token"];
            this.token = this.tokenFull.split("|")[0];
            console.debug("[FunCaptcha] Token: ", this.token);
            return true;
        } else console.error('[FunCaptcha] Failed to get token:', resp.status, await resp.text());
    }

    async getGameInfo(lang) {
        if (!this.tokenFull) return;
        console.debug('[FunCaptcha] Getting game info...');
        // noinspection JSCheckFunctionSignatures
        let resp = await fetch(this.captchaEndpoint + '/fc/gfct/', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: new URLSearchParams({
                lang: lang || 'en',
                sid: 'ap-southeast-1',
                analytics_tier: 40,
                render_type: 'canvas',
                token: this.token,
                'data[status]': this.captchaVersion === 1 ? 'start' : 'init'
            }),
        });
        if (!(resp.status === 200)) return console.error("[FunCaptcha] Failed to get game info:", resp.status, await resp.text());
        resp = await resp.json();
        if (resp.error) return console.error("[FunCaptcha] Failed to get game info:", resp.error);
        this.challengeID = resp['challengeID'];
        this.captchaVersion = resp['game_data']['customGUI']['api_breaker'] ? 2 : 1;
        this.exampleImgs = resp['game_data']['customGUI']['example_images'];
        console.debug('Game ID:', this.challengeID);
        console.debug('Game Type:', resp['game_data']['game_variant']);
        console.debug('Game Version:', this.captchaVersion);
        return [
            resp['string_table'][`${resp['game_data']['gameType']}.instructions-${resp['game_data']['game_variant']}`],
            resp['game_data']['customGUI']['_challenge_imgs']
        ];
    }

    /**
     * @param answers {[{a: Number, b: Number}]} Captcha position answers
     */
    async solve(answers) {
        const buildRequest = await this._getBuildRequestFunc();
        if (!(this.token && buildRequest)) return;
        console.debug('Sending solve request...');
        let resp = await fetch(this.captchaEndpoint + '/fc/ca/', {
            method: 'POST',
            headers: {'Content-Type': 'application/x-www-form-urlencoded', 'User-Agent': UserAgent},
            body: new URLSearchParams({
                game_token: this.challengeID,
                sid: 'ap-southeast-1',
                session_token: this.token,
                guess: buildRequest(JSON.stringify(answers), this.token),
                analytics_tier: '40',
                bio: 'eyJtYmlvIjoiIiwidGJpbyI6IiIsImtiaW8iOiIifQ==',
            }),
        });
        resp = await resp.json();
        console.debug('Response:', JSON.stringify(resp));
        return resp;
    }
}

export class ReCaptchaV2 {
    constructor() {
        this.captchaVersion = null;
        this.captchaEndpoint = "https://www.recaptcha.net";
        this.siteKey = "6Le-wvkSAAAAAPBMRTvw0Q4Muexq9bi0DJwx_mJ-";
        this.website = "https://www.google.com/recaptcha/api2/demo";
    }

    async _getImage(params, id = "", returnBuffer = false) {
        const param = new URLSearchParams({
            p: params,
            k: this.siteKey,
            id: id
        });
        const resp = await fetch(`${this.captchaEndpoint}/recaptcha/api2/payload?${param}`);
        if (resp.status === 200) return returnBuffer ? Buffer.from(await resp.arrayBuffer()) : await resp.arrayBuffer();
    }

    async _getName(mid, lang) {
        const resp = await fetch("https://content-kgsearch.googleapis.com/v1/entities:search?languages=en&" + new URLSearchParams({
            key: "AIzaSyAa8yy0GdcGPHdtD083HiGGx_S0vMPScDM",
            ids: mid,
            limit: "1",
            prefix: "true",
            languages: lang
        }), {
            headers: {
                "X-Origin": "https://explorer.apis.google.com"
            }
        });

        if (resp.status === 200) {
            const names = (await resp.json())['itemListElement'][0]['result']['name'], output = {};
            names.every(item => {
                const baseLang = item['@language'].split("-")[0];
                if (item['@language'].search("-") !== -1 && Object.keys(output).includes(baseLang)) {  // Base lang already exists
                    // Multiple, turn into Array and push it.
                    if (!Array.isArray(output[baseLang])) output[baseLang] = [output[baseLang]];
                    return output[baseLang].push(item['@value']);
                }
                return output[baseLang] = item['@value'];
            });
            return output;
        }
    }

    async getVersion() {
        console.debug("[ReCaptcha] Getting version...");
        if (this.captchaVersion) return this.captchaVersion;
        const versionRegex = /https:\/\/www\.gstatic\.com\/recaptcha\/releases\/(.+)\/recaptcha__en\.js/,
            resp = await fetch("https://www.recaptcha.net/recaptcha/api.js");
        return this.captchaVersion = versionRegex.exec(await resp.text())[1];
    }

    async getBotGuardResponse() {
        let resp, htmlContent;
        while (1) {
            resp = await fetch("https://accounts.google.com/ServiceLogin?hl=en", {headers: {"User-Agent": "APIs-Google"}});
            htmlContent = await resp.text();
            if (htmlContent.search("document.bg")) break;
        }
        const frag = JSDOM.fragment(htmlContent),
            botGuardScript = frag.querySelector('[jsname="xdJtEf"]').querySelectorAll("script")[0].textContent.trim()
                .replace(/if\(\w="FNL"\+\w,\w\)try\{(\w+)=\w\./, "try{$1="),
            botGuardBytecode = frag.querySelector('#program').getAttribute("program-data");
        const dom = new JSDOM(null, {
            runScripts: "outside-only"
        });
        dom.window.eval(`${botGuardScript};var bg=new botguard.bg('${botGuardBytecode}')`);
        await new Promise(resolve => setTimeout(resolve, 100));
        const bgResp = dom.window.eval("bg.invoke()");
        dom.window.close();
        if (!bgResp) return await this.getBotGuardResponse();
        else if (bgResp.startsWith("FNL")) return "";
        return bgResp;
    }

    async getCaptchaToken() {
        const url = new URL(this.website),
            origin = Buffer.from(url.origin + ":443").toString("base64").replaceAll("=", "."),
            endpoint = "https://www.recaptcha.net/recaptcha/api2/anchor",
            params = `?k=${this.siteKey}&hl=en&v=${this.captchaVersion}&co=${origin}`;
        if (!this.captchaVersion) throw Error("Invalid Version");
        const resp = await fetch(endpoint + params),
            frag = JSDOM.fragment(await resp.text());
        return frag.getElementById("recaptcha-token").value;
    }

    parseResponseJSON(rawJson) {
        const json = typeof rawJson === "string" ? JSON.parse(rawJson.replace(")]}'", "")) : rawJson;
        switch (json[0].replace("resp", "")) {
            case "r": // Reload Response
                return {
                    recaptchaToken: json[1],
                    expireInSeconds: json[3],
                    captchaType: json[5],
                    param: json[9],
                    sessionToken: json[12],
                    mid: "dynamic" === json[5] ? json[4][1][0] : null
                };
            case "uv": // User Verify Response
                return {
                    recaptchaToken: json[1],
                    success: Boolean(json[2]),
                    expireInSeconds: json[3],
                    reloadResponse: json[7] ? this.parseResponseJSON(json[7]) : null,
                    sessionToken: json[9]
                }
            case "d": // Dynamic Response (Image Replacement)
                return {
                    recaptchaToken: json[1],
                    imageId: json[2].length ? json[2][0] : null,
                    param: json[5]
                }
            default:
                throw Error("Invalid Response");
        }
    }

    async getNextImage(origImg, token, origPos, pos) {
        console.debug("[ReCaptcha] Getting next image...");
        const resp = await fetch(`${this.captchaEndpoint}/recaptcha/api2/replaceimage?k=${this.siteKey}`, {
            method: "POST",
            headers: {
                Origin: this.captchaEndpoint,
                "Content-Type": "application/x-www-form-urlencoded"
            },
            body: new URLSearchParams({
                v: this.captchaVersion,
                c: token,
                ds: JSON.stringify([pos])
            })
        });
        const dynamicResponse = this.parseResponseJSON(await resp.text());
        const canvas = createCanvas(300, 300), ctx = canvas.getContext('2d');
        ctx.drawImage(await loadImage(ascii85.decode(origImg)), 0, 0);
        if (!dynamicResponse.imageId) {
            ctx.fillStyle = "white";
            ctx.fillRect((origPos % 3) * 100, Math.floor(origPos / 3) * 100, 100, 100);
        } else {
            // noinspection JSCheckFunctionSignatures
            const replaceImg = await loadImage(await this._getImage(dynamicResponse.param, dynamicResponse.imageId, true));
            ctx.drawImage(replaceImg, (origPos % 3) * 100, Math.floor(origPos / 3) * 100);
        }
        return {
            empty: !dynamicResponse.imageId,
            recaptchaToken: dynamicResponse.recaptchaToken,
            image: canvas.toBuffer("image/jpeg")
        }
    }

    async getCaptcha(token = null, lang) {
        await this.getVersion();
        console.debug("[ReCaptcha] Getting captcha...");
        let reloadType = token ? "r" : "fi";
        while (1) {
            let reloadResponse,
                bgResp = await this.getBotGuardResponse(),
                captchaToken = token || await this.getCaptchaToken(),
                reloadRespRaw = await fetch(`https://api2.botguard.workers.dev?k=${this.siteKey}`, {
                    method: "POST",
                    headers: {
                        Origin: this.captchaEndpoint,
                        "Content-Type": "application/x-protobuffer"
                    },
                    body: ReloadRequestProto.encode(ReloadRequestProto.create({
                        version: this.captchaVersion,
                        recaptchaToken: captchaToken,
                        botGuardToken: bgResp,
                        reloadType: reloadType,
                        siteKey: this.siteKey
                    })).finish()
                });
            reloadResponse = this.parseResponseJSON(await reloadRespRaw.text());

            if (reloadResponse.captchaType === "doscaptcha") console.warn("Captcha Not Available, Retrying...");
            else if (reloadResponse.captchaType === "nocaptcha") console.debug("No Captcha Required, Retrying...");
            else if (reloadResponse.captchaType === "dynamic") {
                if (!token) {
                    reloadResponse['image'] = await this._getImage(reloadResponse.param);
                    reloadResponse['target'] = await this._getName(reloadResponse.mid, lang || "en");
                }
                return reloadResponse;
            } else {
                console.debug(`Not Targeted Captcha Type: ${reloadResponse.captchaType}, Retrying...`);
                reloadType = token ? "r" : "fi";
                token = null;
            }
        }
    }

    async solve(token, answers) {
        console.debug("[ReCaptcha] Solving...");
        const randEffortTime = String(randInt(20000, 22000));
        const userVerifyRespRaw = await fetch(`https://api2uv.botguard.workers.dev?k=${this.siteKey}`, {
            method: "POST",
            headers: {
                Origin: this.captchaEndpoint,
                "Content-Type": "application/x-www-form-urlencoded"
            },
            body: new URLSearchParams({
                v: this.captchaVersion,
                c: token,
                response: Buffer.from(JSON.stringify({
                    response: answers,
                    e: "bW8R4jsR2kPTtKltNITZVLC8aIg"
                })).toString("base64").replaceAll("=", "."),
                t: randEffortTime, ct: randEffortTime,
                bg: await this.getBotGuardResponse()
            })
        });
        return this.parseResponseJSON(await userVerifyRespRaw.text());
    }
}