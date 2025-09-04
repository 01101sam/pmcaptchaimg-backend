import protobuf from "protobufjs";

import fs from "node:fs/promises";
import {buildResponseJSON, parseResponseJSON, CAPTCHA_TYPE_AUDIO, CAPTCHA_TYPE_IMAGE_OBJECT_RECOGNITION, CAPTCHA_TYPE_IMAGE_GRID_CHALLENGE} from "./captcha-types.mjs";
import {connect as puppeteerLaunch} from "puppeteer-real-browser";
import {ACRPipelineSingleton} from "../predict/automatic-speech-recognition.mjs";
import {error, proxyUrl} from "../utils.mjs";

const randInt = (min, max) => Math.floor(Math.random() * (max - min + 1)) + min;

let ReloadRequestProto;
protobuf.load("./proto/recaptcha/reload.proto", (err, root) => {
    if (err) throw err;
    ReloadRequestProto = root.lookupType("ReloadRequest");
});

class RealBrowser {
    constructor(captcha, invisible, browser, page) {
        this.captcha = captcha;
        this.invisible = invisible;
        this.browser = browser;
        this.page = page;

        // TEMP value
        this.enterprise = false;
        this.cached = {};

        this.taskPromise = {
            resolve: null,
            reject: null
        };
    }

    static async create(captcha, enterprise = false, invisible = false) {
        const {browser, page} = await puppeteerLaunch({
            // headless: 'shell',
            args: ["--disable-feature=WebFontsCacheAwareTimeoutAdaption"]
        });
        const browserInstance = new RealBrowser(captcha, invisible, browser, page);
        browserInstance.enterprise = enterprise;

        try {
            await page.setRequestInterception(true);
            page.on("request", async request => {
                try {
                    return await browserInstance.interceptRequest.bind(browserInstance)(request);
                } catch (e) {
                    console.error("Failed to intercept request:", e);
                    if (!request.isInterceptResolutionHandled())
                        return request.continue();
                }
            });

            await browserInstance.executeScript([
                [
                    "onloadCallback = () =>",
                    "(grecaptcha.render || grecaptcha.enterprise.render)('container', {",
                    `sitekey: "${captcha.siteKey}",`,
                    `size: '${invisible ? 'invisible' : 'normal'}'`,
                    "});"
                ].join("")
            ], true);
            await page.goto(captcha.siteUrl);
            await page.waitForSelector('iframe');
        } catch (e) {
            console.error("Failed to create browser:", e);
            return error("BROWSER_INIT_FAILED", "Error occurred when creating browser.", e);
        }

        browserInstance.browser = browser;
        browserInstance.page = page;

        return [true, browserInstance];
    }

    async interceptRequest(request) {
        const url = new URL(request.url());
        if (url.origin + url.pathname === this.captcha.siteUrl) {
            let body = null;
            try {
                body = await fs.readFile("./template/recaptcha.html", "utf8");
                body = body.replace("{{version}}", this.enterprise ? "enterprise" : "api");
            } catch (e) {
                console.error("Failed to read template:", e);
                await request.abort();
                return this.taskPromise.resolve(error("TEMPLATE_LOAD_FAILED", "Failed to read template.", e));
            }
            return request.respond({status: 200, contentType: "text/html;charset=UTF-8", body});
        } else if (
            [
                this.captcha.endpoints.reload,
                this.captcha.endpoints.getImage,
                this.captcha.endpoints.replaceImage,
                this.captcha.endpoints.verify
            ].includes(url.origin + url.pathname)
        ) {
            let body = request.hasPostData() ? Buffer.from(request.postData(), "binary") : null;
            switch (url.origin + url.pathname) {
                case this.captcha.endpoints.reload: {
                    const protoBody = ReloadRequestProto.decode(body);
                    body = ReloadRequestProto.encode(protoBody).finish();
                    break;
                }
                case this.captcha.endpoints.verify: {
                    if (this.cached.challenges.type === "nocaptcha") break;
                    const bodyParam = new URLSearchParams(body.toString());
                    
                    let randEffortTime;
                    const challengeType = this.cached.challenges.type;
                    switch (challengeType) {
                        case CAPTCHA_TYPE_AUDIO:
                            // Audio effort time (preserved for future reference)
                            randEffortTime = randInt(15 * 1000, 20 * 1000);
                            break;
                        case CAPTCHA_TYPE_IMAGE_OBJECT_RECOGNITION:
                        case CAPTCHA_TYPE_IMAGE_GRID_CHALLENGE: {
                            // Image effort time based on grid size or number of challenges
                            const metadataLength = this.cached.challenges.metadata?.data?.length || 1;
                            randEffortTime = String(randInt(
                                5000 * metadataLength,
                                (5000 * metadataLength) + (100 * metadataLength)
                            ));
                            break;
                        }
                        default:
                            // Default effort time for unknown types
                            randEffortTime = String(randInt(5000, 6000));
                            break;
                    }
                    
                    bodyParam.set("t", randEffortTime);
                    bodyParam.set("ct", randEffortTime);
                    body = bodyParam.toString();
                    break;
                }
            }
            const response = await fetch(request.url(), {
                // proxy: proxyUrl,
                method: request.method(),
                headers: request.headers(),
                body
            });
            return await this.responseCallback(request, response);
        }

        request.continue();
    }

    async responseCallback(request, response) {
        const url = new URL(response.url);
        let resp;
        switch (url.origin + url.pathname) {
            case this.captcha.endpoints.reload:
                // Get Captcha
                console.debug("Getting Captcha...");
                resp = parseResponseJSON(await response.text());
                // if (this.taskPromiseResolve) this.taskPromiseResolve(resp);
                // TODO: If DOS-Captcha, restart
                if (resp.challenge.type === "doscaptcha") {
                    console.debug("DOS-Captcha detected.");
                    this.taskPromise.resolve(error("DOS_CAPTCHA", "DOS-Captcha detected."));
                    await this.browser.close();
                    return ;
                }

                if (this.invisible && resp.challenge.type === null)
                    // v3
                    this.taskPromise.resolve([true, resp]);

                this.cached.challenges = resp.challenge;
                break;
            case this.captcha.endpoints.replaceImage:
                console.debug("Getting Next Image...");
                resp = parseResponseJSON(await response.text());
                break;
            case this.captcha.endpoints.getImage:
                // Preserve audio handling code for future reference (disabled)
                if (false && this.cached.challenges.type === CAPTCHA_TYPE_AUDIO) {
                    // Original audio handling code - preserved but disabled
                    const elementHandles = await this.page.$$('iframe');
                    if (!elementHandles) {
                        console.error("Failed to get reCAPTCHA iframe.");
                        this.taskPromise.resolve(error("CAPTCHA_IFRAME_NOT_FOUND", "Failed to get reCAPTCHA iframe."));
                        return;
                    }
                    let frame;
                    for (const elementHandle of elementHandles) {
                        const src = await elementHandle.evaluate(el => el.src);
                        if (src.startsWith(this.captcha.endpoints.frame)) {
                            frame = await elementHandle.contentFrame();
                            break;
                        }
                    }
                    // #audio-response
                    try {
                        await frame.waitForSelector("#audio-response");
                    } catch (e) {
                        console.error("Failed to get audio response.");
                        this.taskPromise.resolve(error("CAPTCHA_RESPONSE_ELEM_NOT_FOUND", "Failed to get audio response element."));
                        return;
                    }
                    const audioResponse = await frame.$("#audio-response");
                    if (!audioResponse) {
                        console.error("Failed to get audio response.");
                        this.taskPromise.resolve(error("CAPTCHA_RESPONSE_ELEM_NOT_FOUND", "Failed to get audio response element."));
                        return;
                    }
                    const verifyButton = await frame.$("#recaptcha-verify-button");
                    if (!verifyButton) {
                        console.error("Failed to get verify button.");
                        this.taskPromise.resolve(error("CAPTCHA_VERIFY_BUTTON_NOT_FOUND", "Failed to get verify button."));
                        return;
                    }

                    console.debug("Getting Audio...");
                    const audioData = await response.arrayBuffer();
                    request.respond({
                        status: response.status,
                        headers: Object.fromEntries(response.headers),
                        body: Buffer.from(audioData)
                    });
                    console.debug("Listening to Audio...");
                    const sttResult = await ACRPipelineSingleton.predict(audioData);
                    console.info("STT Result:", sttResult);
                    await audioResponse.type(
                        sttResult.text
                            .replaceAll(".", "")
                            .replaceAll(",", "")
                            .replaceAll("  ", " ")
                            .replaceAll("?", "")
                            .replaceAll("!", "")
                            .trim()
                            .toLowerCase()
                    );
                    await verifyButton.click();
                } else {
                    // New image captcha handling
                    console.debug("Processing Image Captcha...");
                    const imageData = await response.arrayBuffer();
                    
                    // Determine which image captcha type we're dealing with
                    const challengeType = this.cached.challenges.type;
                    
                    if (challengeType === CAPTCHA_TYPE_IMAGE_OBJECT_RECOGNITION) {
                        console.debug("Processing Image Object Recognition Challenge...");
                        
                        // Use ParamMetadata to understand what objects to identify
                        const metadata = this.cached.challenges.metadata;
                        if (metadata && metadata.data) {
                            console.info("Image Challenge Metadata:", JSON.stringify(metadata.data, null, 2));
                            // Example: {name: "traffic lights", splitSize: [3, 3], ...}
                            
                            // Store image data for later processing
                            this.cached.imageData = imageData;
                            this.cached.imageMetadata = metadata;
                            
                            // TODO: Implement actual image object recognition
                            // For now, we'll just log the challenge details
                            const challengeInfo = metadata.data[0]; // Assuming single challenge
                            console.info(`Object Recognition: Select all "${challengeInfo.name}" in a ${challengeInfo.splitSize[0]}x${challengeInfo.splitSize[1]} grid`);
                        }
                        
                    } else if (challengeType === CAPTCHA_TYPE_IMAGE_GRID_CHALLENGE) {
                        console.debug("Processing Image Grid Challenge...");
                        
                        // Handle grid-based image challenges
                        const metadata = this.cached.challenges.metadata;
                        if (metadata && metadata.data) {
                            const { splitSize, name } = metadata.data[0]; // Assuming single challenge
                            console.info(`Grid Challenge: Select all "${name}" in a ${splitSize[0]}x${splitSize[1]} grid`);
                            
                            // Split the image into tiles using ImageData.split
                            const {ImageData} = await import("./captcha-types.mjs");
                            const imageTiles = await ImageData.split(Buffer.from(imageData), splitSize);
                            console.info(`Split image into ${imageTiles.length} tiles`);
                            
                            // Store for later processing
                            this.cached.imageTiles = imageTiles;
                            this.cached.imageMetadata = metadata;
                        }
                        
                    } else {
                        console.warn(`Unknown or unhandled captcha type: ${challengeType}`);
                        // Default image handling
                        this.cached.imageData = imageData;
                    }
                    
                    // Respond with the image data
                    request.respond({
                        status: response.status,
                        headers: Object.fromEntries(response.headers),
                        body: Buffer.from(imageData)
                    });
                    
                    // TODO: The actual solving logic would go here
                    // For now, we're just preparing the data structures
                    console.info("Image captcha data prepared for solving");
                }
                break;
            case this.captcha.endpoints.verify:
                // Solve
                resp = parseResponseJSON(await response.text());
                console.debug("Checking captcha solve result...", resp.success ? "Success" : "Failed");
                if (resp.success) {
                    this.taskPromise.resolve([true, resp]);
                    break;
                }
                console.debug(resp);

                this.cached.challenges = resp.challenge;
                // TODO Solve
                // console.debug("Auto solving captcha...");
                // answers = await this.captcha.solveML(reloadResponse);
                // if (!answers) break;
                // console.info(JSON.stringify(answers));
                // this.cached.answers = answers;
                // resp.reloadResponse.challenge.type = "nocaptcha";
                // resp.reloadResponse.challenge.metadata = null;
                break;
        }

        try {
            return request.respond({
                status: response.status,
                headers: Object.fromEntries(response.headers),
                body: Buffer.isBuffer(resp) ? resp : buildResponseJSON(resp.build())
            });
        } catch {
        }
    }

    async executeScript(scripts = [], onNewDocument = false) {
        if (!Array.isArray(scripts)) scripts = [scripts];

        let lastResult;
        try {
            for (const script of scripts)
                lastResult = await this.page[onNewDocument ? 'evaluateOnNewDocument' : 'evaluate'](script);

            return lastResult;
        } catch (e) {
            console.error("Failed to execute script:", e);
        }
    }
}

export class GoogleCaptcha {
    constructor({siteUrl, siteKey, enterprise = false, invisible = false, action = null}) {
        this.siteUrl = siteUrl;
        this.siteKey = siteKey;
        this.invisible = invisible;
        this.enterprise = enterprise;
        this.action = action;

        this.captchaEndpoint = "https://www.google.com";
        const captchaType = enterprise ? "enterprise" : "api2";
        const prefix = `${this.captchaEndpoint}/recaptcha/${captchaType}`;
        this.endpoints = {
            prefix,

            // v2
            getImage: `${prefix}/payload`,
            replaceImage: `${prefix}/replaceimage`,

            // v3
            // sendClearance: `${prefix}/clr`,

            // both
            getToken: `${prefix}/anchor`,
            frame: `${prefix}/bframe`,
            reload: `${prefix}/reload`,
            verify: `${prefix}/userverify`
        };

        this.cookie = null;

        // Browser
        this.realBrowser = null;
    }

    async getCaptcha() {
        console.debug("[reCAPTCHA] booting browser...");
        const [result, realBrowser] = await RealBrowser.create(this, this.enterprise, this.invisible);
        if (!result) return error("BROWSER_INIT_FAILED", "Failed to boot browser.", realBrowser);
        this.realBrowser = realBrowser;
        const awaitableTaskPromise = new Promise(
            (resolve, reject) => Object.assign(realBrowser.taskPromise, {resolve, reject})
        );
        const taskPromise = realBrowser.taskPromise;
        console.debug("[reCAPTCHA] browser ok.");

        // Move around to bypass v3
        if (!this.invisible) {
            const elementHandle = await realBrowser.page.$('iframe');
            if (!elementHandle) {
                console.error("Failed to get reCAPTCHA iframe.");
                await this.realBrowser.browser.close();
                return taskPromise.resolve(error("CAPTCHA_IFRAME_NOT_FOUND", "Failed to get reCAPTCHA iframe."));
            }
            const frame = await elementHandle.contentFrame();
            await frame.waitForSelector(".recaptcha-checkbox");
            const checkbox = await frame.$(".recaptcha-checkbox");
            if (!checkbox) {
                console.error("Failed to get checkbox.");
                await this.realBrowser.browser.close();
                return taskPromise.resolve(error("CAPTCHA_CHECKBOX_NOT_FOUND", "Failed to get checkbox."));
            }
            console.debug("[reCAPTCHA] clicking checkbox...");
            await checkbox.click();
            // await this.moveAround(3);
        } else {
            console.debug("[reCAPTCHA] solving invisible captcha...");
            await realBrowser.page.waitForSelector("#execute");
            const button = await realBrowser.page.$("#execute");
            if (!button) {
                console.error("Failed to get execute button.");
                await this.realBrowser.browser.close();
                return taskPromise.resolve(error("CAPTCHA_EXECUTE_NOT_FOUND", "Failed to get execute button."));
            }

            console.debug("[reCAPTCHA] clicking button...");
            await this.moveAround(4);
            await button.click();
        }

        return await awaitableTaskPromise;
    }

    async moveAround(steps) {
        const realBrowser = this.realBrowser;
        const time = Date.now();

        // Move around every steps
        try {
            for (let i = 0; i < steps; i++) {
                const [x, y] = [randInt(0, 100), randInt(0, 100)];
                await realBrowser.page.mouse.move(x, y, {steps: 50});
                if (this.action) await realBrowser.page.mouse.click(x, y);
            }
        } catch (e) {
            console.error("Failed to move around:", e);
        }
        await new Promise(resolve => setTimeout(resolve, 100));
        console.info(`Move Around Time: ${(Date.now() - time) / 1000}s`);
    }
}