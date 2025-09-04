import {BotGuardContext} from "./bot-guard.mjs";
import sharp from "sharp";
import {RawImage} from "@huggingface/transformers";
// import {ImageDenoisingSingleton} from "../predict/image-denoising.mjs";

// Captcha type constants
export const CAPTCHA_TYPE_AUDIO = 'audio';
export const CAPTCHA_TYPE_IMAGE_OBJECT_RECOGNITION = 'image_object_recognition';
export const CAPTCHA_TYPE_IMAGE_GRID_CHALLENGE = 'image_grid_challenge';

const captchaResponseCodeMap = {
    r: "reloadResponse",
    uv: "userVerifyResponse",
    d: "dynamicResponse",

    // Data
    bgdata: "botGuardData",
    pmeta: "paramMetadata"
};

class BaseCaptchaType {
    constructor(type, token = null, rawData = null) {
        this.rawData = rawData;
        this.type = type;
        this.token = token;
    }

    build(replaceFields = []) {
        for (const [field, value] of replaceFields)
            if (value === null || value === undefined)
                this.rawData[field] = null;
            else
                this.rawData[field] = value;

        return this.rawData;
    }
}

export class ImageData {
    constructor(token, id = null) {
        this.token = token;
        this.id = id;

        this.data = null;
    }

    async getImageData(fetchFunc, idOnly = false, rawImage = false) {
        if (this.data) return rawImage ? await ImageData.loadImageFunction(await sharp(this.data)) : this.data;

        try {
            const param = {p: this.token};
            if (this.id) param["id"] = this.id;
            else if (idOnly) return null;
            const response = await fetchFunc("getImage", param);

            if (response.status !== 200) {
                console.error("Failed to fetch image data:", response.status, response.statusText);
                return null;
            }
            this.data = Buffer.from(await response.arrayBuffer());
            return rawImage ? await ImageData.loadImageFunction(await sharp(this.data)) : this.data;
        } catch (e) {
            console.error("Failed to fetch image data:", e);
            return null;
        }
    }

    static async loadImageFunction(/**@type {sharp.Sharp}*/ img) {
        const metadata = await img.metadata();
        const rawChannels = metadata.channels;

        let {data, info} = await img.rotate().raw().toBuffer({resolveWithObject: true});

        const newImage = new RawImage(new Uint8ClampedArray(data), info.width, info.height, info.channels);
        if (rawChannels !== undefined && rawChannels !== info.channels) {
            // Make sure the new image has the same number of channels as the input image.
            // This is necessary for grayscale images.
            newImage.convert(rawChannels);
        }
        return newImage;
    }

    async toRawImage() {
        if (!this.data) return null;
        return await ImageData.loadImageFunction(await sharp(this.data));
    }

    static async split(data, splitSize) {
        if (!data) return null;

        const image = await sharp(data).ensureAlpha().toBuffer();
        const {width, height} = await sharp(image).metadata();

        const tileWidth = Math.floor(width / splitSize[0]);
        const tileHeight = Math.floor(height / splitSize[1]);
        const tiles = [];

        for (let y = 0; y < splitSize[1]; y++) {
            for (let x = 0; x < splitSize[0]; x++) {
                const tile = await sharp(image)
                    .extract({
                        left: x * tileWidth,
                        top: y * tileHeight,
                        width: tileWidth,
                        height: tileHeight
                    }).toBuffer();
                tiles.push(await ImageData.loadImageFunction(sharp(tile)));
            }
        }

        return tiles;
    }
}

// region Response

class ReloadResponse extends BaseCaptchaType {
    constructor(json) {
        super("ReloadResponse", json[1], json);

        this.expireInSeconds = json[3];
        this.challenge = {
            type: this.mapChallengeType(json[5]),
            rawType: json[5], // Keep original type for reference
            // Image token 06A
            target: new ImageData(json[9]),
            metadata: json[4] ? new ParamMetadata(json[4]) : null
        };
        // Submit response when next time verify
        this.botGuard = {
            request: json[7] ? new BotGuardData(json[7]) : null,
            response: null
        };
        // Session Token 09A
        this.sessionToken = json[12];

        // only provided when `fi`
        this.unknownFields = {
            // Sent first time by reload request
            "05AToken": json[8],
            "0bAToken": json[15],
            "field21": json[14],  // 0aA
        }
    }

    mapChallengeType(rawType) {
        // Map Google's challenge types to our internal types
        const typeMap = {
            'audio': CAPTCHA_TYPE_AUDIO,
            'imageselect': CAPTCHA_TYPE_IMAGE_OBJECT_RECOGNITION, // Default image type
            'tileselect': CAPTCHA_TYPE_IMAGE_GRID_CHALLENGE,
            'multicaptcha': CAPTCHA_TYPE_IMAGE_GRID_CHALLENGE,
            // Add more mappings as discovered
        };
        
        const mapped = typeMap[rawType] || rawType;
        if (!typeMap[rawType]) {
            console.warn(`Unknown challenge type: ${rawType}, using as-is`);
        }
        
        return mapped;
    }

    async getBotGuardResponse(context) {
        if (!this.botGuard.request) return false;
        Object.assign(context, {
            input: this.botGuard.request.input,
            programData: this.botGuard.request.programData
        })
        this.botGuard.response = await context.getResponse();
        return true;
    }

    build(replaceFields = []) {
        replaceFields = [
            [1, this.token],
            [3, this.expireInSeconds],
            [4, this.challenge.metadata ? this.challenge.metadata.build() : null],
            [5, this.challenge.rawType || this.challenge.type],
            [7, this.botGuard.request ? this.botGuard.request.build() : null],
            [8, this.unknownFields["05AToken"]],
            [9, this.challenge.target.token],
            [12, this.sessionToken],
            [14, this.unknownFields["field21"]],
            [15, this.unknownFields["0bAToken"]]
        ];

        return super.build(replaceFields);
    }
}

class DynamicResponse extends BaseCaptchaType {
    constructor(json) {
        super("DynamicResponse", json[1], json);

        const imageId = json[2] && json[2].length ? json[2][0] : null;
        this.image = new ImageData(json[5], imageId);
    }
}

class UserVerifyResponse extends BaseCaptchaType {
    constructor(json) {
        super("UserVerifyResponse", json[1], json);

        this.success = Boolean(json[2]);
        this.reloadResponse = json[7] ? new ReloadResponse(json[7]) : null;
        this.expireInSeconds = json[3];
        this.sessionToken = json[9];
    }

    toJSON() {
        return {
            success: this.success,
            expireInSeconds: this.expireInSeconds,
            sessionToken: this.sessionToken
        };
    }

    build(replaceFields = []) {
        replaceFields = [
            [1, this.token],
            [2, this.success],
            [3, this.expireInSeconds],
            [7, this.reloadResponse ? this.reloadResponse.build() : null],
            [9, this.sessionToken]
        ];

        return super.build(replaceFields);
    }
}

// endregion Response

// region Metadata

class BotGuardData extends BaseCaptchaType {
    constructor(json = []) {
        super("BotGuardData", null, json);

        this.input = json[1] || null;
        // json[2] ???
        this.programData = json[3] || null;
    }

    async getResponse() {
        return await BotGuardContext.getResponse();
    }

    build(replaceFields = []) {
        replaceFields = [
            [1, this.input],
            [3, this.programData]
        ];

        return super.build(replaceFields);
    }
}

class ParamMetadata extends BaseCaptchaType {
    static userDefinedLabelMap = {
        // tileselect
        "stop sign": {defined: ["stop_sign"], mid: []},

        // multicaptcha
        "street signs": {defined: ["TileSelectionStreetSign"], mid: ["/m/01mqdt"]},
        "business names": {defined: ["TileSelectionBizView"], mid: []},
        "stop signs": {defined: ["stop_sign"], mid: ["/m/02pv19"]},
        "sidewalk": {defined: ["sidewalk", "footpath"], mid: []},
        "car": {defined: ["vehicle", "vehicles", "cars"], mid: ["/m/07yv9", "/m/0k4j"]},
        "roads": {defined: ["road"], mid: ["/m/06gfj"]},
        "houses": {defined: ["house"], mid: ["/m/03jm5"]},
        "bridges": {defined: ["bridges"], mid: []},
        "palm trees": {defined: [], mid: ["/m/0cdl1"]},
        "crosswalks": {defined: ["pedestrian crossing"], mid: ["/m/014xcs"], deref: ["traffic lights"]},
        "traffic lights": {defined: [], mid: ["/m/015qff"]},
        "fire hydrants": {defined: [], mid: ["/m/01pns0"]},
        "buses": {defined: ["bus"], mid: ["/m/01bjv"]},
        "taxis": {defined: ["taxi"], mid: ["/m/0pg52"]},
        "motorcycles": {defined: [], mid: ["/m/04_sv"]},
        "bicycles": {defined: [], mid: ["/m/0199g"]},
        "parking meters": {defined: [], mid: ["/m/015qbp"]},
        "stairs": {defined: [], mid: ["/m/01lynh"]},
        "chimneys": {defined: [], mid: ["/m/01jk_4"]},
        "tractors": {defined: [], mid: ["/m/013xlm"]},
        "trees": {defined: [], mid: ["/m/07j7r"]},
        "flowers": {defined: [], mid: ["/m/0c9ph5"]},

        // unknown type
        "store front": {
            defined: ["ImageSelectStoreFront", "storefront", "ImageSelectBizFront", "ImageSelectStoreFront_inconsistent"],
            mid: []
        },
        "plants": {defined: [], mid: ["/m/05s2s"]},
        "bodies of water": {defined: [], mid: ["/m/03ktm1"]},
        "rivers": {defined: [], mid: ["/m/06cnp"]},
        "beaches": {defined: [], mid: ["/m/0b3yr"]},
        "the sky": {defined: [], mid: ["/m/01bqvp"]},
        "boats": {defined: [], mid: ["/m/019jd"]},
        "school bus": {defined: [], mid: ["/m/02yvhj"]},
        "trains": {defined: [], mid: ["/m/07jdr"]},
        "statues": {defined: [], mid: ["/m/013_1c"]},
        "fountains": {defined: [], mid: ["/m/0h8lhkg"]},
        "pillars or columns": {defined: [], mid: ["/m/01_m7"]},
        "apartment building": {defined: [], mid: ["/m/01nblt"]},
        "billboard": {defined: ["billboard"], mid: ["/m/01knjb"]},
        "traffic cones": {defined: [], mid: ["/m/03sy7v"]}
    }

    constructor(json) {
        super("ParamMetadata", null, json);

        const imageType = {
            2: "area",
            3: "contains"
        };

        const metadata = json[5] || json[1];
        if (!metadata) return;
        const challengeImages = [];
        for (const challengeMetadata of Array.isArray(metadata[0]) ? metadata[0] : [metadata])
            challengeImages.push({
                mid: challengeMetadata[0],
                name: this._getNameCached(challengeMetadata[0]) || challengeMetadata[6].toLowerCase() || false,
                type: imageType[challengeMetadata[2]] || `unknown_${challengeMetadata[2]}`,
                splitSize: [challengeMetadata[3], challengeMetadata[4]]
            });

        this.paramType = json[1] ? "single" : "multiple";
        this.data = challengeImages;
    }

    async getExplorerToken() {
        const tokenRgx = /"(AIzaSy.+?M)"/;
        try {
            const response = await fetch("https://explorer.apis.google.com/embedded.js", {
                headers: {
                    referer: "https://explorer.apis.google.com/embedded.html"
                }
            });

            const text = await response.text();
            return tokenRgx.exec(text)[1];
        } catch (e) {
            console.error("Failed to get explorer token:", e);
            return null;
        }
    }

    _getNameCached(mid) {
        // Handle key that's not a mid using userDefinedLabelMap, or use cached mid for faster response
        for (const [result, {defined, mid: resultMid}] of Object.entries(ParamMetadata.userDefinedLabelMap))
            if (defined.includes(mid) || resultMid.includes(mid)) return result;
    }

    async _getName(mid) {
        const cachedName = this._getNameCached(mid);
        if (cachedName) return cachedName;

        let resp;
        try {
            resp = await fetch("https://content-kgsearch.googleapis.com/v1/entities:search?" + new URLSearchParams({
                key: await this.getExplorerToken(),
                ids: mid,
                limit: "1",
                prefix: "true",
                languages: "en"
            }), {
                headers: {
                    "x-javascript-user-agent": "apix/3.0.0 google-api-javascript-client/1.1.0",
                    "X-origin": "https://explorer.apis.google.com",
                    "x-referer": "https://explorer.apis.google.com",
                    "x-requested-with": "XMLHttpRequest"
                }
            });
        } catch (e) {
            console.error("Error fetching metadata:", e);
            return null;
        }

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

    async ensureName() {
        if (!this.data) return;
        for (const data of this.data)
            if (!data.name) data.name = await this._getName(data.mid);
    }

    build(replaceFields = []) {
        if (this.data)
            for (const [index, challengeImage] of Object.entries(this.data))
                replaceFields.push([index + 1, [
                    challengeImage.mid,
                    // challengeImage.name,
                    null,
                    challengeImage.type.startsWith("unknown")
                        ? challengeImage.type.split("_")[1]
                        : challengeImage.type === "area" ? 2 : 3,
                    ...challengeImage.splitSize
                ]]);

        return super.build(replaceFields);
    }
}

// endregion Metadata

function parseResponseJSON(rawJson) {
    if (!rawJson) return null;

    const json = typeof rawJson === "string" ? JSON.parse(rawJson.replace(")]}'", "")) : rawJson;
    const payloadType = captchaResponseCodeMap[json[0].replace("resp", "")];

    switch (payloadType) {
        case "reloadResponse": // Reload Response
            return new ReloadResponse(json);
        case "userVerifyResponse": // User Verify Response
            return new UserVerifyResponse(json);
        case "dynamicResponse": // Dynamic Response (Image Replacement)
            return new DynamicResponse(json);
        default:
            console.warn(`Unknown Response: ${json[0]}`);
            break;
    }

    return null;
}

function buildResponseJSON(responseData) {
    if (!responseData) return null;

    return `)]}'\n${JSON.stringify(responseData)}`;
}

export {
    parseResponseJSON,
    buildResponseJSON,

    ReloadResponse,
    DynamicResponse,
    UserVerifyResponse,

    BotGuardData,
    ParamMetadata,
};