import jsdom from 'jsdom';
import fetch from 'node-fetch';
import {createCanvas, loadImage} from "canvas";
import protobuf from "protobufjs";
import ascii85 from "ascii85";


const
    randInt = (min, max) => Math.floor(Math.random() * (max - min + 1)) + min,
    {JSDOM} = jsdom;

let ReloadRequestProto;
protobuf.load("./proto/recaptcha/reload.proto", (err, root) => {
    if (err) throw err;
    ReloadRequestProto = root.lookupType("ReloadRequest");
});

class FunCaptchaAssertCache {
    constructor() {
        this.host = "https://api.funcaptcha.com";

        this.jsEnv = null;
        this.window = null;
        this.fingerPrintFunc = null;
        this.buildRequestFunc = null;

        this.lastUpdate = 0;
        this.expireTime = 24 * 60 * 60 * 1000;

        this.endpointRgx = /(https?:\/\/api\.funcaptcha\.com\/cdn\/fc\/js\/[a-f\d]{40}\/standard\/)funcaptcha_api\.js/;
    }

    async update() {
        if (Date.now() - this.lastUpdate < this.expireTime) return true;
        if (this.window) this.window.close();
        this.jsEnv = new JSDOM(``, {runScripts: 'outside-only'});
        this.window = this.jsEnv.window;
        let resp, endpoint;
        console.debug("Getting js asserts endpoint...");
        try {
            resp = await fetch(`${this.host}/fc/api/`);
            if (resp.status !== 200) return console.error("Failed to fetch assert endpoint");
            endpoint = this.endpointRgx.exec(await resp.text());
            if (!endpoint || !endpoint[1]) return console.error("Failed to parse assert endpoint");
            endpoint = endpoint[1];
        } catch (e) {
            return console.error("Failed to get js asserts endpoint:", e);
        }
        const scripts = [];
        for (const fileName of ["funcaptcha_api.js", "meta_bootstrap.js"]) scripts.push((async () => {
            console.debug(`Fetching ${fileName}`);
            resp = await fetch(`${endpoint}/${fileName}`);
            if (resp.status !== 200) return console.error(`Failed to fetch ${fileName}`);
            this.window.eval(await resp.text());
            return true;
        })());
        try {
            for (const result of await Promise.all(scripts)) if (!result) return;
        } catch (e) {
            return console.error("Failed to fetch js asserts:", e);
        }
        if (!this.window['fc_fp']) return console.error("Failed to get FunCaptcha fingerprint function from funcaptcha_api.js");
        this.fingerPrintFunc = this.window['fc_fp'];
        if (!this.window['build_request']) return console.error("Failed to get build_request function from meta_bootstrap.js");
        this.buildRequestFunc = this.window['build_request'];
        this.decryptFunc = this.window['decrypt'];
        this.lastUpdate = Date.now();
        return true;
    }

    get buildRequest() {
        return this.buildRequestFunc;
    }

    get decrypt() {
        return this.decryptFunc;
    }

    get fingerPrint() {
        return this.fingerPrintFunc;
    }

    get canvasFP() {
        return this.fingerPrintFunc['canvasFP'];
    }
}

const cache = new FunCaptchaAssertCache();  // FunCaptcha

export class FunCaptcha {
    constructor() {
        // Fixed define
        this.captchaEndpoint = "https://api.funcaptcha.com";
        this.publicKey = "69A21A01-CC7B-B9C6-0F9A-E7FA06677FFC";
        this.userAgent = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "AppleWebKit/537.36 (KHTML, like Gecko)",
            "Chrome/103.0.5060.114"
        ].join(" ");

        this.captchaVersion = null;
        this.token = null;
        this.tokenFull = null;
        this.challengeID = null;

        // Cache
        this.exampleImgs = null;
        this.decryptionKey = null;
    }

    _generateBDA() {
        console.debug("Generating fingerprint...");
        const
            L51 = S01 => {
                let X01, U01 = 0;
                if (!S01) return "";
                else if (S01.length === 0) return U01;
                if (Array.prototype.reduce)
                    return S01.split("").reduce((V01, y01) => {
                        V01 = (V01 << 5) - V01 + y01.charCodeAt(0);
                        return V01 & V01;
                    }, 0);
                for (let d01 = 0; d01 < S01.length; d01++) {
                    X01 = S01.charCodeAt(d01);
                    U01 = (U01 << 5) - U01 + X01;
                    U01 = U01 & U01;
                }
                return U01;
            },
            FunCaptchaAPI = cache.fingerPrint,
            currTS = new Date().getTime() / 1000,
            aesSecret = this.userAgent + Math.round(currTS - currTS % 21600),
            feObjValues = [
                {
                    "key": "DNT",  // "Do Not Track"
                    "value": "1"
                },
                {
                    "key": "L",  // Language
                    "value": "en-US"
                },
                {
                    "key": "D", // Depth (screen.colorDepth)
                    "value": 24 // crypto.randomInt(12, 24)
                },
                {
                    "key": "PR",  // Pixel Ratio
                    "value": 1.25 // (Math.random() * (2 - 1) + 1).toFixed(2).toString()
                },
                {
                    "key": "S",  // Screen
                    "value": [
                        1536,
                        864
                    ]
                },
                {
                    "key": "AS",  // Available Screen
                    "value": [
                        1536,
                        864
                    ]
                },
                {
                    "key": "TO",  // Time Offset
                    "value": -480
                },
                {
                    "key": "SS",  // Session Storage (window.sessionStorage exists)
                    "value": true
                },
                {
                    "key": "LS",  // Local Storage (window.localStorage exists)
                    "value": true
                },
                {
                    "key": "IDB",  // IndexedDB (window.indexedDB exists)
                    "value": true
                },
                {
                    "key": "B",  // Behaviour (document.body.addBehavior)
                    "value": false
                },
                {
                    "key": "ODB",  // OpenDB (window.openDatabase exists)
                    "value": true
                },
                {
                    "key": "CPUC",  // CPU Class (navigator.cpuClass value)
                    "value": "unknown"
                },
                {
                    "key": "PK",  //  Platform Key (navigator.platform value)
                    "value": "unknown"
                },
                {
                    "key": "CFP",  // Canvas Fingerprint
                    "value": cache.canvasFP()
                },
                {
                    "key": "FR",  // Has Fake Resolution
                    "value": false
                },
                {
                    "key": "FOS",  // Has Fake OS
                    "value": false
                },
                {
                    "key": "FB",  // Fake Browser
                    "value": false
                },
                {
                    "key": "JSF",  // JS Fonts
                    "value": [
                        "Arial",
                        "Arial Black",
                        "Arial Narrow",
                        "Book Antiqua",
                        "Bookman Old Style",
                        "Calibri",
                        "Cambria",
                        "Cambria Math",
                        "Century",
                        "Century Gothic",
                        "Century Schoolbook",
                        "Comic Sans MS",
                        "Consolas",
                        "Courier",
                        "Courier New",
                        "Garamond",
                        "Geneva",
                        "Georgia",
                        "Helvetica",
                        "Impact",
                        "Lucida Bright",
                        "Lucida Calligraphy",
                        "Lucida Console",
                        "Lucida Fax",
                        "LUCIDA GRANDE",
                        "Lucida Handwriting",
                        "Lucida Sans",
                        "Lucida Sans Typewriter",
                        "Lucida Sans Unicode",
                        "Microsoft Sans Serif",
                        "Monotype Corsiva",
                        "MS Gothic",
                        "MS Outlook",
                        "MS PGothic",
                        "MS Reference Sans Serif",
                        "MS Sans Serif",
                        "MS Serif",
                        "MYRIAD",
                        "Palatino Linotype",
                        "Segoe Print",
                        "Segoe Script",
                        "Segoe UI",
                        "Segoe UI Light",
                        "Segoe UI Semibold",
                        "Segoe UI Symbol",
                        "Tahoma",
                        "Times",
                        "Times New Roman",
                        "Times New Roman PS",
                        "Trebuchet MS",
                        "Verdana",
                        "Wingdings",
                        "Wingdings 2",
                        "Wingdings 3"
                    ]
                },
                {
                    "key": "P",  // Plugins Key
                    "value": [
                        "Chrome PDF Viewer::Portable Document Format::application/pdf~pdf,text/pdf~pdf",
                        "Chromium PDF Viewer::Portable Document Format::application/pdf~pdf,text/pdf~pdf",
                        "Microsoft Edge PDF Viewer::Portable Document Format::application/pdf~pdf,text/pdf~pdf",
                        "PDF Viewer::Portable Document Format::application/pdf~pdf,text/pdf~pdf",
                        "WebKit built-in PDF::Portable Document Format::application/pdf~pdf,text/pdf~pdf"
                    ]
                },
                {
                    "key": "T",  // Touch
                    "value": [
                        0,
                        false,
                        false
                    ]
                },
                {
                    "key": "H",  // Hardware Concrun (navigator.hardwareConcurrency value)
                    "value": 12 // crypto.randomInt(1, 128)
                },
                {
                    "key": "SWF",  // Has https://github.com/swfobject/swfobject (window.swfobject value)
                    "value": false
                }
            ],
            webGLKeys = [
                {
                    "key": "webgl_extensions",
                    "value": "ANGLE_instanced_arrays;EXT_blend_minmax;EXT_color_buffer_half_float;EXT_disjoint_timer_query;EXT_float_blend;EXT_frag_depth;EXT_shader_texture_lod;EXT_texture_compression_bptc;EXT_texture_compression_rgtc;EXT_texture_filter_anisotropic;EXT_sRGB;KHR_parallel_shader_compile;OES_element_index_uint;OES_fbo_render_mipmap;OES_standard_derivatives;OES_texture_float;OES_texture_float_linear;OES_texture_half_float;OES_texture_half_float_linear;OES_vertex_array_object;WEBGL_color_buffer_float;WEBGL_compressed_texture_s3tc;WEBGL_compressed_texture_s3tc_srgb;WEBGL_debug_renderer_info;WEBGL_debug_shaders;WEBGL_depth_texture;WEBGL_draw_buffers;WEBGL_lose_context;WEBGL_multi_draw"
                },
                {
                    "key": "webgl_extensions_hash",
                    "value": "00000000000000000000000000000000"
                },
                {
                    "key": "webgl_renderer",
                    "value": "WebKit WebGL"
                },
                {
                    "key": "webgl_vendor",
                    "value": "WebKit"
                },
                {
                    "key": "webgl_version",
                    "value": "WebGL 1.0 (OpenGL ES 2.0 Chromium)"
                },
                {
                    "key": "webgl_shading_language_version",
                    "value": "WebGL GLSL ES 1.0 (OpenGL ES GLSL ES 1.0 Chromium)"
                },
                {
                    "key": "webgl_aliased_line_width_range",
                    "value": "[1, 1]"
                },
                {
                    "key": "webgl_aliased_point_size_range",
                    "value": "[1, 1024]"
                },
                {
                    "key": "webgl_antialiasing",
                    "value": "yes"
                },
                {
                    "key": "webgl_bits",
                    "value": "8,8,24,8,8,0"
                },
                {
                    "key": "webgl_max_params",
                    "value": "16,32,16384,1024,16384,16,16384,30,16,16,4096"
                },
                {
                    "key": "webgl_max_viewport_dims",
                    "value": "[32767, 32767]"
                },
                {
                    "key": "webgl_unmasked_vendor",
                    "value": "Google Inc. (AMD)"
                },
                {
                    "key": "webgl_unmasked_renderer",
                    "value": "ANGLE (AMD, AMD Radeon(TM) Graphics Direct3D11 vs_5_0 ps_5_0, D3D11)"
                },
                {
                    "key": "webgl_vsf_params",
                    "value": "23,127,127,23,127,127,23,127,127"
                },
                {
                    "key": "webgl_vsi_params",
                    "value": "0,31,30,0,31,30,0,31,30"
                },
                {
                    "key": "webgl_fsf_params",
                    "value": "23,127,127,23,127,127,23,127,127"
                },
                {
                    "key": "webgl_fsi_params",
                    "value": "0,31,30,0,31,30,0,31,30"
                },
                {
                    "key": "webgl_hash_webgl",
                    "value": "00000000000000000000000000000000"
                },
                {
                    "key": "user_agent_data_brands",
                    "value": "Not.A/Brand,Chromium"
                },
                {
                    "key": "user_agent_data_mobile",
                    "value": false
                },
                {
                    "key": "navigator_connection_downlink",
                    "value": 10
                },
                {
                    "key": "navigator_connection_downlink_max",
                    "value": null
                },
                {
                    "key": "network_info_rtt",
                    "value": 50
                },
                {
                    "key": "network_info_save_data",
                    "value": false
                },
                {
                    "key": "network_info_rtt_type",
                    "value": null
                },
                {
                    "key": "screen_pixel_depth",
                    "value": 24
                },
                {
                    "key": "navigator_device_memory",
                    "value": 8
                },
                {
                    "key": "navigator_languages",
                    "value": "en-US"
                },
                {
                    "key": "window_inner_width",
                    "value": 162
                },
                {
                    "key": "window_inner_height",
                    "value": 150
                },
                {
                    "key": "window_outer_width",
                    "value": 1536
                },
                {
                    "key": "window_outer_height",
                    "value": 824
                },
                {
                    "key": "browser_detection_firefox",
                    "value": false
                },
                {
                    "key": "browser_detection_brave",
                    "value": false
                },
                {
                    "key": "audio_codecs",
                    "value": "{\"ogg\":\"probably\",\"mp3\":\"probably\",\"wav\":\"probably\",\"m4a\":\"\",\"aac\":\"\"}"
                },
                {
                    "key": "video_codecs",
                    "value": "{\"ogg\":\"probably\",\"h264\":\"\",\"webm\":\"probably\",\"mpeg4v\":\"\",\"mpeg4a\":\"\",\"theora\":\"\"}"
                },
                {
                    "key": "media_query_dark_mode",
                    "value": true
                },
                {
                    "key": "headless_browser_phantom",
                    "value": false
                },
                {
                    "key": "headless_browser_selenium",
                    "value": false
                },
                {
                    "key": "headless_browser_nightmare_js",
                    "value": false
                },
                {
                    "key": "document__referrer",
                    "value": "https://github.com/"
                },
                {
                    "key": "window__ancestor_origins",
                    "value": [
                        "https://github.com"
                    ]
                },
                {
                    "key": "window__tree_index",
                    "value": [
                        0
                    ]
                },
                {
                    "key": "window__tree_structure",
                    "value": "[[]]"
                },
                {
                    "key": "window__location_href",
                    "value": "https://octocaptcha.com/"
                },
                {
                    "key": "client_config__sitedata_location_href",
                    "value": "https://octocaptcha.com/"
                },
                {
                    "key": "client_config__surl",
                    "value": null
                },
                {
                    "key": "mobile_sdk__is_sdk"
                },
                {
                    "key": "client_config__language",
                    "value": null
                },
                {
                    "key": "navigator_battery_charging",
                    "value": true
                },
                {
                    "key": "audio_fingerprint",
                    "value": "0"
                }
            ],
            webGLKeyValue = {},
            feValues = [],
            fpResult = [
                {
                    "value": "js",
                    "key": "api_type"
                },
                {
                    "value": 1,
                    "key": "p"
                },
                {
                    "key": "f",
                    "value": FunCaptchaAPI['x64hash128'](feValues.join("~~~"), 31) // fingerprint
                },
                {
                    "key": "n", // Now
                    "value": Buffer.from(Math.round(Date.now() / 1000).toString()).toString('base64')
                },
                {
                    "key": "wh", // Window Hash | Window Proto Chain Hash
                    "value": "e8ba25df3c5e9c242ffe3db75a89da55|72627afbfd19a741c7da1732218301ac"  // Chrome
                },
            ];

        webGLKeys.forEach(x => {
            webGLKeyValue[x.key] = x.value
        });
        for (let key in feObjValues) {
            let feObject = feObjValues[key];
            switch (feObject.key) {
                case "CFP":
                    feValues.push(`${feObject.key}:${L51(feObject.value)}`);
                    break;
                case "P":
                    let pluginKeyValue, pluginName = [];
                    for (let key in feObject.value) (pluginKeyValue = feObject.value[key]) && pluginName.push(pluginKeyValue.split("::")[0]);
                    feValues.push(`${feObject.key}:${pluginName.join(",")}`);
                    break;
                default:
                    feValues.push(`${feObject.key}:${feObject.value}`);
                    break;
            }
            fpResult.push({
                key: "enhanced_fp",
                value: [
                    ...webGLKeys,
                    {
                        "key": "webgl_hash_webgl",
                        "value": FunCaptchaAPI['x64hash128'](Object.values(Object.keys(webGLKeyValue).sort().reduce((o, k) => {
                            o[k] = webGLKeyValue[k];
                            return o
                        }, {})).join(","))
                    },
                    {
                        "key": "user_agent_data_brands",
                        "value": " Not A;Brand,Chromium,Google Chrome"
                    },
                    {
                        "key": "user_agent_data_mobile",
                        "value": false
                    },
                    {
                        "key": "navigator_connection_downlink",
                        "value": 10
                    },
                    {
                        "key": "navigator_connection_downlink_max",
                        "value": null
                    },
                    {
                        "key": "network_info_rtt",
                        "value": 50
                    },
                    {
                        "key": "network_info_save_data",
                        "value": false
                    },
                    {
                        "key": "network_info_rtt_type",
                        "value": null
                    },
                    {
                        "key": "screen_pixel_depth",
                        "value": 24
                    },
                    {
                        "key": "navigator_device_memory",
                        "value": 2
                    },
                    {
                        "key": "navigator_languages",
                        "value": "en-US"
                    },
                    {
                        "key": "window_inner_width",
                        "value": 556
                    },
                    {
                        "key": "window_inner_height",
                        "value": 150
                    },
                    {
                        "key": "window_outer_width",
                        "value": null
                    },
                    {
                        "key": "window_outer_height",
                        "value": null
                    }
                ]
            });
        }

        fpResult.push(...[
            {
                "key": "fe",
                "value": feValues
            },
            {
                "key": "ife_hash",
                "value": FunCaptchaAPI['x64hash128'](feValues.join(", "), 38)
            },
            {
                "value": 1,
                "key": "cs"
            },
            {
                "key": "jsbd",
                "value": "{\"HL\":2,\"NCE\":true,\"DT\":\"OctoCaptcha\",\"NWD\":\"false\",\"DMTO\":1,\"DOTO\":1}"
            }
        ]);
        return Buffer.from(cache.buildRequest(JSON.stringify(fpResult), aesSecret)).toString('base64');
    }

    async getEncryptionKey() {
        if (this.decryptionKey) return this.decryptionKey;
        console.debug("[FunCaptcha] Getting image encryption key...");
        let resp = await fetch(this.captchaEndpoint + `/fc/ekey/`, {
            method: 'POST',
            headers: {'Content-Type': 'application/x-www-form-urlencoded', 'User-Agent': this.userAgent},
            body: new URLSearchParams({
                game_token: this.challengeID,
                sid: 'ap-southeast-1',
                session_token: this.token,
            })
        });
        resp = await resp.json();
        console.debug('Response:', JSON.stringify(resp));
        this.decryptionKey = resp.key;
        return resp;
    }

    async _getImage(url) {
        try {
            const resp = await fetch(url);
            if (!resp.ok) return console.error(`Failed to fetch image: ${resp.status} ${resp.statusText}`);
            if (resp.headers.get("content-type").includes("application/json")) {
                // Decode Encoded Image
                return console.error(`Decrypt image is not supported yet`);
                // return cache.decrypt(await resp.json(), await this.getEncryptionKey());
            } else {
                // Image is not encoded
                return await resp.arrayBuffer();
            }
        } catch (e) {
            console.error(`Failed to fetch image: ${e}`);
        }
    }
    async getCaptchaImageDisplay(imgUrl) {
        const canvas = createCanvas(400, 400), ctx = canvas.getContext('2d');
        ctx.font = "20px Arial";
        const buffer = await this._getImage(imgUrl);
        if (!buffer) return;
        ctx.drawImage(await loadImage(Buffer.from(buffer)), 50, 150);
        ctx.drawImage(await loadImage(this.exampleImgs['correct']), 150, 5);

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

    async getToken(github = true) {
        if (!await cache.update()) return;
        console.debug("[FunCaptcha] Getting a new token...");
        const browserData = this._generateBDA();
        if (!browserData) return console.error("[FunCaptcha] Failed to generate a browser fingerprint.");
        let resp = await fetch(this.captchaEndpoint + `/fc/gt2/public_key/${this.publicKey}`, {
            method: 'POST',
            headers: {'Content-Type': 'application/x-www-form-urlencoded', 'User-Agent': this.userAgent},
            body: new URLSearchParams({
                bda: browserData,
                public_key: this.publicKey,
                site: "https://octocaptcha.com",
                // site: "https://client-demo.arkoselabs.com",
                userbrowser: this.userAgent,
                rnd: Math.random().toString(),
                "data[origin_page]": github ? "github_signup" : ""
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
        console.debug('Sending solve request...');
        let resp = await fetch(this.captchaEndpoint + '/fc/ca/', {
            method: 'POST',
            headers: {'Content-Type': 'application/x-www-form-urlencoded', 'User-Agent': this.userAgent},
            body: new URLSearchParams({
                game_token: this.challengeID,
                sid: 'ap-southeast-1',
                session_token: this.token,
                guess: cache.buildRequest(JSON.stringify(answers), this.token),
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
