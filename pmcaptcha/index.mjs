import express from "express";
import crypto from "crypto";
import {FunCaptcha, ReCaptchaV2} from "./catpcha.mjs";
import ascii85 from "ascii85";

import {createHandler} from "@bittrance/azure-function-express";

const app = express();
app.use(express.json({type: 'application/*+json'}));

// region Ark Labs (FunCaptcha)

app.get("/funcaptcha", async (req, res) => {
    const uuid = ascii85.encode(Buffer.from(crypto.randomUUID().replaceAll("-", ""), "hex")).toString();
    const captcha = new FunCaptcha();
    if (!await captcha.getToken(req.query['github'] !== void 0)) return res.json({error: "Failed to get token"});
    const result = await captcha.getGameInfo(req.query['hl']);
    if (!result) return res.json({error: "Failed to get captcha info"});
    const [target, challengeImages] = result, images = [];
    for (const imgUrl of challengeImages) {
        images.push(ascii85.encode(await captcha.getCaptchaImageDisplay(imgUrl)).toString());
    }

    res.json({
        id: uuid, captcha: {
            version: captcha.captchaVersion,
            challenge_id: captcha.challengeID,
            token: captcha.token,
            expires: new Date().getTime() + 5 * 60 * 1000
        }, target, image_count: images.length, images
    })
});

app.post("/funcaptcha_answer", async (req, res) => {
    if (!Object.keys(req.body).length) return res.status(400).end();
    const captcha = new FunCaptcha();
    captcha.captchaVersion = req.body['version'];
    captcha.challengeID = req.body['challenge_id'];
    captcha.token = req.body['token'];
    const answers = req.body['guess'].map(pos => captcha.getImgArea(Math.floor(pos - 1)));
    const resp = await captcha.solve(answers);
    res.json({
        result: resp['solved']
    })
});

// endregion

// region reCPATCHA v2

// Proto

app.get("/recaptcha", async (req, res) => {
    const uuid = ascii85.encode(Buffer.from(crypto.randomUUID().replaceAll("-", "").replaceAll("\x00", "*"), "hex")).toString();
    const captcha = new ReCaptchaV2();
    const response = await captcha.getCaptcha(null, req.query['hl']);

    res.json({
        id: uuid, captcha: {
            version: captcha.captchaVersion,
            token: response.recaptchaToken,
            expires: new Date().getTime() + response.expireInSeconds * 1000
        }, target: response.target, image: ascii85.encode(response.image).toString()
    });
});

app.post("/recaptcha_next_img", async (req, res) => {
    if (!Object.keys(req.body).length) return res.status(400).end();
    const captcha = new ReCaptchaV2();
    captcha.captchaVersion = req.body.version;
    const response = await captcha.getNextImage(req.body.image, req.body.token, req.body['orig_pos'], req.body.pos);
    res.json({
        captcha: {
            token: response.recaptchaToken
        },
        image: ascii85.encode(response.image).toString(),
        empty: response.empty
    });
});

app.post("/recaptcha_answer", async (req, res) => {
    if (!Object.keys(req.body).length) return res.status(400).end();
    const captcha = new ReCaptchaV2();
    captcha.captchaVersion = req.body.version;
    const result = await captcha.solve(req.body.token, req.body.guess);
    if (result.success) return res.json({result: true}); else if (!result.reloadResponse) {
        console.debug("No reload response");
        return res.json({result: false});
    }
    // Most of the time, you need to do it twice
    let response = result.reloadResponse;
    if (response.captchaType !== "dynamic") response = await captcha.getCaptcha(response.recaptchaToken, req.query['hl']);
    res.json({
        result: false,
        captcha: {
            version: captcha.captchaVersion,
            token: response.recaptchaToken,
            expires: new Date().getTime() + response.expireInSeconds * 1000
        },
        target: await captcha._getName(response.mid, req.query['hl'] || "en"),
        image: ascii85.encode(await captcha._getImage(response.param)).toString()
    });
});


// endregion

// Uncomment this to enable development environment
// app.listen(8080, "127.0.0.1", () => {
//     console.log(`Server is running on port ${port}`);
// });

export default createHandler(app);
