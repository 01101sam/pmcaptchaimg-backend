import express from "express";
import {GoogleCaptcha} from "./pmcaptcha/catpcha.mjs";
import {Task} from "./pmcaptcha/task.mjs";
import {env} from '@huggingface/transformers';

env.allowRemoteModels = false;
env.allowLocalModels = true;
env['localModelPath'] = "models";

const app = express();
app.use(express.json({type: 'application/json'}));

async function verifyToken(token, siteKey, enterprise) {
    const resp = await fetch(`https://2captcha.com/api/v1/captcha-demo/recaptcha${enterprise ? '-enterprise' : ''}/verify`, {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({answer: token, token, siteKey})
    });
    return await resp.json();
}

async function verifyTokenV3(token) {
    const resp = await fetch("https://antcpt.com/score_detector/verify.php", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({"g-recaptcha-response": token})
    });
    return await resp.json();
}

// region reCPATCHA v2

async function getV2Token() {
    // v2 normal

    // const captcha = new GoogleCaptcha(
    //     "https://2captcha.com/",
    //     "6LfD3PIbAAAAAJs_eEHvoOl75_83eXSqpPSRFJ_u"
    // );

    // v2 enterprise

    const captcha = new GoogleCaptcha(
        "https://2captcha.com/",
        "6Lf26sUnAAAAAIKLuWNYgRsFUfmI-3Lex3xT5N-s",
        true
    );

    // v2 invisible

    // const captcha = new GoogleCaptcha(
    //     "https://2captcha.com/",
    //     "6LdO5_IbAAAAAAeVBL9TClS19NUTt5wswEb3Q7C5",
    //     false, true
    // );

    // v3
    // const captcha = new GoogleCaptcha(
    //     "https://2captcha.com/",
    //     "6Lcyqq8oAAAAAJE7eVJ3aZp_hnJcI6LgGdYD8lge",
    //     false, true,
    //     "demo_action"
    // );

    // v3 Enterprise
    // const captcha = new GoogleCaptcha(
    //     "https://2captcha.com/",
    //     "6Lel38UnAAAAAMRwKj9qLH2Ws4Tf2uTDQCyfgR6b",
    //     true, true,
    //     "demo_action"
    // );

    // v3 prod test

    // const captcha = new GoogleCaptcha(
    //     "https://antcpt.com/",
    //     "6LcR_okUAAAAAPYrPe-HK_0RULO1aZM15ENyM-Mf",
    //     true, true,
    //     "homepage"
    // );

    // Get Challenge Info
    let [result, reloadResponse] = await captcha.getCaptcha();
    if (!result) {
        console.error("Failed to get captcha", JSON.stringify(reloadResponse, null, 4));
        return;
    }
    console.info("Token:", reloadResponse.token);
    // debugger;

    console.info(JSON.stringify(await verifyToken(reloadResponse.token, captcha.siteKey, captcha.enterprise), null, 4));

    // while (true) {
    //     // Solve using Machine Learning
    //     const mlSolveResult = await captcha.solveML(reloadResponse);
    //     if (mlSolveResult) {
    //         const solveResponse = await captcha.solve(reloadResponse, mlSolveResult);
    //         if (solveResponse.success) {
    //             return solveResponse.toJSON();
    //         }
    //         console.warn("Failed to solve captcha. Retrying...");
    //         reloadResponse = await captcha.processReloadResponse(solveResponse.reloadResponse);
    //     } else
    //         reloadResponse = await captcha.getCaptcha();
    // }
}

app.post("/recaptcha/new", async (req, res) => {
    // siteUrl, siteKey, enterprise, invisible, action
    const captcha = new GoogleCaptcha(req.body);
    const newTask = await Task.createTask(captcha.getCaptcha());

    res.status(201).json({taskId: newTask});

    // const captcha = new GoogleCaptcha(req.body);
    // const [result, reloadResponse] = await captcha.getCaptcha();
    // await captcha.realBrowser.browser.close();
    // res.status(result ? 200 : 500).json(result ? reloadResponse.token : reloadResponse);
});

// endregion

// region Task

app.get("/task/:id", async (req, res) => {
    try {
        const getTaskResult = Task.getTask(req.params.id);
        if (getTaskResult) {
            res.status(getTaskResult.code);
            delete getTaskResult.code;
            res.json(getTaskResult);
            return;
        }
        res.status(500).end();
    } catch (e) {
        console.error(e);
        res.status(500).end();
    }
});

// endregion Task

app.listen(10087, "127.0.0.1", () => {
    console.log(`Dev server is running on port 10087`);
});

(new GoogleCaptcha({
    siteUrl: "https://www.google.com:443",
    siteKey: "6Le-wvkSAAAAAPBMRTvw0Q4Muexq9bi0DJwx_mJ-"
})).getCaptcha().then(console.log);