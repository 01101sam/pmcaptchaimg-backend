import {JSDOM} from "jsdom";
import {connect as puppeteerLaunch} from "puppeteer-real-browser";

class Browser {
    static instance = null;

    constructor() {
        this.browser = null;
        this.page = null;
    }

    static async getInstance() {
        if (this.instance) return this.instance;
        const {browser, page} = await puppeteerLaunch({
            headless: 'shell',
            args: ["--disable-feature=WebFontsCacheAwareTimeoutAdaption"]
        });

        try {
            await page.goto("https://accounts.google.com/_/bscframe");
            await page.waitForNetworkIdle();
        } catch (e) {
            console.error("Failed to load botguard page:", e);
            return false;
        }

        const browserSingleton = new Browser();
        browserSingleton.browser = browser;
        browserSingleton.page = page;

        return this.instance = browserSingleton;
    }

    async executeScript(scripts) {
        let lastResult;
        try {
            for (const script of scripts)
                lastResult = await this.page.evaluate(script);

            return lastResult;
        } catch (e) {
            console.error("Failed to execute script:", e);
        }
    }
}

export class BotGuardContext {
    static async getBotGuard() {
        let resp, htmlContent;
        while (1)
            try {
                resp = await fetch("https://accounts.google.com/ServiceLogin?hl=en", {headers: {"User-Agent": "APIs-Google/1.0"}});
                htmlContent = await resp.text();
                if (htmlContent.search("document.bg")) break;
            } catch (e) {
                console.error("Failed to fetch bot guard script:", e);
            }
        const frag = JSDOM.fragment(htmlContent);

        const botGuardScript = frag
                .querySelector('[jsname="xdJtEf"]')
                .querySelectorAll("script")[0].textContent.trim()
                .replace(/if\(\w="FNL"\+\w,\w\)try\{(\w+)=\w\./, "try{$1="),
            programData = frag.querySelector('#program').getAttribute("program-data");
        return [botGuardScript, programData];
    }

    static async getResponse() {
        const [botGuardScript, programData] = await BotGuardContext.getBotGuard();
        return await (await Browser.getInstance()).executeScript([
            botGuardScript,
            `var programData='${programData}'`,
            async () => {
                let bg;
                try {
                    bg = new window['botguard'].bg(programData, function () {
                    });
                } catch (e) {
                    console.error("Failed to initialize bot guard:", e);
                    return Promise.reject(e);
                }

                while (1)
                    try {
                        await new Promise(resolve => setTimeout(resolve, 100));
                        const result = bg.invoke();
                        if (result && !result.startsWith("FNL"))
                            return result;
                    } catch (e) {
                        console.error("Failed to invoke bot guard:", e);
                        return Promise.reject(e);
                    }

                return Promise.resolve(null);
            }
        ]);
    }
}