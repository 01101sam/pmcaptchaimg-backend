import {pipeline} from '@huggingface/transformers';
import wavefile from 'wavefile';
import ffmpeg from "fluent-ffmpeg";
import {Readable} from "node:stream";


const modelName = 'whisper-tiny.en',
    task = "automatic-speech-recognition";

export class ACRPipelineSingleton {
    static instance = null;

    static async getInstance(progress_callback = null) {
        if (this.instance) return this.instance;
        return this.instance = pipeline(task, modelName, {
            quantized: true,
            progress_callback,
            local_files_only: true
        });
    }

    static async preprocessAudioData(mp3AudioBuffer) {
        const wavData = await new Promise((resolve, reject) => {
            const chunks = [];
            try {
                ffmpeg(Readable.from(mp3AudioBuffer))
                    .audioChannels(1)
                    .audioCodec('pcm_f32le')
                    .audioFilters([
                        'aformat=sample_fmts=fltp:sample_rates=16000:channel_layouts=mono'
                    ])
                    .format("wav")
                    .on('error', err => reject(err))
                    .on('end', () => resolve(Buffer.concat(chunks)))
                    .pipe(null, {end: true})
                    .on('data', chunk => chunks.push(chunk));
            } catch (e) {
                reject(e);
            }
        });

        return new wavefile.WaveFile(wavData).getSamples();
    }

    static async predict(audioBuffer) {
        const [audio, classifier] = await Promise.all([
            ACRPipelineSingleton.preprocessAudioData(Buffer.from(audioBuffer)),
            ACRPipelineSingleton.getInstance()
        ]);
        return await classifier(audio);
    }
}

// (async () => {
//     env.allowRemoteModels = false;
//     env.allowLocalModels = true;
//     env['localModelPath'] = "../models";
//
//     const audioBuf = await fs.readFile("audio.mp3");
//     const time1 = Date.now();
//     const result = await ACRPipelineSingleton.predict(audioBuf);
//     const time2 = Date.now();
//     console.log("Time taken", time2 - time1);
//     const result2 = await ACRPipelineSingleton.predict(audioBuf);
//     const time3 = Date.now();
//     console.log("Time taken", time3 - time2);
//     console.log(result, result2);
//     debugger;
// })();