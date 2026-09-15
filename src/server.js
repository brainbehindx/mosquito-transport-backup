import express, { json, text } from "express";
import { Endpoints, getConfig, OTP_CONFIG_FILE } from "./values.js";
import { generateSecret, generateURI, verify } from "otplib";
import backup from "./core/backup.js";
import { createHash } from "node:crypto";
import { WritableBit } from "@deflexable/bit-stream";
import { one_mb } from "./utils.js";
import { resolve as resolveAsPath } from 'path';
import restore from "./core/restore.js";
import { readFile, writeFile } from "node:fs/promises";
import { toDataURL } from "qrcode";

export default async function start_server({ port, middleware, get_ip }) {
    const app = express();
    app.disable("x-powered-by");

    if (typeof middleware === 'function') app.use(middleware);

    [
        json({ type: '*/json', limit: '100MB' }),
        text({ type: 'text/plain', limit: '100MB' })
    ].forEach(e => {
        app.use(e);
    });

    const router = express.Router({ caseSensitive: true });

    const TIP_HEADER = Buffer.from('H', 'utf8');
    const BASE_BODY = Buffer.from('B', 'utf8');
    const CLEANUP_TIMER = 60_000 * 10;
    const MAX_RESIDUE_BUF_SIZE = one_mb * 500;

    const secret_path = resolveAsPath(process.cwd(), './'.concat(OTP_CONFIG_FILE));

    let OTP_SECRET = await readFile(secret_path, 'utf8').catch(() => '');

    if (!OTP_SECRET) {
        OTP_SECRET = generateSecret();
        await writeFile(secret_path, OTP_SECRET, 'utf8');
        console.warn('initializing TOTP...');

        const otp_url =
            generateURI({
                issuer: 'BrainbehindX Inc.',
                label: 'Mosquito Transport',
                secret: OTP_SECRET
            });

        await writeFile(resolveAsPath(process.cwd(), './.mosquito-totp-url.txt'), otp_url, 'utf8');
        await writeFile(resolveAsPath(process.cwd(), './.mosquito-totp-qrcode.txt'), await toDataURL(otp_url), 'utf8');
    }

    const externalConfig = await getConfig();

    const UsedPasskey = new Set([]);

    const IpAddressMap = {};
    const REQUEST_PER_30 = 10;

    /**
     * @param {(req: express.Request, res: express.Response) => Promise<any>} callback 
     * @returns {(req: express.Request, res: express.Response) => void}
     */
    const handleRouter = (callback) =>
        async (req, res) => {
            try {
                const { passkey } = req.headers;

                const otpResult = await verify({ secret: OTP_SECRET, token: passkey });
                if (!otpResult.valid) {
                    const ip_address = get_ip(req);

                    if (!IpAddressMap[ip_address]) {
                        IpAddressMap[ip_address] = {
                            counts: 0,
                            timer: setTimeout(() => {
                                delete IpAddressMap[ip_address];
                            }, 60_000 * 30)
                        };
                    }

                    if (++IpAddressMap[ip_address].counts >= REQUEST_PER_30) {
                        res.status(429).send('Too many requests');
                        return;
                    }

                    throw 'invalid passkey';
                }
                if (UsedPasskey.has(passkey)) throw 'you have recently used this passkey, wait a few minutes and try again';

                UsedPasskey.add(passkey);
                setTimeout(() => {
                    UsedPasskey.delete(passkey);
                }, 60_000);

                const result = await callback?.(req, res);
                if (result !== undefined || !res.headersSent) {
                    res.status(200).send({ result });
                }
            } catch (error) {
                if (!res.headersSent) {
                    res.status(501).send(`${error}`);
                }
            }
        };

    const BACKUP_PROCESS = {};

    const AFRESH_MESSAGE = 'Destroying stream to start afresh';

    app.use(
        router.post(
            Endpoints.backup,
            handleRouter(async (req, res) => {
                let { storage, database, offset = '' } = req.headers;
                database = JSON.parse(database);
                offset = (offset * 1) || 0;

                const hash_id =
                    createHash('sha256')
                        .update(JSON.stringify([storage, database]), 'utf8')
                        .digest('base64').substring(0, 90);

                const max_residue_size = Math.max(res.writableHighWaterMark, MAX_RESIDUE_BUF_SIZE);

                const prevInstance = BACKUP_PROCESS[hash_id];

                if (prevInstance && !prevInstance.disconnected) {
                    res.status(501).send('Another client is currently extracting backup with the same arguments, wait for their disconnection or completion before retrying');
                    return;
                }

                clearTimeout(prevInstance.timer);
                prevInstance.timer = undefined;

                const pauseStreaming = () => {
                    const p = BACKUP_PROCESS[hash_id];
                    if (p && !p.signal.stopage)
                        p.signal.stopage =
                            new Promise(resolve => {
                                p.signal.onDrain = resolve;
                            });
                }

                const doDrain = () => {
                    if (hasDisconnect) return;

                    try {
                        const p = BACKUP_PROCESS[hash_id];
                        p.signal.stopage = undefined;
                        p.signal.onDrain?.();
                    } catch (_) { }
                }

                const doCleanUp = () => {
                    const p = BACKUP_PROCESS[hash_id];
                    if (p) {
                        p._root_data.ended = true;
                        p.stream2.destroy(new Error(AFRESH_MESSAGE));
                        doDrain();

                        delete BACKUP_PROCESS[hash_id];
                    }
                }

                let hasDisconnect;

                res.on('close', () => {
                    hasDisconnect = true;
                    const p = BACKUP_PROCESS[hash_id];
                    if (p) {
                        p.disconnected = true;
                        p.timer = setTimeout(doCleanUp, CLEANUP_TIMER);
                    }
                    pauseStreaming();
                });

                res.on('drain', doDrain);

                if (
                    prevInstance &&
                    offset > 0 &&
                    prevInstance.sent >= offset &&
                    prevInstance.buf.byteLength >= prevInstance.sent - offset
                ) {
                    res.writeHead(200, { ['fs-strategy']: 'APPEND' });

                    prevInstance.disconnected = undefined;

                    if (res.write(prevInstance.buf.subarray(prevInstance.sent - offset))) {
                        doDrain();
                    } else pauseStreaming();

                    prevInstance.stream.on('data', chunk => {
                        if (hasDisconnect) return;

                        if (!res.write(chunk)) {
                            pauseStreaming();
                        }
                    });

                    prevInstance.stream.on('end', () => {
                        res.end();
                    });

                    prevInstance.stream.on('error', (err) => {
                        res.destroy(err);
                    });
                    return;
                }

                if (prevInstance) doCleanUp();

                res.writeHead(200);

                const progress =
                    (BACKUP_PROCESS[hash_id] = {
                        sent: 0,
                        docs: 0,
                        files: 0,
                        buf: undefined,
                        stream: undefined,
                        stream2: undefined,
                        _root_data: undefined,
                        signal: { stopage: undefined, onDrain: undefined },
                        disconnected: false,
                        timer: undefined
                    });

                let databaseStats = {};

                const stream =
                    backup({
                        password: externalConfig?.password,
                        storage: storage || externalConfig?.storage,
                        onMongodbOption: externalConfig?.onMongodbOption,
                        database: database || externalConfig?.database,
                        signal: progress.signal,
                        onProgress: s => {
                            progress.docs = s.documents;
                            progress.files = s.files;
                            databaseStats = s.database;
                            clientLog();
                        }
                    });

                const writable = new WritableBit();
                const root_info = { ended: false };

                progress.stream = writable;
                progress.stream2 = stream;
                progress._root_data = root_info;

                const clientLog = (message) =>
                    writable.write(
                        Buffer.concat([
                            TIP_HEADER,
                            Buffer.from(`${message || ''}` || getLineLog(`Reading ${convertByteToWord(progress.sent)}, ${progress.docs} documents and ${progress.files} files`), 'utf8')
                        ])
                    );

                writable.on('data', chunk => {
                    if (root_info.ended) return;

                    progress.sent += chunk.byteLength;

                    progress.buf =
                        Buffer.concat([progress.buf, chunk].filter(v => v))
                            .subarray(0, max_residue_size);

                    if (hasDisconnect) return;

                    if (!res.write(chunk)) {
                        pauseStreaming();
                    }
                });

                writable.on('end', () => {
                    if (!root_info.ended && BACKUP_PROCESS[hash_id])
                        delete BACKUP_PROCESS[hash_id];
                    res.end();
                });

                writable.on('error', (err) => {
                    if (
                        !err?.message?.includes?.(AFRESH_MESSAGE) &&
                        !root_info.ended &&
                        BACKUP_PROCESS[hash_id]
                    ) delete BACKUP_PROCESS[hash_id];
                    res.destroy(err);
                });

                stream.on('data', chunk => {
                    writable.write(
                        Buffer.concat([
                            BASE_BODY,
                            chunk
                        ])
                    );
                });

                stream.on('end', () => {
                    clientLog(`\nwritten database: ${JSON.stringify(databaseStats, null, 2)}`);
                    writable.end();
                });

                stream.on('error', err => {
                    clientLog(`\n${err}`);
                    writable.destroy(err);
                });
            })
        )
    );

    const RESTORE_PROCESS = {};

    app.use(
        router.post(
            Endpoints.restore,
            handleRouter(async (req, res) => {
                let { storage, database, file_id } = req.headers;
                database = JSON.parse(database);

                const prevInstance = RESTORE_PROCESS[file_id];

                if (prevInstance) {
                    if (!prevInstance.disconnected) {
                        res.status(501).send('Another client is currently restoring backup data with the same argument, wait for their disconnection or completion before retrying');
                        return;
                    }

                    res.writeHead(200, {
                        'fs-start': prevInstance.size || 0
                    });

                    prevInstance.disconnected = undefined;
                    clearTimeout(prevInstance.timer);
                } else {
                    res.writeHead(200);

                    const readable = restore({
                        password: externalConfig?.password,
                        storage: storage || externalConfig?.storage,
                        onMongodbOption: externalConfig?.onMongodbOption,
                        database: database || externalConfig?.database,
                        onProgress: s => {
                            if (RESTORE_PROCESS[file_id])
                                RESTORE_PROCESS[file_id].triggers.onProgress?.(s);
                        },
                        onComplete: (r) => {
                            if (RESTORE_PROCESS[file_id]) {
                                RESTORE_PROCESS[file_id].triggers.onComplete?.(r);
                                delete RESTORE_PROCESS[file_id];
                            }
                        },
                        onError: err => {
                            if (RESTORE_PROCESS[file_id]) {
                                RESTORE_PROCESS[file_id].triggers.onError?.(err);
                                delete RESTORE_PROCESS[file_id];
                            }
                        }
                    });

                    RESTORE_PROCESS[file_id] = {
                        size: 0,
                        stream: undefined,
                        disconnected: undefined,
                        stream: readable,
                        timer: undefined,
                        triggers: {
                            onError: undefined,
                            onComplete: undefined,
                            onProgress: undefined
                        }
                    };
                }

                const currentInstance = RESTORE_PROCESS[file_id];

                currentInstance.triggers.onProgress = (s) => {
                    res.write(
                        getLineLog(`Uploaded ${convertByteToWord(currentInstance.size)}..., Written ${s.documents} documents and ${s.files} files`),
                        'utf8'
                    );
                }

                currentInstance.triggers.onComplete = (v) => {
                    res.write(`\n${JSON.stringify(v, null, 2)}`, 'utf8');
                    res.end();
                }

                currentInstance.triggers.onError = (err) => {
                    res.write(`\nError: ${err}`, 'utf8');
                    res.destroy(err);
                }

                req.on('data', buf => {
                    const p = RESTORE_PROCESS[file_id];
                    p.size += buf.byteLength;
                    p.stream.write(buf);
                });

                req.on('end', () => {
                    const p = RESTORE_PROCESS[file_id];
                    p.stream.end();
                });

                req.on('close', () => {
                    const p = RESTORE_PROCESS[file_id];
                    if (p) {
                        p.disconnected = true;
                        p.triggers = {};
                        p.timer = setTimeout(() => {
                            const p = RESTORE_PROCESS[file_id];
                            if (p) {
                                p.stream.destroy(new Error('stream cleanup'));
                                delete RESTORE_PROCESS[file_id];
                            }
                        }, CLEANUP_TIMER);
                    }
                });
            })
        )
    );

    // TODO:
    // app.use(
    //     router.post(
    //         Endpoints.transfer,
    //         handleRouter(async (req, res) => {
    //             let { storage, database, read } = req.headers;
    //             database = JSON.parse(database);

    //             spawn()

    //             // download backup data
    //             // write backup data to @local
    //         })
    //     )
    // );

    app.listen(port, (err) => {
        if (err) {
            console.error('unable to start server, err:', err);
        } else console.log('server listening in port:', port);
    });
}

const getLineLog = (text) => `\r\x1b[K${text}`;

const convertByteToWord = (bytes) => {
    if (bytes < 1000) {
        return bytes + ' byte' + (bytes > 1 ? 's' : '');
    }
    if (bytes < 1000000) {
        let kb = bytes / 1024;
        return (kb < 10 ? roundToDecimalPlace(kb) : Math.round(kb)) + 'KB';
    }
    if (bytes < 1000000000) {
        let mb = bytes / 1048576; // (1024 * 1024);
        return (mb < 10 ? roundToDecimalPlace(mb) : Math.round(mb)) + 'MB';
    }
    let gb = bytes / 1073741824; // (1024 * 1024 * 1024);
    return (gb < 10 ? roundToDecimalPlace(gb) : Math.round(gb)) + 'GB';
};

const roundToDecimalPlace = (number, decimalPlace = 1) =>
    (Math.round(((number) + Number.EPSILON) * Math.pow(10, decimalPlace)) / Math.pow(10, decimalPlace));