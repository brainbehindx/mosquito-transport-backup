import { MongoClient } from "mongodb";
import { serialize } from 'mongodb/lib/bson.js';
import { encryptData, isPath, isValidColName, isValidDbName, isValidMongoURL, one_mb, RESERVED_DB, Validator, wait } from "../utils.js";
import { readdir, stat } from "fs/promises";
import { createReadStream } from "fs";
import { WritableBit } from "@deflexable/bit-stream";
import { resolve as resolveAsPath } from "path";
import { BLOCKS_IDENTIFIERS } from "../values.js";

const BIT_SIZE = one_mb * 200;
const DOC_LIMITER = 300;

/**
 * stream out mosquito-transport data
 * 
 * @param {{ password?: string | undefined, storage?: string | undefined, onMongodbOption?: ((url: string) => import("mongodb").MongoClient | import("mongodb").MongoClientOptions) | undefined, database?: {[url: string]: {[dbName: string]: '*' | Array<string>}}, onProgress?: (stats: { documents: number, files: number, database: {} }) => void, signal: { stopage?: Promise<void> | undefined } }} config 
 * @returns {import("@deflexable/bit-stream").WritableBit}
 */
export default function backup(config) {
    let { database, storage, password, onMongodbOption, onProgress, signal } = { ...config };

    if (password !== undefined && (typeof password !== 'string' || !password))
        throw `expected "password" as non-empty string but got ${password}`;

    if (onMongodbOption !== undefined && typeof onMongodbOption !== 'function')
        throw `expected "onMongodbOption" to be function but got: ${onMongodbOption}`;

    if (storage !== undefined) {
        if (!isPath(storage)) throw `expected "storage" to be a valid path but got ${storage}`;
    }

    if (database !== undefined) {
        if (Validator.OBJECT(database)) {

            for (const [dbUrl, dbNameObj] of Object.entries(database)) {
                if (!isValidMongoURL(dbUrl))
                    throw `invalid mongodb url format: ${dbUrl}`;

                for (const [dbName, col] of Object.entries(dbNameObj)) {
                    if (dbName !== '*' && !isValidDbName(dbName))
                        throw `invalid dbName: "${dbName}"`;

                    if (col !== '*') {
                        if (Array.isArray(col)) {
                            col.forEach(r => {
                                if (!isValidColName(r))
                                    throw `invalid collection name: "${r}"`;
                            });
                        } else throw `collection should be either "*" or Array<string> but got ${col}`;
                    }
                }
            }
        } else throw `expected "database" to be an object but got ${database}`;
    }

    const stream = new WritableBit();

    let readDocuments = 0;
    let readFiles = 0;
    const databaseMap = {};

    const updateStats = () => {
        onProgress?.({
            documents: readDocuments,
            files: readFiles,
            database: databaseMap
        });
    }

    (async () => {
        try {
            const pushBuffer = (buf) => {
                if (stream.writable) {
                    stream.write(
                        password ? encryptData(buf, password) : buf
                    );
                } else throw 'stream ended prematurely';
            }

            /**
             * we chunk and optionally encrypt mongodb
             * data bit-by-bit and write it to the stream
             */
            if (database) {
                for (let [dbUrl, dbNameObj] of Object.entries(database)) {
                    const mongoHandle = onMongodbOption?.(dbUrl);
                    const isInstance = mongoHandle instanceof MongoClient;

                    const dbInstance = isInstance ? mongoHandle : new MongoClient(dbUrl, { ...mongoHandle });
                    await dbInstance.connect();

                    pushBuffer(Buffer.from(BLOCKS_IDENTIFIERS.DB_URL, 'utf8'));
                    pushBuffer(Buffer.from(`${dbUrl}`, 'utf8'));

                    if (dbNameObj === '*') {
                        const dbList =
                            (await dbInstance.db().admin().listDatabases())
                                .databases.map(v => v.name)
                                .filter(v => !RESERVED_DB.includes(v));

                        dbNameObj = Object.fromEntries(dbList.map(v => [v, '*']));
                    }

                    for (let [dbName, collections] of Object.entries(dbNameObj)) {
                        const dbNameInstance = dbInstance.db(dbName);

                        pushBuffer(Buffer.from(BLOCKS_IDENTIFIERS.DB_NAME, 'utf8'));
                        pushBuffer(Buffer.from(`${dbName}`, 'utf8'));

                        if (collections === '*') {
                            collections = (await dbNameInstance.listCollections().toArray()).map(v => v.name);
                        }

                        for (const colName of collections) {
                            let canLoadMore = true, offset = 0;

                            pushBuffer(Buffer.from(BLOCKS_IDENTIFIERS.COLLECTION, 'utf8'));
                            pushBuffer(Buffer.from(`${colName}`, 'utf8'));

                            while (canLoadMore) {
                                await wait(7); // pause for garbage collection
                                if (signal?.stopage) await signal.stopage;
                                const data =
                                    await dbNameInstance.collection(colName).find({})
                                        .skip(offset).limit(DOC_LIMITER).toArray();
                                offset += DOC_LIMITER;
                                canLoadMore = data.length === DOC_LIMITER;
                                readDocuments += data.length;

                                if (!databaseMap[dbUrl])
                                    databaseMap[dbUrl] = {};
                                if (!databaseMap[dbUrl][dbName])
                                    databaseMap[dbUrl][dbName] = {};
                                if (!databaseMap[dbUrl][dbName][colName])
                                    databaseMap[dbUrl][dbName][colName] = 0;

                                databaseMap[dbUrl][dbName][colName] += data.length;

                                updateStats();
                                data.forEach(doc => {
                                    pushBuffer(Buffer.from(BLOCKS_IDENTIFIERS.DOCUMENT, 'utf8'));
                                    pushBuffer(Buffer.from(serialize(doc)))
                                });
                            }
                        }
                    }
                }
            }

            /**
             * if storage is enabled we recursively read
             * the entire storage directory and optionally
             * encrypt the data bit-by-bit and write it to
             * the stream
             */
            if (storage) {
                const crawlStorage = async (dir = '') => {
                    const storagePath = dir.substring(storage.length);

                    if ((await stat(dir)).isFile()) {
                        await new Promise((resolve, reject) => {
                            pushBuffer(Buffer.from(BLOCKS_IDENTIFIERS.STORAGE_FILE_PATH, 'utf8'));
                            pushBuffer(Buffer.from(storagePath, 'utf8'));

                            const fileStream = createReadStream(dir);
                            let thisBits = [],
                                thisBitsize = 0;

                            const popFile = () => {
                                if (thisBits.length) {
                                    pushBuffer(Buffer.from(BLOCKS_IDENTIFIERS.STORAGE_FILE, 'utf8'));
                                    pushBuffer(Buffer.concat(thisBits));
                                }
                                thisBitsize = 0;
                                thisBits = [];
                            }

                            fileStream.on('data', chunk => {
                                thisBits.push(chunk);
                                if (thisBitsize += chunk.length >= BIT_SIZE) {
                                    popFile();
                                }
                            });

                            fileStream.on('end', () => {
                                popFile();
                                ++readFiles;
                                updateStats();
                                resolve();
                            });

                            fileStream.on('error', err => {
                                reject(err);
                            });
                        });

                        await wait(1); // pause for garbage collection
                        if (signal?.stopage) await signal.stopage;
                    } else {
                        const files = await readdir(dir);
                        if (files.length) {
                            for (const file of files) {
                                await crawlStorage(resolveAsPath(dir, './'.concat(file)));
                            }
                        } else if (storagePath) {
                            pushBuffer(Buffer.from(BLOCKS_IDENTIFIERS.STORAGE_DIRECTORY, 'utf8'));
                            pushBuffer(Buffer.from(storagePath, 'utf8'));
                        }
                    }
                }

                await crawlStorage(storage);
            }

            stream.end();
        } catch (error) {
            stream.destroy(error instanceof Error ? error : new Error(`${error}`));
        }
    })();

    return stream;
};