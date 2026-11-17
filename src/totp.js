import { generateSecret, generateURI } from "otplib";
import { resolve as resolveAsPath } from 'path';
import { readFile, writeFile } from "node:fs/promises";
import { toString } from "qrcode";

const secret_path = resolveAsPath(process.cwd(), './.mosquito-totp-code.txt');

export const getTOTP_Secret = async (alwaysPrint) => {
    let OTP_SECRET = await readFile(secret_path, 'utf8').catch(() => '');

    if (!OTP_SECRET) {
        OTP_SECRET = generateSecret();
        await writeFile(secret_path, OTP_SECRET, 'utf8');
        console.warn('initializing TOTP...');

        if ([true, undefined].includes(alwaysPrint))
            await printTOTP(OTP_SECRET);

        console.log('initialized TOTP ✅');
    } else if (alwaysPrint) {
        await printTOTP(OTP_SECRET);
    }

    return OTP_SECRET;
}

export const getTOTP_URL = (secret) =>
    generateURI({
        issuer: 'BrainbehindX',
        label: 'Zerobase Export',
        secret
    });

export const printTOTP = async (secret, type) => {
    const otp_url = getTOTP_URL(secret);

    if (['url', undefined].includes(type))
        console.log('TOTP-URL:', otp_url, '\n\n');

    if (['qr', undefined].includes(type)) {
        console.log('TOTP QR-CODE:\n');
        console.log(await toString(otp_url, { type: 'terminal', small: true }));
    }
}