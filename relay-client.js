#!/usr/bin/env node

if (process.argv.length < 6) {
    const {basename} = require('path')
    console.log(basename(process.argv[0]), basename(process.argv[1]), "[relay server's endpoint]", "[secret string]", "[internal webhook server]", "[encryption private key]")
    process.exit(0)
}
    
const crypto = require('crypto');
const http = require('http')
const fs = require('fs')
const path = require('path')
const util = require('util')
const {URL} = require('url')
const EventSource = require('eventsource')

const private_key = process.argv[5]
const passphrase = process.argv[6]
const secret = process.argv[3]
let es = new EventSource(process.argv[2])
let timer = null

const decrypt_symmetric = (text, relativeOrAbsolutePathtoPrivateKey) => {
    let textParts = text.split(':');
    let encrypted_key = textParts.shift()
    let key = decrypt_asymmetric(encrypted_key, relativeOrAbsolutePathtoPrivateKey)
    let iv = Buffer.from(textParts.shift(), 'hex');
    let encryptedText = Buffer.from(textParts.join(':'), 'hex');
    let decipher = crypto.createDecipheriv('aes-256-ctr', Buffer.concat([Buffer.from(key), Buffer.alloc(32)], 32), iv);
    let decrypted = decipher.update(encryptedText);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString();
}

const decrypt_asymmetric = (toDecrypt, relativeOrAbsolutePathtoPrivateKey) => {
    let absolutePath = path.resolve(relativeOrAbsolutePathtoPrivateKey)
    let privateKey = fs.readFileSync(absolutePath, 'utf8')
    let buffer = Buffer.from(toDecrypt, 'base64')
    let decrypted = crypto.privateDecrypt(
        {
            key: privateKey.toString(),
            passphrase: passphrase,
        },
        buffer,
    )
    return decrypted.toString('utf8')
}

const handlePayload = (payload) => {
    var headers = JSON.parse(payload.headers)
    var body = JSON.parse(payload.body)
    if ('x-hub-signature' in headers) {
        var hex = crypto.createHmac('sha1', secret).update(payload.body).digest().toString('hex')
        if (headers['x-hub-signature'] == 'sha1=' + hex) {
            console.log('== headers ==')
            console.log(headers)
            console.log('== body ==')
            console.log(util.inspect(body, false, null, true))
            var url = new URL(process.argv[4])

            var options = {
                host: url.hostname,
                port: url.port,
                path: url.pathname,
                headers: headers,
                method: 'POST'
            }

            console.log('= response =')
            const req = http.request(options, (res) => {
                res.on('data', (chunk) => {
                    console.log(chunk.toString())
                })
            })
            req.write(payload.body)
            req.end()
        }
        return
    }
    if ('x-gitlab-token' in headers) {
        console.log('== headers ==')
        console.log(headers)
        console.log('== body ==')
        console.log(body)
    }
    if ('x-line-signature' in headers) {
        var signature = crypto.createHmac('sha256', secret).update(payload.body).digest("base64")
        if (headers['x-line-signature'] == signature) {
            console.log('== headers ==')
            console.log(headers)
            console.log('== body ==')
            console.log(util.inspect(body, false, null, true))
            var url = new URL(process.argv[4])

            var options = {
                host: url.hostname,
                port: url.port,
                path: url.pathname,
                headers: headers,
                method: 'POST'
            }

            console.log('= response =')
            const req = http.request(options, (res) => {
                res.on('data', (chunk) => {
                    console.log(chunk.toString())
                })
            })
            req.write(payload.body)
            req.end()
        }
        return
    }
}

encrypted_webhook = (e) => {
    console.log('= encrtpyed webhook =')
    var payload = JSON.parse(decrypt_symmetric(JSON.parse(e.data), private_key))
    handlePayload(payload)
}

plaintext_webhook = (e) => {
    console.log('= plaintext webhook =')
    var payload = JSON.parse(e.data)
    handlePayload(payload)
}

es.addEventListener('encrypted', encrypted_webhook)
es.addEventListener('webhook', plaintext_webhook)

const exit_when_no_ping = () => {
    console.log('Not received ping from server, close the app.')
    clearInterval(timer)
    es.close()
    process.exit(1)
}

timer = setInterval(exit_when_no_ping, 15000)

ping_webhook = (e) => {
    console.log("ping: " + e.data)
    clearInterval(timer)
    timer = setInterval(exit_when_no_ping, 15000)
}

es.addEventListener('ping', ping_webhook)
