const express = require('express')
const SSE = require('express-sse')
const path = require('path')
const fs = require('fs')
const crypto = require('crypto')

const app = express()
const sse = new SSE()

const pool = {}
const pubFolder = path.join(__dirname, 'public')
const pemFolder = path.join(__dirname, 'pem')
const secretFolder = path.join(__dirname, 'secret')
let timer = null

function encrypt_symmetric(text, relativeOrAbsolutePathToPublicKey) {
    let iv = crypto.randomBytes(16)
    let key = crypto.randomBytes(16).toString('hex')
    let cipher = crypto.createCipheriv('aes-256-ctr', Buffer.concat([Buffer.from(key), Buffer.alloc(32)], 32), iv)
    let encrypted = cipher.update(text);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return encrypt_asymmetric(key, relativeOrAbsolutePathToPublicKey) + ':' + iv.toString('hex') + ':' + encrypted.toString('hex');
}

function encrypt_asymmetric(toEncrypt, relativeOrAbsolutePathToPublicKey) {
  const absolutePath = path.resolve(relativeOrAbsolutePathToPublicKey)
  const publicKey = fs.readFileSync(absolutePath, 'utf8')
  const buffer = Buffer.from(toEncrypt, 'utf8')
  const encrypted = crypto.publicEncrypt(publicKey, buffer)
  return encrypted.toString('base64')
}

app.use(function(req, res, next) {
    var buf = ''
    req.on('data', function(chunk) { 
        buf += chunk
    })
    req.on('end', function() {
        req.rawPayload = buf
    })
    next()
})

app.use(express.json())

app.get('/stream', (req, res) => {
    sse.init(req, res)
})

app.get('/relay/', (req, res) => {
    res.end(JSON.stringify(pool))
})

app.get('/relay/:id', (req, res) => {
    if (!(req.params.id in pool)) {
        pool[req.params.id] = {
            'sse': new SSE(),
            'counter': 1
        }
    } else {
        pool[req.params.id].counter += 1
    }
    pool[req.params.id].sse.init(req, res)
    req.on('close', () => {
        pool[req.params.id].counter -= 1
        if (pool[req.params.id].counter == 0) {
            if (timer) {
                clearInterval(timer)
                timer = null
            }
            delete pool[req.params.id]
        }
    })
    pool[req.params.id].sse.send(pool[req.params.id].counter, "ping")
    if (timer === null) {
        timer = setInterval(function(){
            pool[req.params.id].sse.send(pool[req.params.id].counter, "ping")
        }, 7500)
    }
})

const sendPayload = (req, res) => {
    if ('!~passenger-proto' in req.headers) { delete req.headers['!~passenger-proto'] }
    if ('!~passenger-client-address' in req.headers) { delete req.headers['!~passenger-client-address'] }
    if ('!~passenger-envvars' in req.headers) { delete req.headers['!~passenger-envvars'] }
    var pem_file = path.join(pemFolder, req.params.id)
    if (fs.existsSync(pem_file)) {
        pool[req.params.id].sse.send(encrypt_symmetric(JSON.stringify({'headers': JSON.stringify(req.headers), 'body': req.rawPayload}), pem_file), "encrypted")
    } else {
        pool[req.params.id].sse.send(JSON.stringify({'headers': JSON.stringify(req.headers), 'body': req.rawPayload}), "webhook")
    }
    return res.end()
}

app.post('/relay/:id', async (req, res) => {
    if (req.params.id in pool) {
        /* Launchpad and Github */
        if ('x-hub-signature' in req.headers) {
            var secret_file = path.join(secretFolder, req.params.id)
            if (!fs.existsSync(secret_file)) {
//                console.log(secret_file + " doesn't exist.")
                return res.status(404).end()
            }
            var secret = fs.readFileSync(secret_file, 'utf8')
            var hex = crypto.createHmac('sha1', secret).update(req.rawPayload).digest().toString('hex')
            if (req.headers['x-hub-signature'] == 'sha1=' + hex) {
                return sendPayload(req, res)
            } else {
//                console.log("x-hub-signature doesn't match.")
                return res.status(404).end()
            }
        }
        /* Gitlab */
        if ('x-gitlab-token' in req.headers) {
            var secret_file = path.join(secretFolder, req.params.id)
            if (!fs.existsSync(secret_file)) {
//                console.log(secret_file + " doesn't exist.")
                return res.status(404).end()
            }
            var secret = fs.readFileSync(secret_file, 'utf8')
            if (req.headers['x-gitlab-token'] == secret) {
                return sendPayload(req, res)
            } else {
//                console.log("x-gitlab-token doesn't match.")
                return res.status(404).end()
            }
        }
    }
    res.status(404).end()
})

app.get('/', (req, res) => {
    res.sendFile(path.join(pubFolder, 'index.html'))
})
app.get('/favicon.ico', (req, res) => {
    res.sendFile(path.join(pubFolder, 'favicon.ico'))
})

setInterval(function(){
    sse.send(new Date().getTime(), "message")
},3000)

app.post('/', async (req, res) => {
    res.end('OK', 200)
})

app.listen(3000, function () {
    console.log('Node.js app listening on port 3000! node ' + process.version);
});
