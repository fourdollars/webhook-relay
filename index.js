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

function isAuth(req, res, next) {
    const auth = {
        username: 'username',
        password: 'password'
    }
    const b64auth = (req.headers.authorization || '').split(' ')[1] || ''
    const [username, password] = Buffer.from(b64auth, 'base64').toString().split(':')
    if (username && password && username === auth.username && password === auth.password) {
      next()
    } else {
      if (!req.headers.authorization) {
          res.set('WWW-Authenticate', 'Basic realm="401"')
      }
      res.status(401).send('Authentication required')
    }
}

app.get('/relay/', isAuth, (req, res) => {
    let output = {}
    for (let key in pool) {
        output[key] = pool[key].counter
    }
    res.end(JSON.stringify(output))
})

app.get('/relay/:id', (req, res) => {
    let id = req.params.id
    if (!(id in pool)) {
        pool[id] = {
            'sse': new SSE(),
            'counter': 1,
            'timer': null
        }
    } else {
        pool[id].counter += 1
    }
    pool[id].sse.init(req, res)
    req.on('close', () => {
        pool[id].counter -= 1
        if (pool[id].counter == 0) {
            if (pool[id].timer) {
                clearInterval(pool[id].timer)
                pool[id].timer = null
            }
            delete pool[id]
        }
    })
    pool[id].sse.send(pool[id].counter, "ping")
    if (pool[id].timer === null) {
        pool[id].timer = setInterval(function(){
            pool[id].sse.send(pool[id].counter, "ping")
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
        /* Line */
        if ('x-line-signature' in req.headers) {
            var secret_file = path.join(secretFolder, req.params.id)
            if (!fs.existsSync(secret_file)) {
//                console.log(secret_file + " doesn't exist.")
                return res.status(404).end()
            }
            var secret = fs.readFileSync(secret_file, 'utf8')
            var base64 = crypto.createHmac('sha256', secret).update(req.rawPayload).digest("base64");
            if (req.headers['x-line-signature'] == base64) {
                return sendPayload(req, res)
            } else {
//                console.log("x-line-signature doesn't match.")
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
