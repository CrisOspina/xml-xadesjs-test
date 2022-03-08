const fs = require('fs')
var {Crypto} = require('@peculiar/webcrypto')
const xadesjs = require('xadesjs')
const {XMLSerializer} = require('xmldom')

const crypto = new Crypto()
xadesjs.Application.setEngine('NodeJS', crypto)

function preparePem(pem) {
  return (
    pem
      // remove BEGIN/END
      .replace(/-----(BEGIN|END)[\w\d\s]+-----/g, '')
      // remove \r, \n
      .replace(/[\r\n]/g, '')
  )
}

function pem2der(pem) {
  pem = preparePem(pem)
  // convert base64 to ArrayBuffer
  return new Uint8Array(Buffer.from(pem, 'base64')).buffer
}

async function main() {
  const hash = 'SHA-256'

  const alg = {
    name: 'RSASSA-PKCS1-v1_5',
    hash,
  }

  // Read cert
  const certPem = fs.readFileSync('./key/CERTIFICATE_M.pem', {encoding: 'utf8'})
  const certDer = pem2der(certPem)

  // Read key
  const keyPem = fs.readFileSync('./key/PRIVATE_KEY_M.pem', {encoding: 'utf8'})
  const keyDer = pem2der(keyPem)
  const key = await crypto.subtle.importKey('pkcs8', keyDer, alg, false, [
    'sign',
  ])

  // XAdES-EPES

  const xmlString = fs.readFileSync('./main.xml').toString()

  const xml = xadesjs.Parse(xmlString)

  const xadesXml = new xadesjs.SignedXml()

  const x509 = preparePem(certPem)

  const signature = await xadesXml.Sign(alg, key, xml, {
    id: 'id-AA7791D19927C81B37164582165154222',
    references: [{transforms: ['enveloped', 'c14n'], hash: 'SHA-256'}],
    policy: {
      hash,
      identifier: {
        value: '',
      },
    },
    signingCertificate: x509,
  })

  // xml.documentElement.appendChild(signature.GetXml())
  xml
    .getElementsByTagName('wsse:Security')
    .item(0)
    .appendChild(signature.GetXml())

  // serialize XML
  const oSerializer = new XMLSerializer()
  const sXML = oSerializer.serializeToString(xml)

  console.log(sXML.toString())
}

main().catch((err) => {
  console.error(err)
})
