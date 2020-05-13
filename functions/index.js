const functions = require('firebase-functions');
const hmac_sha256 = require('crypto-js/hmac-sha256');
const request = require('request');
const admin = require('firebase-admin');


const serviceAccount = require('./service-account-key.json');
const firebaseConfig = JSON.parse(process.env.FIREBASE_CONFIG);
firebaseConfig.credentials = admin.credential.cert(serviceAccount);
admin.initializeApp(firebaseConfig);


exports.getCustomToken = functions.https.onRequest((req,res) => {

    const accessToken = req.query.accessToken;
    const facebookAppSecret = '65c452b44bec1855be257cf7c845a4b9'
    const appSecretProof = hmac_sha256(accessToken,facebookAppSecret);


    //validate token
    request({
        url: `https://graph.accountkit.com/v1.1/me?access_token=${accessToken}&appSecretProof=${appSecretProof}`,
        json:true
    },(error, fbResponse,data)=>{
        if(error)
        {
            console.error('Access token validation request failed\n', error);
            res.status(400).send(error);

        }

        else if(data.error){
            console.error('Invalid access token\n',
            `access_token=${accessToken}`, 
            `appsecret_proof=${appSecretProof}`
            ,data.error);
            res.status(400).send(data);
        }

        else {

            //validate
            admin.auth().createCustomToken(data.id)
            .then(customToken => res.status(200).send(customToken))
            .catch(error => {
                console.error('create custom token failed:', error);
                res.status(400).send(error);

            })

        }


    })


})

// // Create and Deploy Your First Cloud Functions
// // https://firebase.google.com/docs/functions/write-firebase-functions
//
// exports.helloWorld = functions.https.onRequest((request, response) => {
//  response.send("Hello from Firebase!");
// });
