const express = require('express');
const router = express.Router();
const app = express();
const request = require('request');
const http = require('http').Server(app);
const svr = require('../server.js');
const io = svr.io;
const helpers = require('../helpers.js');
const hookViewer = require('../hookViewer.js');
const util = require('util');
const hookCommandTypes = svr.hookCommandTypes;

let title;
let description;
let body;

// Read mock data from files
const fs = require('fs');
let rawUsersData = fs.readFileSync('./data/mock_data.json');
let users = JSON.parse(rawUsersData);

/**
*
* SAML token extensibilty Hook Handler (simple email domain demo example)
*
* This demo example will use the op.add command to add a claim called 'externalData'to the assertion, 
* with a hardcoded value of 'NOT_IN_OKTA'. 
*
* If the users email domain is 'allow.example.com' we'll also issue an op.replace
* command to change the subject.nameId domain to 'different.example.com'.
* 
* NOTE: In a production environment, you MUST check the Authorization header. 
* This MUST be done on every request made to this endpoint to verify that the request is really from Okta.
*
**/
router.post("/domain", (req, res) => {
  let requestBody = req.body;
  
  title = req.originalUrl;
  description = `Okta SAML token Hook handler called. Here's the body of the request from Okta:`;
  body = requestBody;
  
  hookViewer.emitViewerEvent(title, description, body, true);  
  
  // Find User secret attribute
  const emailAddress = requestBody.data.context.user.profile.login;
  var mockDirUser = users.users.filter(u => u.email === emailAddress);
  var userSecretData = mockDirUser[0].secret
  var secretValue = (userSecretData != "" ? userSecretData : "GENERIC_SECRET_VALUE");
  
  // all assertions get the sensitiveData demo attribute, value set above
  let debugContext = {
    externalClaims: [
      {
        sensitiveData: secretValue
      }
    ]
  };
  
  // Set the value for the commandArray variable used later to send response to Okta
  let commandArray = [
      {
        "op": "add",
        "path": "/claims/sensitiveData",
        "value": {
          "attributes":
          {
            "NameFormat": "urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
          },            
          "attributeValues": [
            {
              "attributes":
              {
                "xsi:type": "xs:string"
              },
              "value": secretValue
            }
          ]
        }
      }          
  ]

  // This section is a good example of adding additional claims/mods to the assertion
  // Commented out for now as I'm not using it
  /*    
  // If the user's email domain is 'allow.example.com', use the 'replace' command to change domain of the subject.nameId
  const emailDomain = helpers.parseEmailDomain(emailAddress);
  
  if (emailDomain === 'allow.example.com') {
    let emailName = emailAddress.split('@')[0] + '@different.example.com';
   
    // add the additonal command
    const cmd = {        
      "op": "replace",
      "path": "/subject/nameId",
      "value": emailName
    }  
    
    // a corresponding debug context message on the the debugContext array to capture the event in the Okta syslog
    let newClaimDebugContext = {
      nameId: emailName
    }
    
    debugContext.externalClaims.push(newClaimDebugContext);    
    
    commandArray.push(cmd);  
  } */
  
  // compose the final 'commands' attribute
  const commands = [
    {
      "type": hookCommandTypes.samlAssertionPatch,
      "value": commandArray
    }       
  ];
     
  // stringify the debug context so that a JSON payload can be based back to Okta as a string
  debugContext = JSON.parse(JSON.stringify(debugContext));
 
  const responseBody = {
      "result": "SUCCESS",
      "commands": commands,
      "debugContext": debugContext
  }  
  
  // log our response in the live Hook Viewer
  title = req.originalUrl;
  description = `Below is the <b>response</b> that our Hook handler will return to Okta:`;
  body = responseBody;

  hookViewer.emitViewerEvent(title, description, body, true);   
  
  res.status(200).send(responseBody);
  
});

/**
*
*  SAML token extensibilty Hook Handler (db lookup example)
*  JB - NOTE: This does not work at the moment. Fix later for another demo
*  You'll need to at least fix the commandArray syntax, etc.
*
**/

router.post('/dblookup', function(req, res) {
  let requestBody = req.body !== undefined ? req.body : "";
  let provider = requestBody.data.context.protocol.request.providerName !== undefined ? requestBody.data.context.protocol.request.providerName : "";
  let issuer = requestBody.data.context.protocol.issuer.name !== undefined ? requestBody.data.context.protocol.issuer.name : "";
  let lastName = requestBody.data.context.user.profile.lastName !== undefined ? requestBody.data.context.user.profile.lastName : "";
  let last4;
  
  title = '/okta/hooks/saml-token/dblookup';
  description = `Okta SAML token Hook handler called for provider: <b>${provider}</b>, issuer: <b>${issuer}</b>. Here's the body of the request from Okta:`;
  body = requestBody;
  
  hookViewer.emitViewerEvent(title, description, body, true);  
   
  // look up the user in the member-data service and compose a claim using the last 4 of the user's SSN
  const requestJson = {
    "lastName": lastName
  }  
  
  const options = {
    uri: `${process.env.MEMBER_INFO_API}`,
    method: 'POST',
    headers: {
      'Accept': 'application/json',
      'Content-Type': 'application/json',
      'Cache-Control': 'no-cache',
      'x-api-key': process.env.MEMBER_DATA_API_KEY
    },
    json: requestJson
  };
  
  request(options, function(error, response, body) {
  
    console.log(`Member data API request:\n`, util.inspect(options, {showHidden: false, depth: null, colors: true}));
    
    if (error) {
      console.log(`Status: ${response.statusCode}`);
      console.error(error);
      //res.status(500).send(error);
    }
    
    if (response) {
      
      error = null;
      console.log(`Member data API response code: ${response.statusCode}`);
      console.log(`Member data API response body:\n`, util.inspect(response.body, {showHidden: false, depth: null, colors: true}));
      
      if (response.statusCode === 200) {
      // If we found a match in the Member service
        last4 = response.body.last4;
        
        let debugContext = {
          externalClaims: [
            {
              last4: last4
            }
          ]
        };

        // compose 'commands' attribute
        let commandArray = [
          {
            "op": "add",
            "path": "/claims/SSN4",
            "value":
            {
                "attributes":
                {
                  "NameFormat": "urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
                },
                "attributeValues": [
                {
                    "attributes":
                    {
                      "xsi:type": "xs:string"
                    },
                    "value": last4
                }
              ]
            }
          }          
        ]

        // compose the final 'commands' attribute
        const commands = [
          {
            "type": hookCommandTypes.samlAssertionPatch,
            "value": commandArray
          }       
        ];  

        // stringify the debug context so that a JSON payload can be based back to Okta as a string
        debugContext = JSON.parse(JSON.stringify(debugContext));  

        const responseBody = {
            "result": "SUCCESS",
            "commands": commands,
            "debugContext": debugContext
        }  

        // log our response in the live Hook Viewer
        title = '/okta/hooks/saml-token';
        description = `Below is the <b>response</b> that our Hook handler will return to Okta:`;
        body = responseBody;

        hookViewer.emitViewerEvent(title, description, body, true);   

        res.status(200).send(responseBody);        
        
      } else {
        // Member last name wasn't found in Members service
        
        // log our response in the live Hook Viewer
        title = '/okta/hooks/saml-token';
        description = `Below is the <b>response</b> that our Hook handler will return to Okta:`;
        body = `The Hook handler did not modify the SAML assertion, so we are just returning a 204 to Okta.`;

        hookViewer.emitViewerEvent(title, description, body, true);        
        
        res.status(204).send();
     }

    }
        
  });
    
});

  
/**
 * Expose the API routes
 */
module.exports = router;