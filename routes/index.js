 /** 
  * @author: Nathan Brophy, Maverick Software Consulting 
  * @version v1.0.2  
  */
var express = require('express');
var app = express(); 
var router = express.Router(); 
var postmark = require('postmark'); 
var config = require('./serverConfig.json'); 
var https = require('https');

//set up the express-validation checker requirements
const {check, validationResult} = require('express-validator/check');
const {matchedData, sanitize} = require('express-validator/filter');

//Render a 404 error on get, as to not open ourselves up to an XSS attack or spam service.
router.get('/', function(res, req, next){
  res.status(404);
  res.render('404');
}); 

router.post('/', [
    check('fName').isLength({min: 1, max: 60}).withMessage('First Name:').trim().escape(),
    check('lName').isLength({min: 1, max: 80}).withMessage('Last Name:').trim().escape(),
    //a call to optional is made to allow null phoneNum fields to pass through without error
    check('phoneNum').optional({checkFalsy: true}).isMobilePhone('en-US').withMessage('Phone Number:').trim().blacklist('.()-\\s'),
    check('email').isEmail().withMessage('Email:').trim().normalizeEmail(),
    check('message').isLength({min: 1, max: 1000}).withMessage('Message:').trim().escape()
  ], (req, res, next) => { //lambda function to handle the post
  const errors = validationResult(req);
  var validationErrors = []; //set up the errors array
  if (!errors.isEmpty()){ 
    validationErrors = errors.array();
  }
  //following variables check to see if the req URL is in the whitelist or not
  var headerURL = req.get("Referer"); //will return undefined if accessed from a local host
  var badURL = !(config.settings.WhiteList.okRequestURL.includes(headerURL)) || isTesting(req); //boolean var to see if url in the ok urls

  //check captcha for a value
  var captchaError = false;
  if (req.body['g-recaptcha-response'] === undefined || req.body['g-recaptcha-response'] === '' || req.body['g-recaptcha-response'] === null) {
           captchaError = true;         
        }   
  var captchaErrorMsg = { location: 'body', param: 'captcha', value: '', msg: 'Invalid Captcha'};
  if (captchaError) {
    validationErrors.push(captchaErrorMsg);
  }

  if (validationErrors.length > 0 || badURL) {
    //when there are user errors a call to renderClientErrors is called to handle them
    if(!badURL && !captchaError) renderClientErrors(res, req, validationErrors, badURL);
    if(captchaError) console.error("Invalid captcha!");
   }
  else {
      var key = req.body['g-recaptcha-response'] + "&remoteip=" + req.connection.remoteAddress;
      verifyRecaptcha(key, isTesting(req), function(success) {
        if(success){
          processMessage(req, res);
       }
       else{
          console.error("Invalid captcha!");
        }
      });
    }
    res.status(200).end()
});

//helper function for the post method to run the postmark engine and send emails
function processMessage(req, res) {
  var sanitizedData = matchedData(req);
  var contactDate = new Date().toString();
  //create a JSON object of all the form fields from the contact us request
  var form = {
    "contactDate" : contactDate,
    "fName"       : sanitizedData.fName,
    "lName"       : sanitizedData.lName,
    "phoneNum"    : sanitizedData.phoneNum,
    "email"       : sanitizedData.email,
    "message"     : sanitizedData.message
  };
  sendThankYouEmail(form);
  sendEmail(form);
}

/**
 * @param data a JSON object containing the sanitized fields of the body that was parsed.
 */
function sendThankYouEmail(data) {
  //establish a client connection with the postmark service
  var client = new postmark.Client(config.settings.PostmarkAPI);
  //request for the postmark client to send the email
  client.sendEmailWithTemplate({
    "From" 		 : config.settings.ThankYou.emailFrom,
	  "To"		   : data.email,
    "TemplateId" : config.settings.ThankYou.templateID,
    "TemplateModel" : {
      "fName"   	: data.fName,
      "lName"   	: data.lName,
    },
    function(error, result){ 
      if(error){
        console.error("Unable to send Thank You Email via postmark " + error.message);
      }
    }
  });
}

/**
 * @param data a JSON object containing the sanitized fields of the body that was parsed.
 */
function sendEmail(data) {
  //establish a client connection with the postmark service
  var client = new postmark.Client(config.settings.PostmarkAPI);
  client.sendEmailWithTemplate({	  //send the email
    "From" 		 : config.settings.Contact.emailFrom,
	  "To"		   : config.settings.emailTo, 
    "TemplateId" : config.settings.Contact.templateID,
    "TemplateModel" : {
      "fName"       : data.fName,
      "lName"       : data.lName,
      "contactDate" : data.contactDate,
      "tel"         : data.phoneNum,
      "email"       : data.email,
      "message"     : data.message,
    },
    function(error, result){ 
      if(error){
        console.error("Unable to send Email via postmark " + error.message);
      }
    }
  });
}

/**
 * @param data a JSON object containing the sanitized fields of the body that was parsed.
 */
function sendErrorEmailMav(data) {
  //establish a client connection with the postmark service
  var client = new postmark.Client(config.settings.PostmarkAPI);
  client.sendEmailWithTemplate({	//send the email 
    "From" 		 : config.settings.Error.emailFrom,
	  "To"		   : config.settings.emailTo, 
    "TemplateId" : config.settings.Error.templateIDMav,
    "TemplateModel" : {
      "fName"       : data.fName,
      "lName"       : data.lName,
      "contactDate" : data.contactDate,
      "tel"         : data.phoneNum,
      "email"       : data.email,
      "message"     : data.message,
      "errorString" : data.errorString
    },
    function(error, result){ 
      if(error){
        console.error("Unable to send error Email via postmark " + error.message);
      }
    }
  });
}

/**
 * @param email is the user email
 * @param errors are a string representation of the errors rendered by the client.
 */
function sendErrorEmailUser(email, errors){
  var client = new postmark.Client(config.settings.PostmarkAPI);
  client.sendEmailWithTemplate({	//send the email 
    "From" 		 : config.settings.Error.emailFrom,
	  "To"		   : email,
    "TemplateID" : config.settings.Error.templateIDUser,
    "TemplateModel" : {
      "errorString" : errors
    },
    function(error, result){
      if(error){
        console.log("Unable to send error Email to user via postmark " + error.message);
      }
    }
  });
}

/**
 * @param email is the user email
 */
function sendBadURLEmail(email){
  var client = new postmark.Client(config.settings.PostmarkAPI);
  client.sendEmailWithTemplate({	//send the email
    "From" 		 : config.settings.Error.emailFrom,
	  "To"		   : email,
    "TemplateID" : config.settings.Error.templateIDBadURL,
    "TemplateModel" : {},
    function(error, result){
      if(error){
        console.log("Unable to send bad Url error Email via postmark " + error.message);
      }
    }
  });
}

/**
 * @param validationErrors an array of the validation errors recorded by the express validator module functions
 * @param badURL a boolean value to test whether the requested url is in the whitelist
 */
function renderClientErrors(res, req, validationErrors, badURL) {
  var sanitizedData = matchedData(req);
  var contactDate = new Date().toString();
  var errString = getErrorString(validationErrors);
  var validEmail = !(getErrors(validationErrors).includes("email"));
  //create a JSON object of all the form fields from the contact us request
  var form = {
    "errorString" : errString,
    "errors"      : validationErrors,
    "contactDate" : contactDate,
    "fName"       : sanitizedData.fName,
    "lName"       : sanitizedData.lName,
    "phoneNum"    : sanitizedData.phoneNum,
    "email"       : sanitizedData.email,
    "message"     : sanitizedData.message
  };
  if(validEmail){ //make sure the email is valid before attempting to send one 
	  if(badURL){ //if the url is not valid i.e. a spam program
		  //send an email to tell them to use the correct site in case they are not a bot
		  sendBadURLEmail(form.email);
	  }
	  else{ //case that it was a non-spam bot related error
		sendErrorEmailMav(form)
		sendErrorEmailUser(form.email, errString);
	  }
  } else {
    sendErrorEmailMav(form);
  }
}

/**
 * @param errList an array of the errors given back by the validator
 * @return {string} an easy to read, and descriptive string that is used in the emails sent out in the error case
 */  
function getErrorString(errList){
  var errors = getErrors(errList); //get a list of the param handles to pattern match over
  var ret = "";
  for(var er = 0; er < errors.length; er++){
    //iterate over the param handle list to build an error string for the email
    switch (errors[er]) {
      case "phoneNum": ret += "Phone Number, "
        break;
      case "fName": ret += "First Name, "
        break;
      case "lName": ret += "Last Name, "
        break;
      default: ret += errors[er] + ", ";
    }
  }
  return ret.slice(0, -2); //slicing gets rid of the final comma and space 
}

/**
 * @param errList an array of error objects returned by the validator functions
 * @return {Array} an array of the parameter(s) that caused an error
 */
function getErrors(errList){
  var errs = [];
  for(var e = 0; e < errList.length; e++){
    errs.push(errList[e].param);
  }
  return errs;
}

//function to verify the captcha result and push out emails if it was validated
function verifyRecaptcha(key, testing, callback) {    
  if(!testing) {
    var config = require("./serverConfig.json");  
    var secretKey = config.settings.Captcha.privateKey;      
    https.get("https://www.google.com/recaptcha/api/siteverify?secret=" + secretKey + "&response=" + key, function(res) {
      var data = "";
      res.on('data', function (chunk) {
        data += chunk.toString();
      });
      res.on('end', function() {
        try {
          var parsedData = JSON.parse(data);        
          callback(parsedData.success);          
        } 
        catch (e) {        
          console.log('captcha server fail');
          callback(false);
        }
      });
    });
  }
  else {callback(true);}
}

//function to check whether or not we are in testing mode 
function isTesting(req) {
  var retVal = false;
  if (req.session.testingMode != null && req.session.testingMode) {
    retVal = true;
  }
  return(retVal);
}
module.exports = router;


