<?php
//Helper functions to be 'include()'ed

const securityQuestions = [
    1 => 'What was the name of the first school you remember attending?' ,
    2 => 'Where was the destination of your most memorable school field trip?' ,
    3 => 'What was the name of your first stuffed toy?' ,
    4 => 'What was your driving instructor\'s first name?' ,
    5 => 'What is the name of a university you applied to but didn\'t attend?' ,
    6 => 'What is your oldest sibling\'s middle name?' ,
    7 => 'What was the first concert you attended?' ,
    8 => 'In what city or town did your parents meet?' ,
    9 => 'What was the make and model of your first car?' ,
    10 => 'What was your first highscore in a game?'
];

const phoneRegex = "/^\+[0-9]{0,2} [0-9]{8,14}$/";
const passwordRegex = "/^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[a-zA-Z]).{16,}$/";

function getPhoneRegexJS(): string
{
    return ltrim(rtrim(phoneRegex, '/'), '/'); //removes php delimiters
}

function getPasswordRegexJS(): string
{
    return ltrim(rtrim(passwordRegex, '/'), '/'); //removes php delimiters
}

function getSecurityQuestions(): array
{
    return securityQuestions;
}

function getHashingAlgo(): string
{
    return PASSWORD_BCRYPT;  //Salting is built into BCRYPT
}

function getDatabase(): SQLite3
{
    $db = new SQLite3('/home/danbates/uni-compsec-back/lovejoy.db', SQLITE3_OPEN_READWRITE);
    $db->enableExceptions(True); //debugging
    return $db;
}

function checkSession(): void
{
    if (session_status() != PHP_SESSION_ACTIVE) {
        //if no active session
        session_start();
        //set variables to check later
        $_SESSION['ipaddress'] = $_SERVER['REMOTE_ADDR'];
        $_SESSION['useragent'] = $_SERVER['HTTP_USER_AGENT'];
        $_SESSION['lastaccess'] = time();
    }

    //if IP Address doesn't match, or User Agent doesn't match -> Same Origin Policy
    if ($_SERVER['REMOTE_ADDR'] != $_SESSION['ipaddress'] || $_SERVER['HTTP_USER_AGENT'] != $_SESSION['useragent']) {
        quitSession();
    }

    //check the last time the session was used and quit it if over an hour ago
    if (time() > ($_SESSION['lastaccess'] + 3600)) {
        quitSession();
    } else {
        $_SESSION['lastaccess'] = time();
    }

    header("X-XSS-Protection: 1; mode=block"); //avoid XSS by blocking the page if it is detected
    //set content security policy for local content & hcaptcha. Building a string as header() doesn't handle newlines
    $cspHeader = "content-security-policy: default-src 'self'; img-src 'self'; child-src https://hcaptcha.com https://*.hcaptcha.com;";
    $cspHeader .= "script-src 'self' https://hcaptcha.com https://*.hcaptcha.com frame-src https://hcaptcha.com https://*.hcaptcha.com ";
    $cspHeader .= "style-src 'self' https://hcaptcha.com https://*.hcaptcha.com connect-src https://hcaptcha.com https://*.hcaptcha.com";
    header($cspHeader); //Content security policy, avoid XSS attacks. But also allow hcaptcha to function
}

function getUserID() {
    if (!isset($_SESSION['userid'])) {
        //username will have to be set from registration and activation
        $userIDQuery = getDatabase()->prepare("SELECT UserID FROM Users WHERE Username = ?");
        if (!isset($_SESSION['username'])) return False;
        $userIDQuery->bindValue(1, $_SESSION['username']);
        $userIDQueryResult = $userIDQuery->execute();
        if (!$userIDQueryResult) {
            return False; //if fails, return false
        }
        return $userIDQueryResult->fetchArray(SQLITE3_ASSOC)['UserID'];
    } else {
        return $_SESSION['userid'];
    }
}

function isUserSignedIn(): bool
{
    return
        session_status() == PHP_SESSION_ACTIVE &&
        isset($_SESSION['signedIn']) &&
        $_SESSION['signedIn'] &&
        isset($_SESSION['activated']) &&
        $_SESSION['activated'] && getUserID(); //session active, user signed in, account activated, AND UserID is set
}

function isUserAdmin(): bool
{
    if (isUserSignedIn()) {
        $userid = getUserID();
        if (!$userid) return False;

        $userAdminQuery = getDatabase()->prepare("SELECT * FROM Admins WHERE UserID = ?");
        $userAdminQuery->bindValue(1, $userid);
        $userAdminQueryResult = $userAdminQuery->execute();
        if ($userAdminQueryResult) {
            //User is an Admin
            if ($userAdminQueryResult->fetchArray(SQLITE3_ASSOC)) {
                return True; //if there is a returned row, user is admin, if not, they're not
            }
        }
    }
    return False;
}

function quitSession(): void
{
    session_unset();
    session_destroy();
}

function sanitise($data): string
{
    $data = trim($data);
    $data = stripslashes($data);
    return htmlspecialchars($data); //could also use striptags() for a similar effect, but this allows us to keep special chars intact
}

function generateRandomKey(): string
{   //random and not based on user data -> the 32bit hash of a random unique id
    return md5(uniqid(rand(), true));
}

function generateOTP(): string
{   //random and not based on user data -> the 32bit hash of a random unique id
    return substr(md5(uniqid(rand(), true)),6, 6); //offset doesn't really matter but this gets bytes 6-12 of 32
}

function generateRecoveryCodes($num = 6, $len = 6): array
{
    //generate random uppercase alphabetic codes
    $uppercaseAlphabet = range('A','Z');
    $codes = array();
    for ($i = 0; $i < $num;$i++) {
        shuffle($uppercaseAlphabet);
        $codes[$i] = substr(implode($uppercaseAlphabet), 0, $len);
    }
    return $codes;
}

function getEmailHeaders(): string
{
    $headers = "From: uni-compsec@danbat.es\r\n";
    $headers .= "Reply-To: uni-compsec@danbat.es\r\n";
    $headers .= "MIME-Version: 1.0\r\n";
    $headers .= "Content-Type: text/html; charset=UTF-8\r\n";
    return $headers;
}

function sendActivationEmail($name, $url, $address): string
{
    $subject = "Activate your account";
    $body = "<html><body>";
    $body .= "<h1>Lovejoy Antiques</h1>";
    $body .= "<p>Hi $name, great to have you on board!</p>";
    $body .= "<p><a href='$url'>Click here to activate your account</a></p>";
    $body .= "</body></html>";

    $retval = mail($address, $subject, $body, getEmailHeaders());
    if ($retval) {
        return "An activation email has been sent to you successfully (don't forget to check your spam folder!).";
    } else {
        return "An error has occurred and we haven't been able to send your activation email at this time, please try again later.";
    }
}

function sendTwoFactorEmail($name, $code, $address): string
{
    $subject = "One-Time Password for ".$name;
    $body = "<html><body>";
    $body .= "<h1>Lovejoy Antiques</h1>";
    $body .= "<p>Your one-time password is...</p>";
    $body .= "<p><b>$code</b></p>";
    $body .= "</body></html>";

    $retval = mail($address, $subject, $body, getEmailHeaders());
    if ($retval) {
        return "<h3>OTP sent</h3>";
    } else {
        return "<h3>Couldn't send OTP</h3>";
    }
}

function sendPasswordRecoveryEmail($url, $address): string
{
    $subject = "Reset your password";
    $body = "<html><body>";
    $body .= "<h1>Lovejoy Antiques</h1>";
    $body .= "<p><a href='$url'>Click here to reset your password.<a/></p>";
    $body .= "</body></html>";

    $retval = mail($address, $subject, $body, getEmailHeaders());
    if ($retval) {
        return "<h3>Password Recovery Email sent, it should be with you in a few minutes</h3>";
    } else {
        return "<h3>Couldn't send Password Recovery Email</h3>";
    }
}

function genericErrorMessage(): string
{ //A generic error message designed to be user-facing and not give away key information.
    return "<h1>That didn't quite work, please try again later or contact the admin at <a href='mailto:uni-compsec@danbat.es'></a>.</h1>";
}

function pageTop(): string
{
    return '<!DOCTYPE html>
<html lang="en">
<head>
    <title>Lovejoy Antiques</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    
    <link rel="stylesheet" href="lovejoy.css">
    <script src="lovejoy.js"></script>
    <link rel="stylesheet" href="packages/bootstrap-5.2.3-dist/css/bootstrap.min.css">
    <script src="packages/bootstrap-5.2.3-dist/js/bootstrap.bundle.min.js"></script>
</head>
<body class="wrapper">
<div id="top" class="bg-info">
    <h3 class="text-center p-4"><a class="text-light text-decoration-none" href="home.php">Lovejoy Antiques</a></h3>
</div>
<div id="center" class="d-flex justify-content-center">';
}

function pageBottom(): string
{
    return '
    </div>
    <footer class="footer transparent-overlay text-light p-1">©Candidate 234558 for G6077 2022</footer>      
</body>
</html>
';
}

function verifyHCaptcha(): bool
{
    if (isset($_POST['h-captcha-response']) && !empty($_POST['h-captcha-response'])) {
        $data = array (
            'secret' => '0x0Cb5d3565b1849F7B07f261c6405CeB4aE8c7e76',
            'response' => $_POST['h-captcha-response'],
            'sitekey' => '22353c5a-05f5-4f2f-9b3d-a644670de95c',
            'remoteip' => $_SESSION['ipaddress'] ?? ''
        );
        //use curl to verify the HCaptcha on their backend
        $verify = curl_init();
        curl_setopt($verify, CURLOPT_URL, "https://hcaptcha.com/siteverify");
        curl_setopt($verify, CURLOPT_POST, true);
        curl_setopt($verify, CURLOPT_POSTFIELDS, http_build_query($data));
        curl_setopt($verify, CURLOPT_RETURNTRANSFER, true);
        $response = curl_exec($verify);
        $responseData = json_decode($response);
        if($responseData->success) {
            return True; //if verified successfully, return true
        }
    }
    return False;
}

function hCaptchaJS(): string {
    //allow hCaptcha JS to communicate with hCaptcha's client api, so it can serve the user captchas
    //and don't allow users to submit a form without completing a hCaptcha
    return "
    <script src='https://js.hcaptcha.com/1/api.js' async defer></script>
    <script id='hCaptchaJQuery'>
        $('form').submit(function(event) {

        var hcaptchaVal = $('[name=h-captcha-response]').value;
        if (hcaptchaVal === '') {
            event.preventDefault();
            alert('Please complete the hCaptcha to submit');
        }
        });
    </script>";
}

function hCaptchaButton(): string {
    return '
    <div class="h-captcha" data-sitekey="22353c5a-05f5-4f2f-9b3d-a644670de95c"></div>
    ';
}

function enableImageUpload(): void {
    ini_set('file_uploads', 1);
    ini_set('upload_max_filesize', '10M');
    ini_set('post_max_size', '10M');
}

function enableDebugging(): void
{
    //used only when debugging code -> allows errors and warnings to come through to the frontend
    ini_set('display_errors', 1);
    ini_set('display_startup_errors', 1);
    error_reporting(E_ALL);
}

//enableDebugging();