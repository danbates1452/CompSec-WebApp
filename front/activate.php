<?php
set_include_path('/backend-directory');
include('helper.php');
checkSession();

function requestNewKey(): string
{
    return '<h3>Looks like your activation key has expired! <a href="activate.php?requestNewKey">Click here to request a new one to your saved email address!</a></h3>';
}
$htmlOut = ''; //string to hold html we'll output at the end so that we can still modify headers beforehand


if (isset($_GET['activationKey']) && isset($_SESSION['activationKey']) && sanitise($_GET['activationKey']) === $_SESSION['activationKey']) {
    $registrationQuery = getDatabase()->prepare("UPDATE Users SET Activated = 1 WHERE UserID == ?");
    $registrationQuery->bindValue(1, getUserID());

    $registrationQueryResult = $registrationQuery->execute();
    if ($registrationQueryResult) { //if didn't fail
        $_SESSION['activated'] = True;
        $htmlOut .= '<h3>Your account is now activated - you can now <a href="signin.php">sign in</a></h3>';
        header("refresh:10;location:home.php"); //redirect to home 10s after activation
    } else {
        $_SESSION['activated'] = False;
        $htmlOut .= "<h3>We couldn't activate your account right now, please try again later.</h3>";
    }
} else if (isset($_GET['requestNewKey'])) {
    $activationKey = generateRandomKey();
    $activationURL = 'https://danbat.es/cs/uni-compsec/activate.php?activationKey='.$activationKey;
    $_SESSION['activationKey'] = $activationKey;
    sendActivationEmail($_SESSION['displayName'], $activationURL, $_SESSION['emailAddress']);
    $htmlOut .= '<h3>New activation key sent! You should receive a link via email to activate your account soon.</h3>';
} else {
    $htmlOut .= requestNewKey();
}

echo pageTop();
echo $htmlOut;
echo pageBottom();