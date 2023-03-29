<?php

set_include_path('/backend-directory');
include('helper.php');
checkSession();

function twoFactorForm(): string
{
    return '
    <form action="verify.php" method="post">
        <div class="form-group p-1">
            <label for="otp">Please enter the One-Time Password you\'ve been emailed - this may take a few minutes.</label>
            <input class="form-control" name="otp" required id="otp" type="text" placeholder="e.g. ABCDEF">
            <button class="btn btn-primary m-1" type="submit" name="submit">Submit</button>
        </div>
    </form>
    <form action="verify.php" method="post">
        <div class="form-group p-1">
            
        </div>
    </form>
    ';
}
$htmlOut = ''; //string to hold html we'll output at the end so that we can still modify headers beforehand

if (isset($_SESSION['activated']) && $_SESSION['activated']) {
    if (isset($_POST['submit'])) { //if code submitted
        $otp = sanitise($_POST['otp']);
        if ($otp === $_SESSION['twoFactorCode']) {
            //code correct -> complete sign-in process
            $_SESSION['signedIn'] = True;
            header('location:home.php');
        } else if (!(ctype_alnum($otp) && strlen($otp) !== 6)) {
            //code in wrong format
            $htmlOut .= '<h3>One-Time Password in the wrong format, please check it again</h3>';
            $htmlOut .= twoFactorForm();
        } else {
            //code incorrect
            $htmlOut .= '<h3>One-Time Password Incorrect, please try again</h3>';
            $htmlOut .= twoFactorForm();
        }

    } else {
        $htmlOut .= twoFactorForm();
    }
} else if (isset($_SESSION['userid'])) {
    $htmlOut .= '<h3>Please <a href="activate.php">activate your account</a> to use one-time passwords and sign in.</h3>';
} else {
    header('location:signin.php');
}

echo pageTop();
echo $htmlOut;
echo pageBottom();