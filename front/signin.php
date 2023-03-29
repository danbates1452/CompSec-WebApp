<?php
set_include_path('/backend-directory');
include('helper.php');

checkSession();

function signInForm(): string
{
    return '
<form class="mb-4 ml-5 mr-5" action="signin.php" method="post">
    <div class="form-group p-1">
        <label for="username">Username</label>
        <input class="form-control" name="username" required id="username" type="text" placeholder="Your Username">
    </div>
    <div class="form-group p-1">
        <label for="password">Password</label>
        <input class="form-control" name="password" required id="password" type="text" placeholder="Your Password">
    </div>
    <span>First time? <a href="register.php">Register Now</a>.</span>
    <br>
    <span><a href="forgotPassword.php">Forgot your password?</a></span>
    <div class="d-flex justify-content-center">
        <button class="btn btn-primary m-1" type="submit" name="submit">Sign In</button>
        <a class="btn btn-secondary m-1" type="button" href="home.php">Cancel</a>
    </div>
</form>
';
}

function incorrectCredentials(): string
{
    return '<h1>Incorrect Username or Password!</h1>';
}

function attemptsLimit(): string
{
    return '
    <h1>The failed sign-in attempts limit has been hit for this user. Try again in an hour.</h1>
    ';
}

$htmlOut = ''; //variable to store the html we're going to output all at once to avoid outputting before we can send different headers (for redirects)

if (isset($_SESSION['signFail']) && $_SESSION['signFail']) {
    $htmlOut .= incorrectCredentials();
    if (isset($_SESSION['signAttempts'])) {
        if ($_SESSION['signAttempts'] > 5) {
            $htmlOut .= attemptsLimit(); //if user fails 5x, lock them out until their session expires (in an hour)
        } else {
            $_SESSION['signAttempts']++;
            $htmlOut .= signInForm();
        }
    } else {
        $_SESSION['signAttempts'] = 1; //define
        $htmlOut .= signInForm();
    }
    unset($_SESSION['signFail']);
} else if (isset($_POST['submit'])) { //if submitted
    if ($_POST['username'] <> '' && $_POST['password'] <> '') {
        //local variables for inserting into db
        $username = htmlspecialchars($_POST['username'], ENT_HTML5);
        $password = htmlspecialchars($_POST['password'], ENT_HTML5);
        //sanitized special characters to html
        // -> allows use of special characters in username and password while avoiding escape characters

        $passwordHash = password_hash($password, PASSWORD_BCRYPT);

        $db = getDatabase();

        $attributesQuery = $db->prepare("SELECT * FROM Users where Username = ?");
        $attributesQuery->bindValue(1, $username);
        $attributesQueryResult = $attributesQuery->execute();
        $userAttributesArray = $attributesQueryResult->fetchArray(SQLITE3_ASSOC);

        $storedPasswordHash = $userAttributesArray['Password'];

        if (password_verify($password, $storedPasswordHash)) { //if correct password
            //Store relevant variables in the session
            $_SESSION['username'] = $username;
            $_SESSION['passwordHash'] = $passwordHash;

            //additional attributes to be used on other pages
            $_SESSION['userid'] = $userAttributesArray['UserID'];
            $_SESSION['displayName'] = $userAttributesArray['DisplayName'];
            $_SESSION['emailAddress'] = $userAttributesArray['EmailAddress'];
            $_SESSION['phoneNumber'] = $userAttributesArray['PhoneNumber'];
            $_SESSION['activated'] = (bool)$userAttributesArray['Activated'];

            if ((bool)$userAttributesArray['TwoFactor']) {
                $code = generateOTP();
                $_SESSION['twoFactorCode'] = $code;
                $htmlOut .= sendTwoFactorEmail($userAttributesArray['DisplayName'], $code, $userAttributesArray['EmailAddress']);
                header("location:verify.php"); //divert to verify 2fa
            } else {
                $_SESSION['signedIn'] = True;
            }

            //Immediately redirect back to the home page
            header("refresh:0;url=home.php", True, 302);
        } else {
            //refresh with failure message
            $_SESSION['signFail'] = True;
            header("location:signin.php");
        }
    }
} else if (isUserSignedIn()) {
    header('location:home.php'); //redirect already signed-in users
} else {
    $htmlOut .= signInForm();
}

echo pageTop();
echo $htmlOut;
echo pageBottom();